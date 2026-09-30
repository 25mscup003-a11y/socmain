require('dotenv').config();
const mongoose = require('mongoose');
const { Kafka } = require('kafkajs');
const connectDB = require('../config/db');
const Alert = require('../models/Alert.model');
const Company = require('../models/Company.model');
const { applyRetention } = require('../utils/retentionPolicy');
const { clickhouseEnabled, insertAlerts, closeClickHouse } = require('../services/clickhouse.service');
const { TOPICS, kafkaConfig, getEventBroker } = require('../services/eventBroker.service');
const { isRoutineSecurityTelemetry } = require('../utils/routineTelemetry');
const { ingestNetworkTelemetry } = require('../services/networkMonitoring.service');
const { persistCurrentGpsState } = require('../services/geolocation.service');

const maxRetries = Math.max(1, Number(process.env.BROKER_MAX_RETRIES || 8));
let shuttingDown = false;

function decodeMessage(message) {
  const envelope = JSON.parse(message.value.toString('utf8'));
  if (envelope.schemaVersion !== 1 || envelope.kind !== 'alert') throw new Error('Unsupported event envelope');
  const document = envelope.document;
  if (!document?.tenantId || !document?.companyId || !document?.eventId) {
    throw new Error('tenantId, companyId and eventId are required');
  }
  return document;
}

function retryCount(message) {
  return Number(message.headers?.['retry-count']?.toString() || 0);
}

async function persistBatch(documents, { heartbeat = async () => {} } = {}) {
  if (!documents.length) return;
  const companyIds = [...new Set(documents.map(document => String(document.companyId)))];
  const companies = await Company.find({ _id: { $in: companyIds } }).select('_id tenantId partnerId retentionPolicy').lean();
  const companyMap = new Map(companies.map(company => [String(company._id), company]));
  const prepared = documents.map(document => {
    const company = companyMap.get(String(document.companyId));
    if (!company) throw new Error(`Unknown company scope: ${document.companyId}`);
    if (String(company.tenantId || '') !== String(document.tenantId || '')) {
      throw new Error(`Tenant/company scope mismatch: ${document.companyId}`);
    }
    return applyRetention({ ...document, partnerId: company.partnerId || document.partnerId }, company.retentionPolicy, document.createdAt);
  });
  // Mongoose timestamps may mutate bulk-write documents. Preserve the original
  // event time so ClickHouse's replacement key remains stable on a replay.
  const clickhouseDocuments = prepared.map(document => ({ ...document }));
  let newlyInsertedAlerts = [];
  if (process.env.HOT_EVENT_STORE !== 'clickhouse') {
    const result = await Alert.bulkWrite(prepared.map(document => ({
      updateOne: {
        filter: { companyId: document.companyId, eventId: document.eventId },
        update: { $setOnInsert: document },
        upsert: true,
        // The agent's observation time is already in document.createdAt.
        // Mongoose bulk-write timestamps otherwise replace it with backlog
        // insertion time, making old Kafka events look like live floods.
        timestamps: false,
      },
    })), { ordered: false, writeConcern: { w: 'majority' } });
    const insertedIds = Object.values(result.upsertedIds || {}).filter(Boolean);
    if (insertedIds.length) newlyInsertedAlerts = await Alert.find({ _id: { $in: insertedIds } });
  }
  const currentStateDocuments = process.env.HOT_EVENT_STORE === 'clickhouse'
    ? prepared
    : newlyInsertedAlerts;
  await Promise.all(currentStateDocuments.map(alert => persistCurrentGpsState(alert)));
  if (clickhouseEnabled()) await insertAlerts(clickhouseDocuments);
  await heartbeat();

  // Materialize the rich per-connection rows consumed by Capability 3. In
  // broker mode the HTTP route returns before this hook runs, so omitting it
  // left Source/Destination/Process/DNS/Geo columns empty on the dashboard.
  for (const alert of newlyInsertedAlerts) {
    if (alert.ruleId !== 'NET_CONNECTION_SUMMARY') continue;
    try {
      await ingestNetworkTelemetry(alert, null);
    } catch (error) {
      console.error(JSON.stringify({
        level: 'error', event: 'broker_network_materialization_failed',
        alertId: String(alert._id), error: error.message,
      }));
    }
    await heartbeat();
  }

  // Broker-mode ingestion must feed the existing correlation engine just like
  // direct HTTP ingestion. Per-company debounce prevents a scan per message.
  if (process.env.HOT_EVENT_STORE !== 'clickhouse') {
    const { scheduleCompanyCorrelation } = require('../services/correlation.service');
    // Broker catch-up can persist many consecutive batches. A longer debounce
    // collapses them into one correlation pass instead of rescanning the
    // alerts collection once per batch and starving MongoDB's connection pool.
    const correlationDelayMs = Math.max(5_000, Number(process.env.BROKER_CORRELATION_DEBOUNCE_MS || 30_000));
    const correlationCompanyIds = [...new Set(newlyInsertedAlerts
      .filter(alert => !isRoutineSecurityTelemetry(alert))
      .map(alert => String(alert.companyId)))];
    for (const companyId of correlationCompanyIds) scheduleCompanyCorrelation(companyId, null, correlationDelayMs);

    // Kafka ingestion must pass every newly persisted alert through the same
    // SOAR rule engine as direct HTTP ingestion. Only upserted IDs are used so
    // Kafka retries/replays cannot execute the same alert workflow again.
    if (newlyInsertedAlerts.length) {
      const { runSoarForAlert } = require('../services/soar.service');
      const { scheduleGeolocationEnrichment } = require('../services/geolocation.service');
      const { processProfileMismatchAlert, processGeolocationProtectionAlert } = require('../services/uebaProfileLock.service');
      const concurrency = Math.max(1, Number(process.env.BROKER_SOAR_CONCURRENCY || 8));
      for (let index = 0; index < newlyInsertedAlerts.length; index += concurrency) {
        const batch = newlyInsertedAlerts.slice(index, index + concurrency);
        batch.filter(alert => !isRoutineSecurityTelemetry(alert))
          .forEach(alert => scheduleGeolocationEnrichment(alert, null));
        const actionableBatch = batch.filter(alert => !isRoutineSecurityTelemetry(alert));
        const outcomes = await Promise.allSettled(actionableBatch.map(alert => runSoarForAlert(alert)));
        outcomes.forEach((outcome, offset) => {
          if (outcome.status === 'rejected') {
            console.error(JSON.stringify({
              level: 'error', event: 'broker_soar_evaluation_failed',
              alertId: String(actionableBatch[offset]._id), error: outcome.reason?.message || String(outcome.reason),
            }));
          }
        });
        // SOAR and enrichment may involve external services. Keep Kafka group
        // membership alive while a large preserved backlog is processed.
        await heartbeat();
        const mismatchOutcomes = await Promise.allSettled(batch
          .filter(alert => alert.ruleId === 'UEBA_INPUT_PROFILE_MISMATCH' && alert.inputProfileMismatch === true)
          .map(alert => processProfileMismatchAlert(alert, null)));
        mismatchOutcomes.filter(outcome => outcome.status === 'rejected').forEach(outcome => {
          console.error(JSON.stringify({ level: 'error', event: 'broker_ueba_profile_lock_failed', error: outcome.reason?.message || String(outcome.reason) }));
        });
        const geolocationOutcomes = await Promise.allSettled(batch
          .filter(alert => /^GEO_/i.test(String(alert.ruleId || ''))
            && (alert.rawEvent?.systemLogoutRequested || alert.rawEvent?.sessionRevokeRequested
              || alert.rawEvent?.geoFenceLockRequested || alert.rawEvent?.lockRecommended))
          .map(alert => processGeolocationProtectionAlert(alert, null)));
        geolocationOutcomes.filter(outcome => outcome.status === 'rejected').forEach(outcome => {
          console.error(JSON.stringify({ level: 'error', event: 'broker_geolocation_protection_log_failed', error: outcome.reason?.message || String(outcome.reason) }));
        });
        await heartbeat();
      }
    }
  }
}

async function run() {
  await connectDB();
  const kafka = new Kafka(kafkaConfig());
  const consumer = kafka.consumer({
    groupId: process.env.KAFKA_ALERT_GROUP_ID || 'soc-alert-storage-v1',
    allowAutoTopicCreation: false,
    maxBytesPerPartition: Number(process.env.KAFKA_CONSUMER_MAX_PARTITION_BYTES || 5_242_880),
  });
  run.consumer = consumer;
  await consumer.connect();
  await consumer.subscribe({ topic: TOPICS.alerts, fromBeginning: false });
  await consumer.subscribe({ topic: TOPICS.retry, fromBeginning: false });
  await consumer.run({
    partitionsConsumedConcurrently: Number(process.env.KAFKA_CONSUMER_PARTITION_CONCURRENCY || 3),
    eachBatchAutoResolve: false,
    eachBatch: async ({ batch, resolveOffset, heartbeat, commitOffsetsIfNecessary }) => {
      const valid = [];
      const broker = getEventBroker();
      for (const message of batch.messages) {
        try {
          valid.push({ message, document: decodeMessage(message) });
        } catch (error) {
          await broker.publishDeadLetter({ raw: message.value.toString('utf8') }, error.message, retryCount(message));
          resolveOffset(message.offset);
        }
      }

      // A broker batch can contain thousands of retained events. Persist it in
      // bounded chunks and heartbeat between chunks so Kafka does not evict the
      // consumer and replay the same backlog indefinitely.
      const persistBatchSize = Math.max(10, Math.min(500, Number(process.env.BROKER_PERSIST_BATCH_SIZE || 50)));
      for (let index = 0; index < valid.length; index += persistBatchSize) {
        const chunk = valid.slice(index, index + persistBatchSize);
        try {
          await persistBatch(chunk.map(item => item.document), { heartbeat });
          chunk.forEach(item => resolveOffset(item.message.offset));
        } catch (error) {
          for (const item of chunk) {
            const nextRetry = retryCount(item.message) + 1;
            if (nextRetry >= maxRetries) await broker.publishDeadLetter(item.document, error.message, nextRetry);
            else await broker.publishAlerts([item.document], { topic: TOPICS.retry, retryCount: nextRetry });
            resolveOffset(item.message.offset);
          }
        }
        await commitOffsetsIfNecessary();
        await heartbeat();
      }
    },
  });
}

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(JSON.stringify({ level: 'info', event: 'worker_shutdown', signal }));
  if (run.consumer) await run.consumer.disconnect().catch(() => {});
  await getEventBroker().disconnect().catch(() => {});
  await closeClickHouse().catch(() => {});
  await mongoose.disconnect().catch(() => {});
  process.exit(0);
}

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));

if (require.main === module) {
  run().catch(error => {
    console.error(JSON.stringify({ level: 'error', event: 'worker_failed', message: error.message }));
    process.exit(1);
  });
}

module.exports = { decodeMessage, retryCount, persistBatch, run };
