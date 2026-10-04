const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const { spawn, execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { Kafka, logLevel } = require('../../backend/node_modules/kafkajs');
const { MongoClient, ObjectId } = require('../../backend/node_modules/mongodb');
const runId = crypto.randomBytes(6).toString('hex');
const root = path.resolve(__dirname, '../..');
const composeFile = path.join(__dirname, 'docker-compose.ha.yml');
const runCommand = promisify(execFile);
const brokers = '127.0.0.1:29092,127.0.0.1:29093,127.0.0.1:29094';
const uri = 'mongodb://127.0.0.1:37017/soc_kafka_ha';
const groupId = `soc-ha-${runId}`;
const topics = { alerts: `soc.ha.${runId}.alerts`, retry: `soc.ha.${runId}.retry`, deadLetter: `soc.ha.${runId}.dlq` };
Object.assign(process.env, { KAFKA_BROKERS: brokers, KAFKA_LOG_LEVEL: 'error', KAFKA_REQUEST_TIMEOUT_MS: '3000', KAFKA_CONNECTION_TIMEOUT_MS: '1000', BROKER_ALERT_TOPIC: topics.alerts, BROKER_ALERT_RETRY_TOPIC: topics.retry, BROKER_ALERT_DLQ_TOPIC: topics.deadLetter });
const { EventBroker } = require('../../backend/src/services/eventBroker.service');
// Do not load the application's environment into this isolated test.
process.env.DOTENV_CONFIG_PATH = '/dev/null';
const { ensureBrokerStorageIndex } = require('../../backend/scripts/provision-broker-storage');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const workerCount = Number(process.env.HA_WORKER_COUNT || 3);
assert.ok(Number.isInteger(workerCount) && workerCount >= 1 && workerCount <= 6);
const report = { scope: 'isolated-three-broker-and-MongoDB-test', workers: workerCount, productionCapacityValidated: false, checks: [] };
const workers = [];
let workerOutput = '';
function progress(check) { report.checks.push(check); console.log(JSON.stringify(check)); }
async function waitUntil(label, check, timeout = 90000) {
  const deadline = Date.now() + timeout;
  let lastError;
  while (Date.now() < deadline) {
    const exited = workers.find(worker => worker.exitCode !== null);
    if (exited) throw new Error(`Worker exited (${exited.exitCode}): ${workerOutput.slice(-3000)}`);
    try { if (await check()) return; } catch (error) { lastError = error; }
    await delay(500);
  }
  throw new Error(`${label} timed out${lastError ? ': ' + lastError.message : ''}; worker: ${workerOutput.slice(-2000)}`);
}
async function compose(...args) { await runCommand('docker', ['compose', '-f', composeFile, ...args], { timeout: 180000, maxBuffer: 1024 * 1024 }); }
async function run() {
  const kafka = new Kafka({ clientId: 'soc-ha-controller', brokers: brokers.split(','), requestTimeout: 5000, retry: { retries: 5 }, logLevel: logLevel.ERROR });
  const admin = kafka.admin();
  const mongo = new MongoClient(uri, { serverSelectionTimeoutMS: 1500 });
  const publisher = new EventBroker({ deliveryTimeoutMs: 5000 });
  const sendFromAgent = async documents => {
    const until = Date.now() + 90000;
    for (;;) {
      try { return await publisher.publishAlerts(documents); } catch (error) {
        if (error.statusCode !== 503 || Date.now() >= until) throw error;
        await delay(1000);
      }
    }
  };
  const tenantId = new ObjectId();
  const companyId = new ObjectId();
  const db = mongo.db();
  const payload = crypto.randomBytes(1024).toString('hex');
  const document = id => ({ eventId: `${runId}-${id}`, companyId: String(companyId), tenantId: String(tenantId), agentId: `agent-${id}`, ruleId: 'PROC_INVENTORY_SUMMARY', severity: 'low', source: 'agent', category: 'system', isSynthetic: true, dataOrigin: 'synthetic', description: 'Isolated Kafka reliability test', createdAt: new Date().toISOString(), rawEvent: { payload } });
  const stored = () => db.collection('alerts').countDocuments({ companyId });
  const expectedDLQ = async () => {
    const offsets = await admin.fetchTopicOffsets(topics.deadLetter);
    return offsets.reduce((sum, part) => sum + Number(part.high) - Number(part.low), 0);
  };
  try {
    await admin.connect();
    await mongo.connect();
    progress({ check: 'storage lookup index provisioned', ...await ensureBrokerStorageIndex(db) });
    await admin.createTopics({ waitForLeaders: false, topics: Object.values(topics).map(topic => ({ topic, numPartitions: 6, replicationFactor: 3, configEntries: [{ name: 'min.insync.replicas', value: '2' }, { name: 'unclean.leader.election.enable', value: 'false' }, { name: 'retention.ms', value: '3600000' }] })) });
    await waitUntil('topic replication readiness', async () => {
      const metadata = await admin.fetchTopicMetadata({ topics: Object.values(topics) });
      return metadata.topics.length === 3 && metadata.topics.every(topic => topic.partitions.length === 6
        && topic.partitions.every(part => part.leader >= 0 && part.isr.length === 3));
    });
    await db.collection('companies').insertOne({ _id: companyId, tenantId, name: 'Isolated Kafka Test', email: `${runId}@example.invalid`, status: 'active' });
    const env = { ...process.env, NODE_ENV: 'test', DOTENV_CONFIG_PATH: '/dev/null', MONGO_URI: uri, KAFKA_ALERT_GROUP_ID: groupId, BROKER_PERSIST_BATCH_SIZE: '250', KAFKA_CONSUMER_PARTITION_CONCURRENCY: '3', KAFKA_PUBLISH_WAIT_MS: '5000', MONGO_SERVER_SELECTION_TIMEOUT_MS: '1000', MONGO_CONNECT_TIMEOUT_MS: '1000', MONGO_HEARTBEAT_FREQUENCY_MS: '1000', MONGO_MAX_POOL_SIZE: '10', JWT_SECRET: crypto.randomBytes(32).toString('hex'), AGENT_STORAGE_MASTER_KEY: crypto.randomBytes(32).toString('hex'), THREAT_INTEL_PUBLIC_FEEDS_ENABLED: 'false' };
    for (let index = 0; index < workerCount; index += 1) {
      const worker = spawn(process.execPath, ['--disable-warning=TimeoutNegativeWarning', 'backend/src/workers/alertIngestion.worker.js'], { cwd: root, env: { ...env, KAFKA_CLIENT_ID: `soc-ha-worker-${index}` }, stdio: ['ignore', 'pipe', 'pipe'] });
      workers.push(worker);
      for (const stream of [worker.stdout, worker.stderr]) stream.on('data', bytes => { workerOutput = (workerOutput + bytes.toString()).slice(-32000); });
    }
    await waitUntil('consumer startup', async () => (await admin.describeGroups([groupId])).groups.some(group => group.state === 'Stable' && group.members.length === workerCount));
    await sendFromAgent([document('baseline')]);
    await waitUntil('baseline persistence', async () => await stored() === 1);
    await sendFromAgent([document('baseline')]);
    await delay(1500);
    assert.equal(await stored(), 1);
    progress({ check: 'Kafka -> actual worker -> MongoDB and duplicate replay', status: 'pass' });

    const metadata = await admin.fetchTopicMetadata({ topics: [topics.alerts] });
    const firstDown = metadata.topics[0].partitions[0].leader;
    await compose('kill', '-s', 'SIGKILL', `broker-${firstDown}`);
    await waitUntil('leader failover', async () => (await admin.fetchTopicMetadata({ topics: [topics.alerts] })).topics[0].partitions.every(part => part.leader !== firstDown && part.leader >= 0));
    await sendFromAgent([document('one-broker-down')]);
    await waitUntil('single-broker-failure persistence', async () => await stored() === 2);
    progress({ check: 'one broker abruptly killed; quorum publish and persistence', status: 'pass' });

    const secondDown = [1, 2, 3].find(id => id !== firstDown);
    await compose('kill', '-s', 'SIGKILL', `broker-${secondDown}`);
    await delay(2000);
    await assert.rejects(publisher.publishAlerts([document('quorum-recovery')]), error => error.statusCode === 503);
    assert.equal(await stored(), 2);
    progress({ check: 'two brokers down; no successful acknowledgment without quorum', status: 'pass' });
    await compose('start', `broker-${firstDown}`, `broker-${secondDown}`);
    await waitUntil('restored replica quorum', async () => (await admin.fetchTopicMetadata({ topics: [topics.alerts] })).topics[0].partitions.every(part => part.isr.length === 3), 120000);
    // A 503 never releases the agent's durable spool entry. Retry that same
    // event ID after recovery, even if the earlier send later succeeds.
    await sendFromAgent([document('quorum-recovery')]);
    await waitUntil('quorum recovery delivery', async () => await stored() === 3, 120000);
    await sendFromAgent([document('quorum-recovery')]);
    await delay(1500);
    assert.equal(await stored(), 3);
    await waitUntil('pending producer sends drained after recovery', async () => publisher.pendingPublishes === 0);
    assert.equal(publisher.pendingBytes, 0);
    progress({ check: 'quorum restored; agent retry delivered and deduplicated', status: 'pass' });

    await compose('stop', '-t', '3', 'mongo');
    await sendFromAgent([document('storage-recovery')]);
    await waitUntil('storage backoff', async () => workerOutput.includes('broker_storage_retry'), 30000);
    assert.equal(await expectedDLQ(), 0);
    await compose('start', 'mongo');
    await waitUntil('storage recovery persistence', async () => await stored() === 4, 60000);
    progress({ check: 'MongoDB outage; retained Kafka offset, no DLQ loss, storage recovery', status: 'pass' });

    const started = performance.now();
    let cursor = 0;
    const send = async () => {
      while (cursor < 30000) {
        const first = cursor; cursor += 250;
        await sendFromAgent(Array.from({ length: Math.min(250, 30000 - first) }, (_, index) => document(first + index)));
      }
    };
    await Promise.all(Array.from({ length: 4 }, send));
    const publishedSeconds = (performance.now() - started) / 1000;
    console.log(JSON.stringify({ stage: 'load-published', events: 30000, publishedSeconds }));
    await waitUntil('30000-agent persistence', async () => await stored() === 30004, 240000);
    const completeSeconds = (performance.now() - started) / 1000;
    const eventIds = new Set(await db.collection('alerts').distinct('eventId', { companyId }));
    assert.equal(eventIds.size, 30004);
    for (let id = 0; id < 30000; id += 1) assert.ok(eventIds.has(`${runId}-${id}`), `Missing agent event ${id}`);
    for (const id of ['baseline', 'one-broker-down', 'quorum-recovery', 'storage-recovery']) assert.ok(eventIds.has(`${runId}-${id}`));
    assert.equal(await expectedDLQ(), 0);
    assert.equal(publisher.pendingPublishes, 0);
    assert.equal(publisher.pendingBytes, 0);
    progress({ check: '30000 logical agents through RF3 Kafka and actual MongoDB worker', status: 'pass', events: 30000, publishedSeconds, completeSeconds, observedStoredEventsPerSecond: Math.round(30000 / completeSeconds) });
    report.status = 'pass';
  } catch (error) {
    report.status = 'fail';
    report.error = error.message;
    throw error;
  } finally {
    // Restart only these isolated services before disconnecting clients.
    await compose('start', 'broker-1', 'broker-2', 'broker-3', 'mongo').catch(() => {});
    await Promise.all(workers.map(async worker => {
      if (worker.exitCode !== null) return;
      worker.kill('SIGTERM');
      await Promise.race([new Promise(resolve => worker.once('exit', resolve)), delay(16000)]);
      if (worker.exitCode === null) worker.kill('SIGKILL');
    }));
    await publisher.disconnect().catch(() => {});
    await mongo.close().catch(() => {});
    await admin.disconnect().catch(() => {});
    fs.writeFileSync('/tmp/soc-kafka-ha-result.json', JSON.stringify(report, null, 2) + '\n');
    fs.writeFileSync('/tmp/soc-kafka-ha-worker.log', workerOutput);
  }
}
process.once('SIGTERM', () => { workers.forEach(worker => worker.kill('SIGTERM')); process.exit(1); });
run().then(() => process.exit(0)).catch(error => { console.error(error.stack); process.exit(1); });
