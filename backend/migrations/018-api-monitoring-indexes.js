require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

const ALERT_INDEXES = [
  // Alert.model already owns the canonical company/capability/time indexes.
  // Do not consume additional slots on installations at MongoDB's index cap.
];

const WAF_INDEXES = [
  [{ company: 1, ts: -1 }, { name: 'waf_events_company_ts' }],
  [{ company: 1, requestPath: 1, method: 1, ts: -1 }, { name: 'waf_events_company_endpoint_ts' }],
  [{ company: 1, severity: 1, blocked: 1, ts: -1 }, { name: 'waf_events_company_severity_blocked_ts' }],
  [{ integrationId: 1, externalEventId: 1 }, { name: 'waf_events_external_dedupe', unique: true, sparse: true }],
];

async function createIndexes(collection, indexes) {
  const existing = await collection.indexes().catch(() => []);
  const names = [];
  for (const [keys, options] of indexes) {
    const equivalent = existing.find(index => JSON.stringify(index.key) === JSON.stringify(keys));
    names.push(equivalent?.name || await collection.createIndex(keys, options));
  }
  return names;
}

async function run() {
  await connectDB();
  const db = mongoose.connection.db;
  const backfill = await db.collection('alerts').updateMany({
    isSynthetic: { $ne: true },
    $or: [
      { ruleId: { $regex: '^(?:WAF_|API_)' } },
      { source: { $regex: 'waf|api.gateway|ingress|reverse.proxy', $options: 'i' } },
      { eventType: { $regex: 'api.request|http.request', $options: 'i' } },
    ],
  }, { $addToSet: { capabilityIds: 20 } });
  const alertIndexes = await createIndexes(db.collection('alerts'), ALERT_INDEXES);
  const wafIndexes = await createIndexes(db.collection('waf_events'), WAF_INDEXES);
  console.log(JSON.stringify({ matched: backfill.matchedCount, backfilled: backfill.modifiedCount, alertIndexes, wafIndexes }));
}

if (require.main === module) {
  run().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => mongoose.disconnect());
}

module.exports = { run, ALERT_INDEXES, WAF_INDEXES };
