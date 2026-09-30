require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

const ALERT_INDEXES = [
  [{ companyId: 1, capabilityIds: 1, createdAt: -1 }, { name: 'script_capability_time' }],
  [{ companyId: 1, capabilityIds: 1, interpreter: 1, createdAt: -1 }, { name: 'script_interpreter_time' }],
  [{ companyId: 1, capabilityIds: 1, scriptHash: 1, createdAt: -1 }, { name: 'script_hash_time', sparse: true }],
];

const RULE_INDEXES = [
  [{ companyId: 1, departmentId: 1, enabled: 1, priority: 1 }, { name: 'script_rule_scope_priority' }],
  [{ companyId: 1, systemIds: 1, enabled: 1 }, { name: 'script_rule_agent_scope' }],
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
      { ruleId: { $regex: '^SCRIPT_' } },
      { source: 'script_execution' },
      { processClassifications: { $in: ['powershell', 'command_shell', 'python', 'vbscript_javascript'] } },
    ],
  }, { $addToSet: { capabilityIds: 21 } });
  const alertIndexes = await createIndexes(db.collection('alerts'), ALERT_INDEXES);
  const ruleIndexes = await createIndexes(db.collection('scriptmonitoringrules'), RULE_INDEXES);
  console.log(JSON.stringify({ matched: backfill.matchedCount, backfilled: backfill.modifiedCount, alertIndexes, ruleIndexes }));
}

if (require.main === module) {
  run().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => mongoose.disconnect());
}

module.exports = { run, ALERT_INDEXES, RULE_INDEXES };
