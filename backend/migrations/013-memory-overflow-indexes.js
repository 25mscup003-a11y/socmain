require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

const ALERT_INDEXES = [
  [{ companyId: 1, capabilityIds: 1, createdAt: -1 }, { name: 'memory_company_capabilities_time' }],
  [{ companyId: 1, capabilityIds: 1, eventType: 1, severity: 1, status: 1, createdAt: -1 }, { name: 'memory_event_triage' }],
  [{ companyId: 1, memoryMetricType: 1, systemId: 1, createdAt: -1 }, { name: 'memory_metric_host_time' }],
  [{ companyId: 1, capabilityIds: 1, processName: 1, pid: 1, createdAt: -1 }, { name: 'memory_process_time' }],
  [{ companyId: 1, detectionRuleId: 1, createdAt: -1 }, { name: 'memory_detection_rule_time', sparse: true }],
  [{ companyId: 1, incidentId: 1, createdAt: -1 }, { name: 'memory_incident_time', sparse: true }],
];

const RULE_INDEXES = [
  [{ companyId: 1, ruleId: 1 }, { name: 'memory_rule_company_id', unique: true }],
  [{ companyId: 1, enabled: 1, severity: 1 }, { name: 'memory_rule_enabled_severity' }],
];

async function createIndexes(collection, indexes) {
  const existing = await collection.indexes();
  const names = [];
  for (const [keys, options] of indexes) {
    const equivalent = existing.find(index => JSON.stringify(index.key) === JSON.stringify(keys));
    if (equivalent) {
      if (options.unique === true && equivalent.unique !== true) {
        throw new Error(`Existing index ${equivalent.name} must be unique before memory migration can continue`);
      }
      names.push(equivalent.name);
    } else {
      names.push(await collection.createIndex(keys, options));
    }
  }
  return names;
}

async function run() {
  await connectDB();
  const db = mongoose.connection.db;
  const alerts = db.collection('alerts');
  const rules = db.collection('memorydetectionrules');
  const [alertIndexes, ruleIndexes] = await Promise.all([
    createIndexes(alerts, ALERT_INDEXES),
    createIndexes(rules, RULE_INDEXES),
  ]);
  console.log(JSON.stringify({ alertIndexes, ruleIndexes }));
}

if (require.main === module) {
  run()
    .catch(error => {
      console.error(error);
      process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
}

module.exports = { run, ALERT_INDEXES, RULE_INDEXES };
