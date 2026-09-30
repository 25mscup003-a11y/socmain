'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const alerts = mongoose.connection.collection('alerts');
  const controls = mongoose.connection.collection('systemchangecontrols');
  const evidence = {
    isSynthetic: { $ne: true },
    $or: [
      { systemChangeCategory: { $exists: true, $nin: ['', null] } },
      { ruleId: /^(?:SYS_|USER_|GROUP_|ACCOUNT_|ADMIN_|FILE_(?:CREATED|MODIFIED|DELETED|RENAMED|PERMISSION|OWNERSHIP)|REG_)/i },
      { eventCategory: 'systemchanges' },
    ],
  };
  const backfill = await alerts.updateMany(evidence, { $addToSet: { capabilityIds: 7 } });
  const indexes = [
    [{ companyId: 1, departmentId: 1, capabilityIds: 1, systemChangeCategory: 1, createdAt: -1 }, { name: 'system_change_category_time' }],
    [{ companyId: 1, capabilityIds: 1, systemChangeType: 1, createdAt: -1 }, { name: 'system_change_type_time' }],
    [{ companyId: 1, capabilityIds: 1, baselineStatus: 1, riskScore: -1, createdAt: -1 }, { name: 'system_change_baseline_risk_time' }],
    [{ companyId: 1, capabilityIds: 1, hostname: 1, createdAt: -1 }, { name: 'system_change_host_time' }],
  ];
  const existing = await alerts.indexes(); let created = 0;
  for (const [keys, options] of indexes) {
    if (existing.some(index => JSON.stringify(index.key) === JSON.stringify(keys))) continue;
    await alerts.createIndex(keys, options); created += 1;
  }
  await controls.createIndex({ companyId: 1, departmentId: 1, kind: 1, enabled: 1, createdAt: -1 }, { name: 'system_change_control_scope' });
  await controls.createIndex({ companyId: 1, systemId: 1, target: 1, kind: 1, enabled: 1 }, { name: 'system_change_control_target' });
  await controls.createIndex({ expiresAt: 1 }, { name: 'system_change_control_expiry' });
  console.log(`System changes monitoring ready: ${backfill.modifiedCount} alerts backfilled, ${created} indexes created`);
  await mongoose.disconnect();
}

run().catch(async error => {
  console.error(error.message);
  try { await mongoose.disconnect(); } catch (_) { /* no-op */ }
  process.exitCode = 1;
});
