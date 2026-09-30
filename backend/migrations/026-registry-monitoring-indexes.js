'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const alerts = mongoose.connection.collection('alerts');
  const controls = mongoose.connection.collection('registryconfigurationcontrols');
  const evidence = {
    isSynthetic: { $ne: true },
    $or: [
      { eventCategory: 'registry' }, { source: 'registry_monitor' },
      { keyPath: /(?:hklm|hkcu|hkey|\/etc\/(?:passwd|shadow|sudoers|ssh|cron|systemd|pam\.d|audit|security))/i },
      { registryKey: { $exists: true, $nin: ['', null] } },
      { configurationCategory: { $exists: true, $nin: ['', null] } },
    ],
  };
  const backfill = await alerts.updateMany(evidence, { $addToSet: { capabilityIds: 6 } });
  const indexes = [
    [{ companyId: 1, departmentId: 1, capabilityIds: 1, configurationCategory: 1, createdAt: -1 }, { name: 'registry_configuration_category_time' }],
    [{ companyId: 1, capabilityIds: 1, configurationPlatform: 1, configurationOperation: 1, createdAt: -1 }, { name: 'registry_platform_operation_time' }],
    [{ companyId: 1, capabilityIds: 1, configurationPolicyViolation: 1, riskScore: -1, createdAt: -1 }, { name: 'registry_policy_risk_time' }],
    [{ companyId: 1, capabilityIds: 1, hostname: 1, createdAt: -1 }, { name: 'registry_host_time' }],
  ];
  const existing = await alerts.indexes(); let created = 0;
  for (const [keys, options] of indexes) {
    if (existing.some(index => JSON.stringify(index.key) === JSON.stringify(keys))) continue;
    try {
      await alerts.createIndex(keys, options); created += 1;
    } catch (error) {
      // Large existing installations can already be at MongoDB's 64-index
      // ceiling. The canonical capability/time indexes are sufficient for the
      // dashboard query, so do not fail the data backfill over optional facets.
      if (error?.code !== 67 && !/too many indexes|IndexMaxNumReached/i.test(String(error?.message || ''))) throw error;
      console.warn(`Skipping optional ${options.name}: alerts index limit reached`);
    }
  }
  await controls.createIndex({ companyId: 1, departmentId: 1, kind: 1, enabled: 1, createdAt: -1 }, { name: 'registry_control_scope' });
  await controls.createIndex({ companyId: 1, departmentId: 1, policyId: 1 }, { name: 'registry_policy_scope_unique', unique: true, sparse: true });
  await controls.createIndex({ companyId: 1, systemId: 1, target: 1, kind: 1, enabled: 1 }, { name: 'registry_control_target' });
  await controls.createIndex({ expiresAt: 1 }, { name: 'registry_control_expiry' });
  console.log(`Registry monitoring ready: ${backfill.modifiedCount} alerts backfilled, ${created} indexes created`);
  await mongoose.disconnect();
}

run().catch(async error => {
  console.error(error.message);
  try { await mongoose.disconnect(); } catch (_) { /* no-op */ }
  process.exitCode = 1;
});
