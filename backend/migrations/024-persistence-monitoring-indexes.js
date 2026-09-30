'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const alerts = mongoose.connection.collection('alerts');

  const evidence = {
    isSynthetic: { $ne: true },
    $or: [
      { category: 'persistence' }, { isPersistence: true },
      { ruleId: /(?:PERSIST|REG_(?:REGISTRY_NEW_ENTRY|REGISTRY_MODIFIED)|PROC_ASSET_(?:CREATED|CHANGED)|WIN_REG_PERSIST)/i },
      { inventoryType: { $in: ['scheduled_task', 'startup', 'ssh_key', 'wmi_subscription', 'browser_extension', 'boot_configuration'] } },
      { mitreId: { $in: ['T1053', 'T1053.003', 'T1053.005', 'T1543.003', 'T1546.003', 'T1547', 'T1547.001', 'T1547.006', 'T1098.004', 'T1574', 'T1542'] } },
    ],
  };
  const backfill = await alerts.updateMany(evidence, { $addToSet: { capabilityIds: 8 } });

  const indexes = [
    [{ companyId: 1, capabilityIds: 1, persistenceType: 1, createdAt: -1 }, { name: 'persistence_type_time' }],
    [{ companyId: 1, capabilityIds: 1, mitreTechnique: 1, createdAt: -1 }, { name: 'persistence_mitre_time' }],
    [{ companyId: 1, capabilityIds: 1, hostname: 1, createdAt: -1 }, { name: 'persistence_host_time' }],
  ];
  const existing = await alerts.indexes();
  let created = 0;
  for (const [keys, options] of indexes) {
    const equivalent = existing.find(index => JSON.stringify(index.key) === JSON.stringify(keys));
    if (equivalent) continue;
    await alerts.createIndex(keys, options);
    created += 1;
  }
  console.log(`Persistence monitoring ready: ${backfill.modifiedCount} alerts backfilled, ${created} indexes created`);
  await mongoose.disconnect();
}

run().catch(async error => {
  console.error(error.message);
  try { await mongoose.disconnect(); } catch (_) { /* no-op */ }
  process.exitCode = 1;
});
