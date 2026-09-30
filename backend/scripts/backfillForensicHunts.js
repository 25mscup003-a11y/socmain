require('dotenv').config();
const mongoose = require('mongoose');
const Log = require('../src/models/Log.model');
const User = require('../src/models/User.model');
const ForensicHunt = require('../src/models/ForensicHunt.model');

async function main() {
  await mongoose.connect(process.env.MONGO_URI);
  const legacy = await Log.find({
    source: 'velociraptor',
    'fields.action': { $in: ['forensic_hunt_launched', 'forensic_hunt_failed'] },
  }).sort({ createdAt: 1 }).lean();

  let migrated = 0;
  let skipped = 0;
  for (const log of legacy) {
    const exists = await ForensicHunt.exists({ legacyLogId: log._id });
    if (exists) {
      skipped += 1;
      continue;
    }
    const actor = await User.findOne({
      companyId: log.companyId,
      role: { $in: ['company_admin', 'department_admin', 'soc_manager', 'l3_analyst', 'l2_analyst'] },
    }).sort({ createdAt: 1 }).select('_id role').lean();
    if (!actor) {
      console.warn(`Skipping ${log._id}: no scoped user available for audit attribution`);
      skipped += 1;
      continue;
    }
    const fields = log.fields || {};
    const failed = fields.action === 'forensic_hunt_failed' || log.level === 'error';
    await ForensicHunt.create({
      companyId: log.companyId,
      departmentId: log.departmentId || null,
      systemId: log.systemId || null,
      clientId: fields.clientId || '',
      name: fields.huntName || 'Legacy Velociraptor hunt',
      artifacts: (Array.isArray(fields.artifacts) ? fields.artifacts : [fields.artifactName]).filter(Boolean),
      status: failed ? 'failed' : 'completed',
      requestedBy: actor._id,
      requestedByRole: actor.role,
      sourceIp: 'legacy-log-migration',
      legacyLogId: log._id,
      providerResult: fields.result || null,
      error: failed ? String(fields.error || log.message || '').slice(0, 4000) : '',
      startedAt: log.logTime || log.createdAt,
      completedAt: log.receivedAt || log.updatedAt || log.createdAt,
      createdAt: log.createdAt,
      updatedAt: log.updatedAt || log.createdAt,
    });
    migrated += 1;
  }
  console.log(JSON.stringify({ scanned: legacy.length, migrated, skipped }));
  await mongoose.disconnect();
}

main().catch(async error => {
  console.error(error);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
