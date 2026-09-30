require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');

const SIGNAL_RULES = Object.freeze({
  privileged_access: ['AUTH_ROOT_LOGIN', 'AUTH_SUDO', 'PROC_PRIVILEGED_COMMAND'],
  privilege_change: ['AUTH_GROUP_CHANGE', 'AUTH_ADMIN_RIGHTS', 'EDR_GROUP_MOD'],
  account_change: ['AUTH_USER_CREATED', 'AUTH_USER_DELETED'],
  privilege_escalation: ['EDR_PRIV_ESC', 'PROC_PRIVILEGE_ESCALATION'],
  defense_evasion: ['PROC_SECURITY_TOOL_TAMPER', 'PROC_SECURITY_TOOL_TERMINATED'],
  log_tampering: ['PROC_SECURITY_LOG_CLEARED'],
  archive_staging: ['PROC_ARCHIVE_STAGING'],
  credential_access: ['SCRIPT_CREDENTIAL_ACCESS'],
  data_exfiltration: ['SCRIPT_DATA_EXFILTRATION', 'NET_OUTBOUND_TRANSFER_ANOMALY', 'NET_EXFIL'],
  destructive_file_activity: ['SCRIPT_MASS_FILE_OPERATION'],
  lateral_movement: ['NET_LATERAL_MOVEMENT_PATTERN', 'SCRIPT_REMOTE_EXECUTION', 'WIN_PSEXEC'],
  removable_media_exfiltration: ['USB_SENSITIVE_FILE_COPIED'],
  removable_media_policy_violation: ['USB_POLICY_BLOCKED', 'USB_POLICY_VIOLATION'],
  sensitive_file_activity: ['FILE_SENSITIVE'],
  identity_anomaly: ['GEO_IMPOSSIBLE_TRAVEL'],
});

const ALL_RULES = Object.freeze([...new Set(Object.values(SIGNAL_RULES).flat())]);

async function run() {
  await connectDB();
  const alerts = mongoose.connection.db.collection('alerts');
  // Tenant-first batches use the existing { companyId, ruleId, createdAt }
  // index and avoid a repeated full-collection scan on large installations.
  const companyIds = await alerts.distinct('companyId', { companyId: { $type: 'objectId' } });
  let matched = 0;
  let capabilityTagged = 0;
  let classified = 0;
  for (const companyId of companyIds) {
    const capabilityResult = await alerts.updateMany(
      { companyId, isSynthetic: { $ne: true }, ruleId: { $in: ALL_RULES } },
      { $addToSet: { capabilityIds: 16 } },
    );
    matched += capabilityResult.matchedCount;
    capabilityTagged += capabilityResult.modifiedCount;

    for (const [insiderSignalType, ruleIds] of Object.entries(SIGNAL_RULES)) {
      const result = await alerts.updateMany(
        {
          companyId,
          isSynthetic: { $ne: true },
          ruleId: { $in: ruleIds },
          $or: [
            { insiderSignalType: { $exists: false } },
            { insiderSignalType: null },
            { insiderSignalType: '' },
          ],
        },
        { $set: { insiderSignalType } },
      );
      classified += result.modifiedCount;
    }
  }

  console.log(JSON.stringify({
    companies: companyIds.length,
    matched,
    capabilityTagged,
    classified,
    indexes: 'existing companyId/capabilityId/capabilityIds/createdAt indexes reused',
  }));
}

if (require.main === module) {
  run().catch(error => {
    console.error(error);
    process.exitCode = 1;
  }).finally(() => mongoose.disconnect());
}

module.exports = { run, SIGNAL_RULES, ALL_RULES };
