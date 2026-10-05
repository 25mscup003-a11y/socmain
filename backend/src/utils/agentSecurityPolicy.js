const { isSystemOnline } = require('./systemPresence');

const CONTROL_KEYS = {
  selfProtection: 'self_protection', tamperProtection: 'tamper_protection',
  antiDebugging: 'anti_debugging', antiReverseEngineering: 'anti_reverse_engineering',
  antiDumpProtection: 'anti_dump_protection', integrityVerification: 'integrity_verification',
  secureCommunication: 'secure_communication', configurationEncryption: 'configuration_encryption',
  certificateValidation: 'certificate_validation', codeIntegrityMonitoring: 'code_integrity_monitoring',
  lockdownMode: 'lockdown_mode', maintenanceMode: 'maintenance_mode',
};
const REQUIRED_CONTROLS = new Set(['secureCommunication', 'configurationEncryption', 'certificateValidation']);
const REPORT_STATES = new Set(['enforced', 'monitoring', 'disabled', 'unsupported', 'not_applicable', 'error']);
const REPORT_MAX_AGE_MS = 3 * 60 * 1000;

function desktopSecuritySupported(system) {
  return system.agentType !== 'phone' && !/android|ios|solaris/i.test(`${system.os || ''} ${system.osType || ''}`);
}

function securityPolicySnapshot(system) {
  const controls = system.securityControls || {};
  return {
    ...Object.fromEntries(Object.entries(CONTROL_KEYS).map(([key, wire]) => [wire,
      REQUIRED_CONTROLS.has(key) || (key === 'maintenanceMode' ? controls[key] === true : controls[key] !== false)])),
    policy_version: Number(controls.policyVersion || 1),
    protection_level: controls.protectionLevel || 'hardened',
    erase_code_on_open: controls.eraseCodeOnOpen === true,
  };
}

function sanitizeControlReport(value, now = new Date()) {
  if (!value || value.version !== 2 || !Number.isSafeInteger(value.policyVersion) || value.policyVersion < 0) return null;
  const controls = {};
  for (const key of Object.keys(CONTROL_KEYS)) {
    const item = value.controls?.[key];
    if (!item || typeof item.enabled !== 'boolean' || !REPORT_STATES.has(item.state)) continue;
    controls[key] = { enabled: item.enabled, state: item.state, detail: String(item.detail || '').slice(0, 400) };
    const fileOpen = key === 'selfProtection' && item.fileOpen;
    if (fileOpen && typeof fileOpen.enabled === 'boolean' && typeof fileOpen.supported === 'boolean' && REPORT_STATES.has(fileOpen.state)) {
      controls[key].fileOpen = {
        enabled: fileOpen.enabled, supported: fileOpen.supported, state: fileOpen.state,
        detail: String(fileOpen.detail || '').slice(0, 400),
        protectedFiles: Number.isSafeInteger(fileOpen.protectedFiles) ? Math.max(0, Math.min(10000, fileOpen.protectedFiles)) : 0,
      };
    }
  }
  return {
    version: value.policyVersion, state: value.policyError ? 'failed' : 'applied',
    error: String(value.policyError || '').slice(0, 500), controls, reportedAt: now,
    maintenanceActive: value.maintenanceActive === true,
  };
}

function securityPolicyMatchesReport(policy, report) {
  return report.version === policy.policy_version && Object.entries(CONTROL_KEYS)
    .every(([key, wire]) => report.controls?.[key]?.enabled === policy[wire])
    && (report.controls?.selfProtection?.fileOpen?.enabled ?? false) === policy.erase_code_on_open;
}

function securityPolicyPosture(system, now = Date.now()) {
  const policy = securityPolicySnapshot(system);
  const report = system.agentSecurityPolicyStatus || {};
  const supported = desktopSecuritySupported(system);
  const age = now - new Date(report.reportedAt || 0).getTime();
  const fresh = isSystemOnline(system, now) && age >= 0 && age < REPORT_MAX_AGE_MS;
  const matches = securityPolicyMatchesReport(policy, report);
  const state = !supported ? 'unsupported' : !report.reportedAt ? 'pending'
    : !fresh ? 'stale' : report.state === 'failed' ? 'failed' : matches ? 'applied' : 'pending';
  const controlStatus = Object.fromEntries(Object.keys(CONTROL_KEYS).map(key => {
    const actual = report.controls?.[key];
    return [key, {
      state: !supported ? 'unsupported' : state === 'applied' ? actual.state : state,
      reportedState: actual?.state || 'unknown', enabled: actual?.enabled ?? null,
      detail: !supported ? 'This endpoint does not support the desktop security runtime.' : actual?.detail || 'Awaiting a runtime report from the updated agent.',
      required: REQUIRED_CONTROLS.has(key),
      ...(key === 'selfProtection' ? { fileOpen: actual?.fileOpen ? {
        ...actual.fileOpen,
        reportedState: actual.fileOpen.state,
        state: !supported ? 'unsupported' : state === 'applied' ? actual.fileOpen.state : state,
      } : { enabled: false, supported: false, state: 'unsupported', detail: 'Download and install agent 0.1.13 or later to report file-open support.' } } : {}),
    }];
  }));
  return { policySync: { state, desiredVersion: policy.policy_version, appliedVersion: report.version ?? null, reportedAt: report.reportedAt || null, error: report.error || '' }, controlStatus, securitySupported: supported };
}

module.exports = { CONTROL_KEYS, REQUIRED_CONTROLS, desktopSecuritySupported, securityPolicySnapshot, sanitizeControlReport, securityPolicyPosture, securityPolicyMatchesReport };
