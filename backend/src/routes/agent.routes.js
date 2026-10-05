const { emitPartnerUpdate } = require('../utils/partnerRealtime');
const router = require('express').Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const System = require('../models/System.model');
const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const Download = require('../models/Download.model');
const Partner = require('../models/Partner.model');
const UsbPolicy = require('../models/UsbPolicy.model');
const MemoryDetectionRule = require('../models/MemoryDetectionRule.model');
const GeolocationPolicy = require('../models/GeolocationPolicy.model');
const Firewall = require('../models/Firewall.model');
const IpsWhitelist = require('../models/IpsWhitelist.model');
const CountryBlock = require('../services/countryBlock.service');
const Alert = require('../models/Alert.model');
const AgentSecurityAudit = require('../models/AgentSecurityAudit.model');
const DnsSinkholeConfig = require('../models/DnsSinkholeConfig.model');
const DnsCachePoisonConfig = require('../models/DnsCachePoisonConfig.model');
const RansomwareConfig = require('../models/RansomwareConfig.model');
const HashSignaturePolicy = require('../models/HashSignaturePolicy.model');
const NetworkPolicy = require('../models/NetworkPolicy.model');
const TimeAnomalyPolicy = require('../models/TimeAnomalyPolicy.model');
const TimeAnomalyException = require('../models/TimeAnomalyException.model');
const ScriptMonitoringRule = require('../models/ScriptMonitoringRule.model');
const RegistryConfigurationControl = require('../models/RegistryConfigurationControl.model');
const { BEACON_BASE_NAME, BEACON_BUILTIN_RULES, BEACON_CUSTOM_PREFIX, BEACON_POLICY_PREFIX } = require('../services/networkMonitoring.service');
const { authenticate, requireCompanyAdmin, requireManager } = require('../middleware/auth.middleware');
const { verifySignedAgentRequest } = require('../utils/agentRequestAuth');
const { TRANSPORT_VERSION: AGENT_PAYLOAD_ENCRYPTION_VERSION } = require('../utils/agentPayloadEncryption');
const {
  heartbeatMacAddress, identityMismatch, normalizeMac,
} = require('../utils/agentIdentity');
const { getSubscriptionEntitlement } = require('../utils/subscriptionEntitlement');
const { resolveIdsHeartbeat } = require('../utils/agentCapabilities');
const { resolvePackageForSystem, defaultPackageForSystem } = require('../utils/agentPackageProfile');
const { CAPABILITY_GROUPS, listAttackTypes } = require('../constants/idsIpsCapabilities');
const { securityPolicySnapshot, sanitizeControlReport, securityPolicyMatchesReport } = require('../utils/agentSecurityPolicy');

// Desktop and Android releases have independent version lines. A single global
// value previously made a v3.x Windows install "update" to Android v0.x.
const AGENT_VERSION = process.env.AGENT_VERSION || '0.1.13';
const ANDROID_AGENT_VERSION = process.env.ANDROID_AGENT_VERSION || '0.1.4';
const CREDENTIAL_SECURITY_RULE_IDS = Object.freeze([
  'CRED_DUMP_TOOL', 'CRED_LSASS_DUMP', 'CRED_SAM_SECRETS_DUMP', 'CRED_KERBEROS_ABUSE',
  'CRED_PASS_THE_HASH', 'CRED_WINDOWS_VAULT_ACCESS', 'CRED_MACOS_KEYCHAIN_ACCESS',
  'CRED_UNIX_SECRET_FILE_ACCESS', 'CRED_BROWSER_PASSWORD_STORE_ACCESS',
  'CRED_EXPLICIT_PRIVILEGED_AUTH', 'CRED_STORE_METADATA_CHANGED',
  'AUTH_SCREEN_LOCK', 'AUTH_SCREEN_UNLOCK_SUCCESS', 'AUTH_SCREEN_UNLOCK_FAILURE',
]);

function agentPackageSha256(payload) {
  const algorithm = String(process.env.AGENT_PACKAGE_HASH_ALGORITHM || 'sha256').toLowerCase();
  if (algorithm !== 'sha256') {
    throw new Error('AGENT_PACKAGE_HASH_ALGORITHM must be sha256');
  }
  return crypto.createHash('sha256').update(payload).digest();
}

function setAgentPackageIntegrityHeaders(res, payload) {
  const digest = agentPackageSha256(payload);
  const sha256 = digest.toString('hex');
  res.setHeader('X-AJNAT-Artifact-SHA256', sha256);
  res.setHeader('Digest', `sha-256=${digest.toString('base64')}`);
  res.setHeader('Content-Digest', `sha-256=:${digest.toString('base64')}:`);
  return sha256;
}

// How long a queued OTA update may stay in-flight before it is treated as failed.
const UPDATE_TIMEOUT_MS = Number(process.env.AGENT_UPDATE_TIMEOUT_MS || 15 * 60 * 1000);

function agentServerConnection() {
  const proto = String(process.env.SERVER_PROTO).trim();
  const ip = String(process.env.SERVER_IP).trim();
  const port = Number(process.env.SERVER_PORT);
  return { proto, ip, port, url: `${proto}://${ip}:${port}` };
}

function compareVersions(left, right) {
  const parts = value => String(value || '').trim().replace(/^v/i, '')
    .split(/[+-]/)[0].split('.').map(part => Number.parseInt(part, 10) || 0);
  const a = parts(left);
  const b = parts(right);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (a[index] || 0) - (b[index] || 0);
    if (difference !== 0) return difference > 0 ? 1 : -1;
  }
  return 0;
}

function isAndroidSystem(system = {}) {
  return String(system.agentType || '').toLowerCase() === 'phone'
    || /android/i.test(`${system.os || ''} ${system.osType || ''}`);
}

function currentAgentVersionFor(system) {
  return isAndroidSystem(system) ? ANDROID_AGENT_VERSION : AGENT_VERSION;
}

const isAgentVersionCurrent = (version, targetVersion = AGENT_VERSION) => (
  Boolean(version) && compareVersions(version, targetVersion) === 0
);

// Update status to report to dashboards, with a lazy timeout so a stuck in-progress
// update surfaces as 'failed' without needing a background sweep.
function effectiveUpdateStatus(system) {
  const status = system.updateStatus || 'idle';
  if (['pending', 'downloading', 'installing'].includes(status)) {
    const pendingUpdate = [...(system.pendingCommands || [])]
      .reverse()
      .find(item => item?.command === 'update');
    const startedAt = system.updateRequestedAt
      ? new Date(system.updateRequestedAt).getTime()
      : (pendingUpdate?.createdAt ? new Date(pendingUpdate.createdAt).getTime() : 0);
    // Older Android/desktop builds could leave an orphaned "installing" state
    // after the command was removed. Do not disable the Update button forever.
    if (!pendingUpdate && !startedAt) return 'failed';
    if (startedAt && (Date.now() - startedAt) > UPDATE_TIMEOUT_MS) return 'failed';
  }
  return status;
}

function heartbeatIp(req) {
  const reported = String(req.body?.ip || '').trim();
  const connected = String(req.socket?.remoteAddress || req.connection?.remoteAddress || req.ip || '').trim();
  return (reported || connected)
    .replace(/^::ffff:/, '')
    .replace(/^::1$/, '127.0.0.1')
    .slice(0, 64);
}

function cleanSha256(value) {
  const text = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(text) ? text : '';
}

function sanitizeAgentSecurityReport(value, system, now) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const allowedStatuses = new Set(['unknown', 'verified', 'mismatch', 'missing', 'error']);
  let integrityStatus = allowedStatuses.has(value.integrityStatus) ? value.integrityStatus : 'error';
  const reportedHash = cleanSha256(value.reportedFleetSha256);
  const manifestHash = cleanSha256(value.expectedFleetSha256);
  const serverHash = cleanSha256(system.agentExpectedIntegrityHash);
  const pendingHash = cleanSha256(system.agentPendingIntegrityHash);
  const allowedHashes = [serverHash, pendingHash].filter(Boolean);
  const findings = Array.isArray(value.findings) ? value.findings.slice(0, 40).map(item => ({
    type: String(item?.type || 'unknown').slice(0, 48),
    file: String(item?.file || '').slice(0, 260),
    detail: String(item?.detail || '').slice(0, 300),
  })) : [];
  if (integrityStatus === 'verified' && (!reportedHash || !manifestHash || !allowedHashes.length)) {
    integrityStatus = 'unknown';
    findings.push({ type: 'unverified_baseline', file: '', detail: 'A server package baseline and both reported hashes are required for verification' });
  }
  if (allowedHashes.length && reportedHash && !allowedHashes.includes(reportedHash)) {
    integrityStatus = 'mismatch';
    if (!findings.some(item => item.type === 'server_hash_mismatch')) {
      findings.push({
        type: 'server_hash_mismatch', file: '',
        detail: 'Agent aggregate SHA-256 does not match the package generated by the server',
      });
    }
  }
  if (allowedHashes.length && manifestHash && !allowedHashes.includes(manifestHash)) {
    integrityStatus = 'mismatch';
    findings.push({
      type: 'manifest_replaced', file: 'integrity_manifest.json',
      detail: 'Agent manifest hash does not match the package generated by the server',
    });
  }
  const analysisTools = Array.isArray(value.analysisTools)
    ? [...new Set(value.analysisTools.map(tool => String(tool).slice(0, 64)).filter(Boolean))].slice(0, 20)
    : [];
  const debuggerDetected = value.debuggerDetected === true;
  const incidentActive = ['mismatch', 'missing', 'error'].includes(integrityStatus)
    || debuggerDetected || analysisTools.length > 0
    || (system.agentSecurityIncidentActive === true && integrityStatus !== 'verified');
  const checkedAtValue = new Date(value.checkedAt || now);
  const checkedAt = Number.isNaN(checkedAtValue.getTime()) || checkedAtValue > now ? now : checkedAtValue;
  const fingerprint = crypto.createHash('sha256').update(JSON.stringify({
    integrityStatus, reportedHash, debuggerDetected, analysisTools,
    findings: findings.map(item => [item.type, item.file, item.detail]),
    lockdown: value.lockdownActive === true,
  })).digest('hex');
  return {
    integrityStatus, reportedHash, manifestHash, findings: findings.slice(0, 40),
    analysisTools, debuggerDetected, incidentActive, checkedAt, fingerprint,
    lockdownActive: value.lockdownActive === true,
    matchedPending: Boolean(pendingHash && reportedHash === pendingHash && manifestHash === pendingHash),
  };
}

function sanitizeTransportSecurity(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return Object.fromEntries(Object.entries(value).slice(0, 20).map(([key, item]) => [
    String(key).slice(0, 64),
    ['string', 'number', 'boolean'].includes(typeof item) ? String(item).slice(0, 300) : '',
  ]));
}

async function recordAgentSecurityTransition(req, system, report, now) {
  if (!report || system.agentSecurityEventFingerprint === report.fingerprint) return;
  if (!report.incidentActive && !system.agentSecurityIncidentActive) return;
  const action = report.incidentActive ? 'AGENT_TAMPER_DETECTED' : 'AGENT_SECURITY_RECOVERED';
  const summary = report.incidentActive
    ? `Agent self-protection detected ${report.integrityStatus} integrity, debugger=${report.debuggerDetected}, tools=${report.analysisTools.join(', ') || 'none'}`
    : 'Agent self-protection reports verified integrity and no active analysis tools';
  const audit = await AgentSecurityAudit.create({
    tenantId: system.tenantId, companyId: system.companyId?._id || system.companyId,
    systemId: system._id, userId: null, username: 'AJNAT Agent', role: 'system',
    action, previousValue: {
      incidentActive: system.agentSecurityIncidentActive,
      integrityStatus: system.agentIntegrityStatus,
    },
    newValue: {
      integrityStatus: report.integrityStatus,
      debuggerDetected: report.debuggerDetected,
      analysisTools: report.analysisTools,
      lockdownActive: report.lockdownActive,
      findings: report.findings,
    },
    sourceIp: heartbeatIp(req), device: 'AJNAT endpoint self-protection',
    result: report.incidentActive ? 'denied' : 'success',
  });
  if (report.incidentActive) {
    const eventFingerprint = crypto.createHash('sha256')
      .update(`${system._id}:${report.fingerprint}:${system.agentSecurityLastEventAt || 'first'}`).digest('hex');
    const alert = await Alert.create({
      tenantId: system.tenantId, partnerId: system.partnerId,
      companyId: system.companyId?._id || system.companyId,
      departmentId: system.departmentId, systemId: system._id,
      eventId: `agent-security-${system._id}-${now.getTime()}`,
      eventFingerprint, schemaVersion: 1,
      normalizedEventType: 'AGENT_TAMPER_DETECTED',
      eventName: 'AJNAT agent tamper or reverse-engineering activity detected',
      eventTimestamp: now, receivedAt: now, sensor: 'AJNAT Self Protection',
      agentId: system.agentId, agentName: system.name, hostname: system.hostname,
      osType: system.osType, agentVersion: system.agentVersion,
      ruleId: 'AGENT_TAMPER_DETECTED', ruleLevel: 15,
      description: summary, full_log: JSON.stringify(report).slice(0, 12000),
      srcip: heartbeatIp(req), source: 'agent-security', type: 'AGENT_TAMPER_DETECTED',
      module: 'EDR', source_type: 'edr', event_category: 'agent_tamper',
      attackType: 'Defense Evasion', category: 'Endpoint Security',
      subCategory: 'Agent Self Protection', eventType: 'tamper',
      riskScore: report.integrityStatus === 'mismatch' || report.debuggerDetected ? 100 : 90,
      recommendedAction: 'Keep the agent in lockdown, preserve evidence, verify package integrity, then recover or update from the trusted console.',
      eventCategory: 'edr', severity: 'critical', status: 'open',
      detectionSource: 'AJNAT Agent Self Protection', firstSeen: now, lastSeen: now,
      actionable: true, dataOrigin: 'agent', rawEvent: report,
    }).catch(error => {
      if (error?.code !== 11000) throw error;
      return null;
    });
    if (alert) {
      const io = req.app.get('io');
      io?.to(`company:${alert.companyId}`).emit('alert:new', alert);
      if (alert.departmentId) io?.to(`dept:${alert.departmentId}`).emit('alert:new', alert);
      io?.to('superadmin').emit('alert:new', alert);
    }
  } else {
    // A verified recovery closes the alert raised by this self-protection
    // incident. Keep the original evidence, but do not leave a recovered
    // endpoint represented as an active critical alert indefinitely.
    await Alert.updateMany({
      companyId: system.companyId?._id || system.companyId,
      systemId: system._id,
      type: 'AGENT_TAMPER_DETECTED',
      status: { $in: ['open', 'investigating', 'under_observation'] },
    }, {
      $set: { status: 'resolved', resolvedAt: now },
    });
  }
  req.app.get('io')?.to('superadmin').emit('agent-security:update', {
    systemId: system._id, audit, incidentActive: report.incidentActive,
  });
}

function getAgentLicenseLimit(company) {
  const sysCount = Number(company?.plan?.systemCount) || 0;
  const srvCount = Number(company?.plan?.serverCount) || 0;
  const phnCount = Number(company?.plan?.phoneCount) || 0;
  const totalEndpoints = sysCount + srvCount + phnCount;
  const legacyLimit = Number(company?.plan?.systemLimit) || 0;

  if (totalEndpoints > 0) return totalEndpoints;
  return legacyLimit > 0 ? legacyLimit : 0;
}

function classifyDownloadCategory(type, requestedCategory = '') {
  const category = String(requestedCategory || '').toLowerCase();
  if (['zip', 'universal', 'bundle'].includes(type)) return 'universal';
  if (['apk'].includes(type)) return 'android';
  if (['solaris'].includes(type)) return 'server';
  if (category === 'server' || ['linux-server', 'windows-server', 'solaris-server'].includes(category)) return 'server';
  if (category === 'universal') return 'universal';
  if (category === 'android' || ['iphone', 'ios', 'ipad'].includes(category)) return 'system';
  if (category === 'system') return 'system';
  return 'system';
}

function findVelociraptorClientBundle(type = 'deb') {
  const bases = [
    process.env.VELOCIRAPTOR_CLIENT_BUNDLE_DIR,
    path.resolve(__dirname, '..', '..', '..', 'velociraptor', 'client_bundles'),
    path.resolve(process.cwd(), 'velociraptor', 'client_bundles'),
    path.resolve(process.cwd(), '..', 'velociraptor', 'client_bundles'),
  ].filter(Boolean);
  const rels = type === 'rpm'
    ? ['linux/velociraptor_client_amd64.rpm', 'linux/velociraptor_client_amd64_repacked']
    : ['linux/velociraptor_client_amd64.deb', 'linux/velociraptor_client_amd64_repacked'];
  for (const base of bases) {
    for (const rel of rels) {
      const candidate = path.join(base, rel);
      try {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          fs.accessSync(candidate, fs.constants.R_OK);
          return candidate;
        }
      } catch { /* skip unreadable bundle */ }
    }
  }
  return '';
}

function addVelociraptorBundle(zip, dirName) {
  const bundle = findVelociraptorClientBundle('deb') || findVelociraptorClientBundle('rpm');
  if (bundle) zip.addLocalFile(bundle, `${dirName}/velociraptor`);
}

function localVelociraptorClientsBySnapshot() {
  const configPath = String(process.env.VELOCIRAPTOR_SERVER_CONFIG || '').trim();
  if (!configPath) return [];

  const snapshotPath = path.join(path.dirname(configPath), 'client_info', 'snapshot.json');
  try {
    return fs.readFileSync(snapshotPath, 'utf8')
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean)
      .map(line => {
        try {
          const row = JSON.parse(line);
          const decodedInfo = row.info ? Buffer.from(String(row.info), 'hex').toString('utf8') : '';
          return {
            clientId: row.client_id || row.ClientId || '',
            searchable: decodedInfo.toLowerCase(),
          };
        } catch {
          return null;
        }
      })
      .filter(row => row?.clientId);
  } catch {
    return [];
  }
}

function findVelociraptorClientIdForSystem(system) {
  if (system?.velociraptorClientId) return system.velociraptorClientId;

  const hostname = String(system?.hostname || '').trim().toLowerCase();
  if (!hostname) return '';

  const matches = localVelociraptorClientsBySnapshot()
    .filter(client => client.searchable.includes(hostname));
  return matches.length === 1 ? matches[0].clientId : '';
}

async function refreshSystemVelociraptorClientId(system) {
  const clientId = findVelociraptorClientIdForSystem(system);
  if (!clientId || system?.velociraptorClientId) return system;

  try {
    const updated = await System.findByIdAndUpdate(
      system._id,
      { velociraptorClientId: clientId },
      { new: true }
    ).populate('departmentId', 'name');
    return updated || system;
  } catch {
    return { ...system.toObject?.() || system, velociraptorClientId: clientId };
  }
}

// ── Helper: Check if company has reached their download limit ────────────────
async function checkDownloadLimit(companyId) {
  try {
    const company = await Company.findById(companyId).lean();
    if (!company) return { allowed: false, reason: 'Company not found', current: 0, limit: 0 };

    const entitlement = await getSubscriptionEntitlement(company);
    const batchLimit =
      entitlement.batchSystemCount +
      entitlement.batchServerCount +
      entitlement.batchPhoneCount;
    const storedBaseLimit =
      (Number(company?.plan?.baseSystemCount) || 0) +
      (Number(company?.plan?.baseServerCount) || 0) +
      (Number(company?.plan?.basePhoneCount) || 0);
    const baseLimit = entitlement.baseActive
      ? (storedBaseLimit > 0 ? storedBaseLimit : Math.max(0, getAgentLicenseLimit(company) - batchLimit))
      : 0;
    const calculatedLimit = baseLimit + batchLimit;
    const systemLimit = calculatedLimit > 0
      ? calculatedLimit
      : (entitlement.baseActive ? getAgentLicenseLimit(company) : 0);

    // Count TOTAL DOWNLOADS only (how many times download button was clicked)
    const billableDownloadFilter = {
      companyId,
      downloadType: { $not: /^update-/ },
    };
    const downloadCount = await Download.countDocuments(billableDownloadFilter);

    if (downloadCount >= systemLimit) {
      return {
        allowed: false,
        reason: `Agent download limit reached. You've downloaded ${downloadCount} / ${systemLimit} times. To download more, please upgrade your plan.`,
        current: downloadCount,
        limit: systemLimit,
        type: 'limit_exceeded',
      };
    }

    return {
      allowed: true,
      current: downloadCount,
      limit: systemLimit,
      remaining: systemLimit - downloadCount,
    };
  } catch (err) {
    console.error('[checkDownloadLimit]', err.message);
    return { allowed: false, reason: 'Error checking download limit', current: 0, limit: 0 };
  }
}

function recalcPartnerAgentLicenses(partner) {
  const now = new Date();
  const purchases = Array.isArray(partner?.agentLicensePurchases) ? partner.agentLicensePurchases : [];
  let totalPurchased = 0;
  let consumedLicenses = 0;
  let activeLicenses = 0;
  let inactiveLicenses = 0;
  let lastExpiryAt = null;
  purchases.forEach(item => {
    const qty = Number(item.agentQuantity || 0);
    const consumed = Number(item.consumedQuantity || 0);
    totalPurchased += qty;
    consumedLicenses += consumed;
    if (item.expiryDate && new Date(item.expiryDate) <= now) item.status = 'inactive';
    if (item.status === 'active') activeLicenses += Math.max(qty - consumed, 0);
    if (item.status !== 'active') inactiveLicenses += qty;
    if (item.expiryDate && (!lastExpiryAt || new Date(item.expiryDate) > new Date(lastExpiryAt))) lastExpiryAt = item.expiryDate;
  });
  partner.agentLicenseSummary = {
    totalPurchased,
    consumedLicenses,
    remainingLicenses: Math.max(activeLicenses, 0),
    activeLicenses,
    inactiveLicenses,
    lastExpiryAt,
  };
  partner.capabilities = partner.capabilities || {};
  partner.capabilities.downloadAgent = activeLicenses > 0;
  return partner.agentLicenseSummary;
}

async function requirePartnerAgentLicense(company) {
  if (!company?.partnerId) return { allowed: true, partner: null };
  const partner = await Partner.findById(company.partnerId);
  if (!partner) return { allowed: false, reason: 'Partner account not found' };
  const summary = recalcPartnerAgentLicenses(partner);
  if (summary.remainingLicenses <= 0) {
    await partner.save().catch(() => { });
    return { allowed: false, reason: 'Partner agent licenses are exhausted or expired. Please ask your partner to buy more licenses.' };
  }
  return { allowed: true, partner };
}

async function consumePartnerAgentLicense(partner) {
  if (!partner) return;
  recalcPartnerAgentLicenses(partner);
  const active = (partner.agentLicensePurchases || [])
    .filter(item => item.status === 'active' && Number(item.agentQuantity || 0) > Number(item.consumedQuantity || 0))
    .sort((a, b) => new Date(a.expiryDate || 0) - new Date(b.expiryDate || 0))[0];
  if (active) active.consumedQuantity = Number(active.consumedQuantity || 0) + 1;
  recalcPartnerAgentLicenses(partner);
  await partner.save().catch(() => { });
}

// Bootstrap a unique endpoint certificate over the already encrypted and
// HMAC-signed agent channel. TLS proves possession of the private key; the
// server pins that certificate to exactly one System record.
router.post('/certificate/enroll', async (req, res) => {
  try {
    if (!req.socket?.encrypted) {
      return res.status(400).json({ message: 'AJNAT certificate enrollment requires HTTPS' });
    }
    const auth = await verifySignedAgentRequest(req, {
      agentKey: req.body.agent_key,
      allowCertificateEnrollment: true,
    });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message });

    const certificate = req.socket.getPeerCertificate?.();
    const fingerprint256 = String(certificate?.fingerprint256 || '').replace(/:/g, '').toLowerCase();
    const claimedFingerprint = String(req.body.certificate_fingerprint256 || '').replace(/:/g, '').toLowerCase();
    const expectedCommonName = `AJNAT-${auth.system._id}`;
    if (String(req.body.system_id || '') !== String(auth.system._id)) {
      return res.status(403).json({ message: 'AJNAT enrollment system identity mismatch' });
    }
    if (!fingerprint256 || fingerprint256.length !== 64) {
      return res.status(400).json({ message: 'A valid client certificate was not presented' });
    }
    if (claimedFingerprint !== fingerprint256) {
      return res.status(400).json({ message: 'Presented certificate fingerprint does not match enrollment request' });
    }
    if (String(certificate?.subject?.CN || '') !== expectedCommonName) {
      return res.status(400).json({ message: 'AJNAT client certificate identity does not match system' });
    }
    const expiresAt = new Date(certificate.valid_to);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt <= new Date()) {
      return res.status(400).json({ message: 'AJNAT client certificate is expired or invalid' });
    }

    await System.updateOne({ _id: auth.system._id }, {
      $set: {
        agentCertificateFingerprint256: fingerprint256,
        agentCertificateSerial: String(certificate.serialNumber || ''),
        agentCertificateExpiresAt: expiresAt,
        agentCertificateRevokedAt: null,
      },
    });
    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      enrolled: true,
      fingerprint256,
      expiresAt: expiresAt.toISOString(),
    });
  } catch (err) {
    console.error('[agent/certificate/enroll]', err.message);
    return res.status(500).json({ message: 'Unable to enroll AJNAT client certificate' });
  }
});

// Derive a per-agent AES-256 key from a server-only master secret. The key is
// returned only over an authenticated, replay-protected agent request and is
// never embedded in an installer or persisted in agent configuration.
router.post('/storage-key', async (req, res) => {
  try {
    const auth = await verifySignedAgentRequest(req, { agentKey: req.body.agent_key });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message });
    const master = String(process.env.AGENT_STORAGE_MASTER_KEY || '');
    if (Buffer.byteLength(master, 'utf8') < 32) {
      return res.status(503).json({ message: 'Agent storage encryption is not configured' });
    }
    const purpose = String(req.body.purpose || 'durable-spool-v1');
    if (purpose !== 'durable-spool-v1') return res.status(400).json({ message: 'Invalid key purpose' });
    const context = `${auth.system._id}:${purpose}`;
    const key = crypto.createHmac('sha256', master).update(context).digest('base64');
    res.setHeader('Cache-Control', 'no-store');
    return res.json({ algorithm: 'AES-256-GCM', key, purpose });
  } catch (err) {
    console.error('[agent/storage-key]', err.message);
    return res.status(500).json({ message: 'Unable to issue storage key' });
  }
});

// ── POST /api/agent/response-result — signed agent callback, no JWT ────────
// This stays ahead of router.use(authenticate), just like heartbeat. A result is
// accepted only for the authenticated system and its tenant/company.
router.post('/response-result', async (req, res) => {
  try {
    const auth = await verifySignedAgentRequest(req, { agentKey: req.body.agent_key });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message });
    const { responseId, commandId, ok, result, durationMs, exitCode } = req.body;
    if (!responseId || !commandId || typeof ok !== 'boolean') {
      return res.status(400).json({ message: 'responseId, commandId, and ok are required' });
    }
    const { recordAgentResult } = require('../services/automatedResponse.service');
    const response = await recordAgentResult({
      companyId: auth.system.companyId,
      systemId: auth.system._id,
      responseId,
      commandId,
      ok,
      result: String(result || '').slice(0, 2000),
      durationMs: Number(durationMs || 0),
      exitCode: Number.isFinite(Number(exitCode)) ? Number(exitCode) : null,
    }, req.app.get('io'));
    res.json({ ok: true, status: response.status });
  } catch (err) {
    console.error('[agent/response-result]', err.message);
    res.status(400).json({ message: 'Unable to record response result' });
  }
});

router.post('/response-status', async (req, res) => {
  try {
    const auth = await verifySignedAgentRequest(req, { agentKey: req.body.agent_key });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message });
    const { responseId, commandId, status } = req.body;
    if (!responseId || !commandId || !['acknowledged', 'executing'].includes(status)) {
      return res.status(400).json({ message: 'A valid responseId, commandId, and status are required' });
    }
    const { recordAgentStatus } = require('../services/automatedResponse.service');
    const response = await recordAgentStatus({ companyId: auth.system.companyId, systemId: auth.system._id, responseId, commandId, status }, req.app.get('io'));
    res.json({ ok: true, status: response.status });
  } catch (err) {
    console.error('[agent/response-status]', err.message);
    res.status(400).json({ message: 'Unable to record response status' });
  }
});

// Country datasets use the same signed agent identity as heartbeat.
router.post('/country-block-policy', async (req, res) => {
  try {
    const auth = await verifySignedAgentRequest(req, { agentKey: req.body.agent_key });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message });
    const policy = await CountryBlock.enforcementPolicy(auth.system);
    res.json(policy);
  } catch (error) {
    console.error('[country-block-policy]', error.message);
    res.status(503).json({ message: 'Country IP ranges are temporarily unavailable. Existing blocks are retained.' });
  }
});

// ── POST /api/agent/heartbeat — NO JWT, agent uses x-integration-secret ──────
// MUST be defined BEFORE router.use(authenticate) so agent can reach it.
router.post('/heartbeat', async (req, res) => {
  try {
    const { agent_key, agent_version, status } = req.body;
    const secret = req.headers['x-integration-secret'];
    const auth = await verifySignedAgentRequest(req, { agentKey: agent_key });
    const hasIntegrationSecret = secret && secret === process.env.INTEGRATION_SECRET;
    if (!auth.ok && !hasIntegrationSecret) {
      return res.status(auth.status).json({ active: false, stop_monitoring: true, message: auth.message });
    }

    const systemFilter = auth.ok ? { _id: auth.system._id } : { agentKey: agent_key };
    const system = await System.findOne(systemFilter)
      .populate('companyId', 'name plan status partnerId')
      .lean();

    if (!system) return res.status(404).json({ stop_monitoring: true, message: 'Unknown agent key' });

    const heartbeatMac = heartbeatMacAddress(req.body);
    const mismatchReason = identityMismatch(system, req.body);
    if (mismatchReason) {
      console.warn(`[agent/heartbeat] duplicate install blocked: system=${system._id} reason=${mismatchReason}`);
      return res.status(409).json({
        active: false,
        stop_monitoring: true,
        code: 'AGENT_ALREADY_INSTALLED',
        message: `This agent is already installed on another system. ${mismatchReason}. Create a new system and download its own agent.`,
        system_id: system._id,
      });
    }
    // A fresh system record/key must not claim an endpoint identity that is already
    // bound inside the company. This remains enforced while the original record is
    // inactive (for example, during subscription expiry), so recharging resumes the
    // original agent instead of allowing a second agent to take over the machine.
    const incomingAgentId = String(req.body.agentId || req.body.agent_id || '').trim();
    const incomingMac = normalizeMac(req.body.macAddress || req.body.mac_address);
    const duplicateIdentityChecks = [];
    if (incomingAgentId) duplicateIdentityChecks.push({ agentId: incomingAgentId });
    if (incomingMac) duplicateIdentityChecks.push({ macAddress: incomingMac });
    if (duplicateIdentityChecks.length) {
      const identityOwner = await System.findOne({
        companyId: system.companyId?._id || system.companyId,
        $or: duplicateIdentityChecks,
      })
        // The record with real heartbeat history owns the endpoint. This keeps an
        // expired/original installation authoritative over a newly-created key,
        // while allowing it to coexist with older inactive migration records.
        .sort({ lastSeen: -1, installDate: -1, createdAt: 1 })
        .select('_id name agentId macAddress isActive lastSeen installDate createdAt')
        .lean();
      if (identityOwner && String(identityOwner._id) !== String(system._id)) {
        console.warn(`[agent/heartbeat] cross-record endpoint duplicate blocked: incoming=${system._id} owner=${identityOwner._id}`);
        return res.status(409).json({
          active: false,
          stop_monitoring: true,
          code: 'DUPLICATE_ENDPOINT_IDENTITY',
          message: `This endpoint is already registered as ${identityOwner.name || 'another system'}. Recharge or reactivate its original agent instead of installing a second agent key.`,
          system_id: system._id,
        });
      }
    }

    const company = system.companyId;

    // Base subscription and Add-System batches are independent entitlements.
    const entitlement = await getSubscriptionEntitlement(company);
    const planActive = entitlement.licenseActive;
    const now = new Date();
    const baseExpiresAt = company?.plan?.expiresAt ? new Date(company.plan.expiresAt) : null;
    const expiresAt = entitlement.baseActive
      ? baseExpiresAt
      : (entitlement.batchExpiresAt || baseExpiresAt);
    const expired = !planActive && Boolean(baseExpiresAt && now > baseExpiresAt);
    const companyActive = company?.status === 'active';

    const shouldStop = !planActive || expired || !companyActive;

    // Update system heartbeat — persist ALL agent-reported fields
    const heartbeatUpdate = {
      lastSeen: now,
      status: shouldStop ? 'inactive' : 'active',
      isActive: !shouldStop,
    };
    if (agent_version) heartbeatUpdate.agentVersion = agent_version;
    const countryBlockReport = CountryBlock.sanitizeReport(req.body.countryBlockStatus);
    if (countryBlockReport) heartbeatUpdate.countryBlockStatus = countryBlockReport;
    if (req.body.hostname) heartbeatUpdate.hostname = req.body.hostname;
    const currentIp = heartbeatIp(req);
    if (currentIp) heartbeatUpdate.ip = currentIp;
    // Desktop agents in the field use both camelCase and snake_case. Persist the
    // same normalized value used by identity validation so a legitimate NIC
    // rotation is not rediscovered and logged on every heartbeat.
    if (heartbeatMac) heartbeatUpdate.macAddress = heartbeatMac;
    if (req.body.os) heartbeatUpdate.os = req.body.os;
    if (req.body.osType) heartbeatUpdate.osType = req.body.osType;
    if (req.body.os_version || req.body.osVersion)
      heartbeatUpdate.osVersion = req.body.os_version || req.body.osVersion;
    if (req.body.arch) heartbeatUpdate.arch = req.body.arch;
    if (req.body.agentId) heartbeatUpdate.agentId = req.body.agentId;
    const reportedVelociraptorClientId = req.body.velociraptor_client_id || req.body.velociraptorClientId || req.body.client_id;
    // Packaged agent config can retain an old C.xxxx after Velociraptor is
    // re-enrolled. Do not let that stale heartbeat overwrite a server-verified
    // mapping; empty systems still accept their first enrollment ID.
    if (reportedVelociraptorClientId
      && (!system.velociraptorClientId || system.velociraptorClientId === reportedVelociraptorClientId)) {
      heartbeatUpdate.velociraptorClientId = reportedVelociraptorClientId;
    }

    // ── Module flags — persist EDR/IDS/IPS/Firewall status from agent ─────
    if (req.body.edrEnabled != null) heartbeatUpdate.edrEnabled = !!req.body.edrEnabled;
    Object.assign(heartbeatUpdate, resolveIdsHeartbeat(req.body, system));
    if (req.body.packetIdsMode != null) {
      heartbeatUpdate.packetIdsMode = String(req.body.packetIdsMode).slice(0, 80);
    }
    if (req.body.ipsEnforcementMode != null) {
      heartbeatUpdate.ipsEnforcementMode = String(req.body.ipsEnforcementMode).slice(0, 80);
    }
    if (req.body.inlinePacketVerdict != null) {
      heartbeatUpdate.inlinePacketVerdict = req.body.inlinePacketVerdict === true;
    }
    if (req.body.ipsEnabled != null) heartbeatUpdate.ipsEnabled = !!req.body.ipsEnabled;
    if (req.body.firewallEnabled != null) heartbeatUpdate.firewallEnabled = !!req.body.firewallEnabled;
    if (req.body.yaraEnabled != null) heartbeatUpdate.yaraEnabled = !!req.body.yaraEnabled;
    if (req.body.sandboxAnalysisEnabled != null) heartbeatUpdate.sandboxAnalysisEnabled = !!req.body.sandboxAnalysisEnabled;
    if (req.body.sandboxAnalysisStatus && typeof req.body.sandboxAnalysisStatus === 'object' && !Array.isArray(req.body.sandboxAnalysisStatus)) {
      heartbeatUpdate.sandboxAnalysisStatus = {
        collection: ['active', 'disabled', 'degraded'].includes(String(req.body.sandboxAnalysisStatus.collection))
          ? String(req.body.sandboxAnalysisStatus.collection) : 'degraded',
        detonation: 'not-applicable',
        reason: String(req.body.sandboxAnalysisStatus.reason || '').slice(0, 300),
        reportedAt: now,
      };
    }
    if (req.body.sandboxVmStatus && typeof req.body.sandboxVmStatus === 'object' && !Array.isArray(req.body.sandboxVmStatus)) {
      const vmState = ['running', 'idle', 'unavailable'].includes(String(req.body.sandboxVmStatus.state))
        ? String(req.body.sandboxVmStatus.state) : 'unavailable';
      const vmCount = Math.trunc(Math.max(0, Math.min(25, Number(req.body.sandboxVmStatus.vmCount) || 0)));
      heartbeatUpdate.sandboxVmRunning = vmState === 'running' && vmCount > 0;
      heartbeatUpdate.sandboxVmCount = vmCount;
      heartbeatUpdate.sandboxVmStatus = {
        state: vmState,
        vmRunning: heartbeatUpdate.sandboxVmRunning,
        vmCount,
        providers: Array.isArray(req.body.sandboxVmStatus.providers)
          ? req.body.sandboxVmStatus.providers.slice(0, 10).map(value => String(value).slice(0, 80)) : [],
        instances: Array.isArray(req.body.sandboxVmStatus.instances)
          ? req.body.sandboxVmStatus.instances.slice(0, 25).map(instance => ({
            provider: String(instance?.provider || '').slice(0, 80),
            process: String(instance?.process || '').slice(0, 80),
            pid: Math.max(0, Number(instance?.pid) || 0),
            name: String(instance?.name || '').slice(0, 120),
          })) : [],
        checkedAt: now,
        reason: String(req.body.sandboxVmStatus.reason || '').slice(0, 160),
      };
    }
    if (req.body.wafEnabled != null) heartbeatUpdate.wafEnabled = !!req.body.wafEnabled;
    if (req.body.networkMonitorEnabled != null) heartbeatUpdate.networkMonitorEnabled = !!req.body.networkMonitorEnabled;
    if (req.body.dnsSinkholeEnabled != null) heartbeatUpdate.dnsSinkholeEnabled = !!req.body.dnsSinkholeEnabled;
    if (req.body.dnsSinkholeTelemetryEnabled != null) heartbeatUpdate.dnsSinkholeTelemetryEnabled = !!req.body.dnsSinkholeTelemetryEnabled;
    if (req.body.dnsSinkholeEnforcementMode != null) heartbeatUpdate.dnsSinkholeEnforcementMode = String(req.body.dnsSinkholeEnforcementMode).slice(0, 20);
    if (req.body.dnsSinkholePolicyVersion != null && Number.isFinite(Number(req.body.dnsSinkholePolicyVersion))) {
      heartbeatUpdate.dnsSinkholePolicyVersion = Math.max(0, Number(req.body.dnsSinkholePolicyVersion));
    }
    if (req.body.dnsCachePoisonEnabled != null) heartbeatUpdate.dnsCachePoisonEnabled = !!req.body.dnsCachePoisonEnabled;
    if (req.body.dnsCachePoisonTelemetryEnabled != null) heartbeatUpdate.dnsCachePoisonTelemetryEnabled = !!req.body.dnsCachePoisonTelemetryEnabled;
    if (req.body.dnsCachePoisonPolicyVersion != null && Number.isFinite(Number(req.body.dnsCachePoisonPolicyVersion))) {
      heartbeatUpdate.dnsCachePoisonPolicyVersion = Math.max(0, Number(req.body.dnsCachePoisonPolicyVersion));
    }
    if (req.body.dnsCachePoisonStatus && typeof req.body.dnsCachePoisonStatus === 'object' && !Array.isArray(req.body.dnsCachePoisonStatus)) {
      heartbeatUpdate.dnsCachePoisonStatus = req.body.dnsCachePoisonStatus;
    }
    if (req.body.usbMonitorEnabled != null) heartbeatUpdate.usbMonitorEnabled = !!req.body.usbMonitorEnabled;
    if (req.body.processMonitorEnabled != null) heartbeatUpdate.processMonitorEnabled = !!req.body.processMonitorEnabled;
    if (req.body.advancedProcessMonitorEnabled != null) heartbeatUpdate.advancedProcessMonitorEnabled = !!req.body.advancedProcessMonitorEnabled;
    if (req.body.containerMonitorEnabled != null) heartbeatUpdate.containerMonitorEnabled = !!req.body.containerMonitorEnabled;
    if (req.body.advancedProcessSensorStatus && typeof req.body.advancedProcessSensorStatus === 'object' && !Array.isArray(req.body.advancedProcessSensorStatus)) {
      heartbeatUpdate.advancedProcessSensorStatus = req.body.advancedProcessSensorStatus;
    }
    if (req.body.telemetrySensorStatus && typeof req.body.telemetrySensorStatus === 'object' && !Array.isArray(req.body.telemetrySensorStatus)) {
      heartbeatUpdate.telemetrySensorStatus = req.body.telemetrySensorStatus;
    }
    if (req.body.patchInventoryEnabled != null) heartbeatUpdate.patchInventoryEnabled = !!req.body.patchInventoryEnabled;
    if (req.body.memoryMonitorEnabled != null) heartbeatUpdate.memoryMonitorEnabled = !!req.body.memoryMonitorEnabled;
    if (req.body.responseEnabled != null) heartbeatUpdate.responseEnabled = !!req.body.responseEnabled;
    if (req.body.geoEnrichmentEnabled != null) heartbeatUpdate.geoEnrichmentEnabled = !!req.body.geoEnrichmentEnabled;

    const agentSecurityReport = sanitizeAgentSecurityReport(req.body.agent_security, system, now);
    if (agentSecurityReport) {
      heartbeatUpdate.agentReportedIntegrityHash = agentSecurityReport.reportedHash;
      heartbeatUpdate.agentIntegrityStatus = agentSecurityReport.integrityStatus;
      heartbeatUpdate.agentIntegrityCheckedAt = agentSecurityReport.checkedAt;
      heartbeatUpdate.agentSecurityFindings = agentSecurityReport.findings;
      heartbeatUpdate.agentDebuggerDetected = agentSecurityReport.debuggerDetected;
      heartbeatUpdate.agentAnalysisTools = agentSecurityReport.analysisTools;
      heartbeatUpdate.agentSecurityLockdown = agentSecurityReport.lockdownActive;
      heartbeatUpdate.agentSecurityIncidentActive = agentSecurityReport.incidentActive;
      heartbeatUpdate.agentSecurityEventFingerprint = agentSecurityReport.fingerprint;
      if (agentSecurityReport.matchedPending) {
        heartbeatUpdate.agentExpectedIntegrityHash = system.agentPendingIntegrityHash;
        heartbeatUpdate.agentPendingIntegrityHash = '';
      }
      if (system.agentSecurityEventFingerprint !== agentSecurityReport.fingerprint) {
        heartbeatUpdate.agentSecurityLastEventAt = now;
        await recordAgentSecurityTransition(req, system, agentSecurityReport, now).catch(error => {
          console.error('[agent-security] transition logging failed:', error.message);
        });
      }
    }
    const controlReport = sanitizeControlReport(req.body.agent_security, now);
    if (controlReport) {
      // Transport encryption is an observed property of this request.
      if (controlReport.controls.secureCommunication && !req.agentEncryptedEnvelope) {
        controlReport.controls.secureCommunication.state = 'error';
        controlReport.controls.secureCommunication.detail = 'This heartbeat was not encrypted.';
      }
      heartbeatUpdate.agentSecurityPolicyStatus = controlReport;
      const desired = securityPolicySnapshot(system);
      const matches = securityPolicyMatchesReport(desired, controlReport);
      if (matches) {
        const result = controlReport.state === 'failed' ? 'failed' : 'success';
        await AgentSecurityAudit.updateMany({ systemId: system._id, result: 'queued', action: 'SECURITY_CONTROLS_UPDATED',
          'newValue.policyVersion': controlReport.version,
        }, { $set: { result, 'newValue.agentResult': controlReport.error || 'Policy applied and reported by agent', 'newValue.completedAt': now } });
        await AgentSecurityAudit.updateMany({ systemId: system._id, result: 'queued', action: 'SECURITY_CONTROLS_UPDATED',
          'newValue.policyVersion': { $lt: controlReport.version },
        }, { $set: { result: 'superseded', 'newValue.agentResult': 'A newer policy reached the agent first', 'newValue.completedAt': now } });
        await System.updateOne({ _id: system._id }, { $pull: { pendingCommands: { command: 'security-policy-sync' } } });
      }
    }
    if (req.body.transport_security != null || req.agentEncryptedEnvelope) {
      const transportSecurity = sanitizeTransportSecurity(req.body.transport_security);
      delete transportSecurity.api_payload_encryption;
      if (req.agentEncryptedEnvelope) {
        // This flag is observed by the server middleware, not trusted from the
        // agent's self-reported heartbeat fields.
        transportSecurity.api_payload_encryption = AGENT_PAYLOAD_ENCRYPTION_VERSION;
      }
      heartbeatUpdate.agentTransportSecurity = transportSecurity;
    }

    // Command acknowledgement is reported on the heartbeat after execution.
    // It updates the original queued audit instead of creating an ambiguous log.
    if (Array.isArray(req.body.security_action_results)) {
      const AgentSecurityAudit = require('../models/AgentSecurityAudit.model');
      const { recordAgentCommandResult } = require('../services/ips.service');
      for (const result of req.body.security_action_results.slice(0, 20)) {
        if (mongoose.isValidObjectId(result?.auditId)) {
          const command = (system.pendingCommands || []).find(item => String(item.auditId || '') === String(result.auditId));
          const verified = command?.command !== 'verify-integrity' || agentSecurityReport?.integrityStatus === 'verified';
          const status = result.ok === true && verified ? 'success' : 'failed';
          const audit = await AgentSecurityAudit.findOneAndUpdate(
            { _id: result.auditId, systemId: system._id, result: 'queued', 'newValue.command': { $nin: ['security-policy-sync', 'update'] } },
            {
              $set: {
                result: status,
                'newValue.agentResult': verified ? String(result.message || '').slice(0, 500) : 'Agent report does not match the server package integrity baseline',
                'newValue.completedAt': now,
              },
            },
            { new: true },
          ).lean();
          if (audit) req.app.get('io')?.to('superadmin').emit('agent-security:update', { systemId: system._id, audit });
          // Audit-only legacy commands also need removal after acknowledgement;
          // otherwise lockdown/recovery is executed on every heartbeat.
          await System.updateOne({ _id: system._id }, { $pull: { pendingCommands: {
            auditId: { $in: [String(result.auditId), new mongoose.Types.ObjectId(result.auditId)] },
            command: { $nin: ['update', 'security-policy-sync'] },
          } } });
          continue;
        }
        if (result?.commandId && result?.command) {
          const command = String(result.command).toLowerCase();
          // An updater can report "installer started" before the service is
          // replaced. Keep update commands durable until the restarted build
          // proves completion with its embedded update_request_id.
          if (command === 'update') continue;
          await recordAgentCommandResult({
            systemId: system._id,
            commandId: String(result.commandId),
            command,
            ip: result.ip,
            ok: result.ok === true,
            message: String(result.message || '').slice(0, 1000),
          }, req.app.get('io'));
          // Keep this heartbeat response consistent with the state just
          // acknowledged above; `system` was read before result processing.
          if (result.ok === true && command === 'isolate') system.isIsolated = true;
          if (result.ok === true && command === 'reconnect') system.isIsolated = false;
        }
      }
    }

    if (!system.installDate && !shouldStop) heartbeatUpdate.installDate = now;
    if (!system.fimStartAt && !shouldStop) heartbeatUpdate.fimStartAt = system.installDate || heartbeatUpdate.installDate || system.createdAt || now;
    const fimStartAt = heartbeatUpdate.fimStartAt || system.fimStartAt || heartbeatUpdate.installDate || system.installDate || now;

    // ── OTA update tracking ────────────────────────────────────────────────
    // Agents may report interim progress/failure; the definitive success signal is the
    // agent reporting the target version after it restarts into the new build.
    const updateInProgress = ['pending', 'downloading', 'installing'].includes(system.updateStatus);
    const pendingUpdateCommand = [...(system.pendingCommands || [])]
      .reverse()
      .find(item => item?.command === 'update');
    const reachedUpdateTarget = Boolean(
      pendingUpdateCommand
      && agent_version
      && isAgentVersionCurrent(agent_version, pendingUpdateCommand.targetVersion || system.updateTargetVersion)
    );
    const reportedUpdateRequestId = String(req.body.update_request_id || '').trim();
    const reportedStatus = String(req.body.update_status || '').toLowerCase();
    const matchingUpdateRequest = Boolean(
      reportedUpdateRequestId
      && reportedUpdateRequestId === String(pendingUpdateCommand?.id || '')
    );
    const updateRequestConfirmed = Boolean(
      reachedUpdateTarget
      && (pendingUpdateCommand.force !== true
        || (matchingUpdateRequest && !['downloading', 'installing'].includes(reportedStatus)))
    );
    const failedUpdateRequestConfirmed = Boolean(
      updateInProgress
      && pendingUpdateCommand
      && String(req.body.update_status || '').toLowerCase() === 'failed'
      && matchingUpdateRequest
    );
    const currentAgentVersion = currentAgentVersionFor(system);
    const reachedRecordedUpdateTarget = Boolean(
      system.updateRequestedAt
      && agent_version
      && isAgentVersionCurrent(agent_version, system.updateTargetVersion || currentAgentVersion)
    );
    const manualVersionUpdateConfirmed = reachedRecordedUpdateTarget && pendingUpdateCommand?.force !== true;
    if (updateInProgress && updateRequestConfirmed) {
      heartbeatUpdate.updateStatus = 'success';
      heartbeatUpdate.updateFinishedAt = now;
      heartbeatUpdate.updateError = null;
    } else if (failedUpdateRequestConfirmed) {
      heartbeatUpdate.updateStatus = 'failed';
      heartbeatUpdate.updateFinishedAt = now;
      heartbeatUpdate.updateError = String(req.body.update_error || 'Agent reported update failure').slice(0, 500);
    } else if (
      updateInProgress
      && pendingUpdateCommand
      && reportedUpdateRequestId === String(pendingUpdateCommand.id)
      && ['downloading', 'installing'].includes(reportedStatus)
    ) {
      heartbeatUpdate.updateStatus = reportedStatus;
      heartbeatUpdate.updateError = null;
      heartbeatUpdate.updateFinishedAt = null;
    } else if (manualVersionUpdateConfirmed && system.updateStatus !== 'success') {
      // A manual in-place install has no OTA request id, but the reported
      // package-owned version is still definitive. Clear an obsolete failure
      // once the endpoint proves it reached the recorded target release.
      heartbeatUpdate.updateStatus = 'success';
      heartbeatUpdate.updateFinishedAt = now;
      heartbeatUpdate.updateError = null;
    }

    const heartbeatWrite = { $set: heartbeatUpdate };
    if (updateRequestConfirmed || failedUpdateRequestConfirmed || manualVersionUpdateConfirmed) {
      // A Windows installer stops the service process that launched it, so the
      // restarted package's exact version/request id is the durable success
      // signal. Remove only the command that this package acknowledged.
      heartbeatWrite.$pull = pendingUpdateCommand
        ? { pendingCommands: { id: pendingUpdateCommand.id } }
        : { pendingCommands: { command: 'update' } };
    }
    await System.findByIdAndUpdate(system._id, heartbeatWrite);
    if (system.status !== heartbeatUpdate.status || system.isActive !== heartbeatUpdate.isActive || !system.agentVersion) {
      emitPartnerUpdate(req.app?.get?.('io'), company?.partnerId, 'agent_status', company?._id);
    }
    if (pendingUpdateCommand?.auditId && (updateRequestConfirmed || failedUpdateRequestConfirmed)) {
      await AgentSecurityAudit.updateOne({ _id: pendingUpdateCommand.auditId, systemId: system._id, result: 'queued' }, {
        $set: { result: updateRequestConfirmed ? 'success' : 'failed', 'newValue.completedAt': now,
          'newValue.agentResult': updateRequestConfirmed ? `Installed agent ${agent_version} confirmed after restart` : heartbeatUpdate.updateError },
      });
    }
    // Recover completion after an old fallback heartbeat consumed the queue.
    // The installed package still proves the exact request ID and version.
    if (!pendingUpdateCommand && mongoose.isValidObjectId(reportedUpdateRequestId)
      && reachedRecordedUpdateTarget && agentSecurityReport?.integrityStatus === 'verified'
      && !['downloading', 'installing', 'failed'].includes(reportedStatus)) {
      await AgentSecurityAudit.updateOne({ _id: reportedUpdateRequestId, systemId: system._id,
        result: 'queued', 'newValue.command': 'update',
      }, { $set: { result: 'success', 'newValue.completedAt': now,
        'newValue.agentResult': `Installed agent ${agent_version} confirmed after restart (${reportedUpdateRequestId})` } });
    }

    const nextUpdateStatus = heartbeatUpdate.updateStatus;
    if (nextUpdateStatus) {
      const companyRoomId = system.companyId?._id || system.companyId;
      req.app.get('io')?.to(`company:${companyRoomId}`).emit('agent:update-status', {
        systemId: String(system._id),
        agentVersion: agent_version || system.agentVersion || null,
        currentVersion: currentAgentVersion,
        updateStatus: nextUpdateStatus,
        updateError: heartbeatUpdate.updateError ?? system.updateError ?? null,
        updateTargetVersion: pendingUpdateCommand?.targetVersion || system.updateTargetVersion || null,
        lastSeen: now,
      });
    }

    // Push VM start/stop transitions to the existing tenant-scoped dashboard
    // room. The periodic /api/system refresh remains the recovery path when a
    // browser misses a socket event.
    if (heartbeatUpdate.sandboxVmStatus) {
      const previousVmState = String(system.sandboxVmStatus?.state || '');
      const previousVmCount = Number(system.sandboxVmCount ?? system.sandboxVmStatus?.vmCount) || 0;
      const previousProviders = Array.isArray(system.sandboxVmStatus?.providers)
        ? system.sandboxVmStatus.providers.map(String).sort().join('|') : '';
      const nextProviders = heartbeatUpdate.sandboxVmStatus.providers.map(String).sort().join('|');
      const vmStatusChanged = previousVmState !== heartbeatUpdate.sandboxVmStatus.state
        || previousVmCount !== heartbeatUpdate.sandboxVmStatus.vmCount
        || previousProviders !== nextProviders;

      if (vmStatusChanged) {
        const companyRoomId = system.companyId?._id || system.companyId;
        req.app.get('io')?.to(`company:${companyRoomId}`).emit('sandbox:vm-status', {
          systemId: String(system._id),
          hostname: heartbeatUpdate.hostname || system.hostname || system.name || '',
          sandboxVmRunning: heartbeatUpdate.sandboxVmRunning,
          sandboxVmCount: heartbeatUpdate.sandboxVmCount,
          sandboxVmStatus: heartbeatUpdate.sandboxVmStatus,
          lastSeen: now,
        });
      }
    }

    const updateAvailable = Boolean(agent_version)
      && compareVersions(agent_version, currentAgentVersion) < 0;

    if (shouldStop) {
      const reason = !companyActive ? 'Company suspended'
        : expired ? `Subscription expired on ${expiresAt?.toDateString()}`
          : 'Subscription inactive — please renew payment';
      // Only log warnings once per status change, avoid console flooding on every heartbeat
      if (system.status !== 'inactive') {
        console.warn(`[heartbeat] STOP_MONITORING — system:${system._id} reason:${reason}`);
      }
      return res.json({
        active: false,
        stop_monitoring: true,
        message: reason,
        system_id: system._id,
        update_available: updateAvailable,
      });
    }

    // Commands remain durable until the agent reports their commandId result on
    // a later heartbeat. This prevents a process crash after delivery from
    // silently losing an IPS or response command.
    const commandQueue = await System.findById(system._id).select('pendingCommands').lean();
    const responseUpdateStatus = heartbeatUpdate.updateStatus || system.updateStatus;
    // Keep the update command durable for final version confirmation, but do
    // not launch another detached installer on each heartbeat while the first
    // one is already downloading/installing.
    const pendingCommands = (commandQueue?.pendingCommands || []).filter(command => (
      command?.command !== 'update'
      || !['downloading', 'installing'].includes(responseUpdateStatus)
    ));
    const usbPolicies = await UsbPolicy.find({
      companyId: company._id,
      enabled: true,
      $or: [{ departmentId: null }, { departmentId: { $exists: false } }, ...(system.departmentId ? [{ departmentId: system.departmentId }] : [])],
    }).select('name description ruleType action values maxBytes updatedAt').lean();
    const registryConfigurationControls = mongoose.connection.readyState === 1
      ? await RegistryConfigurationControl.find({
        companyId: company._id,
        kind: 'policy',
        enabled: true,
        $and: [
          { $or: [{ departmentId: null }, { departmentId: { $exists: false } }, ...(system.departmentId ? [{ departmentId: system.departmentId }] : [])] },
          { $or: [{ systemId: null }, { systemId: { $exists: false } }, { systemId: system._id }] },
          { $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] },
        ],
      }).select('target updatedAt').sort({ updatedAt: -1 }).limit(128).lean()
      : [];
    const configuredMonitorPaths = [...new Set(registryConfigurationControls
      .map(control => String(control.target || '').trim())
      .filter(target => target && target !== '*' && !target.includes('*')))].slice(0, 64);
    const memoryRules = await MemoryDetectionRule.find({
      companyId: company._id,
      $or: [{ departmentId: null }, { departmentId: { $exists: false } }, ...(system.departmentId ? [{ departmentId: system.departmentId }] : [])],
    }).select('ruleId name enabled threshold timeWindowSeconds minimumSampleCount cooldownSeconds severity confidence riskScore operatingSystems processExclusions allowlist maintenanceWindows updatedAt').lean();
    const memoryRule = ruleId => memoryRules.find(rule => rule.ruleId === ruleId);
    const memoryRuleEnabled = (...ruleIds) => !memoryRules.length || ruleIds.some(ruleId => memoryRule(ruleId)?.enabled !== false);
    const allGeolocationPolicies = await GeolocationPolicy.find({
      companyId: company._id,
      enabled: true,
      $or: [{ departmentId: null }, { departmentId: { $exists: false } }, ...(system.departmentId ? [{ departmentId: system.departmentId }] : [])],
    }).select('name category severity action priority conditions version updatedAt').sort({ priority: 1 }).lean();
    const geolocationPolicies = allGeolocationPolicies.filter(policy => {
      const targets = Array.isArray(policy.conditions?.systemIds) ? policy.conditions.systemIds.map(String) : [];
      return !targets.length || targets.includes(String(system._id));
    });
    const countryPolicies = geolocationPolicies.filter(policy => policy.category === 'Country-Based');
    const highRiskCountries = [...new Set(countryPolicies
      .filter(policy => !/allow/i.test(policy.action))
      .flatMap(policy => policy.conditions?.countries || []))];
    const allowedCountries = [...new Set(countryPolicies
      .filter(policy => /allow/i.test(policy.action))
      .flatMap(policy => policy.conditions?.countries || []))];
    const travelPolicy = geolocationPolicies.find(policy => policy.category === 'Impossible Travel');
    const locationPolicy = geolocationPolicies.find(policy => policy.category === 'Location-Based');
    const gpsTrackingPolicy = geolocationPolicies.find(policy => (
      ['Device GPS Tracking', 'Location-Based'].includes(policy.category)
      && policy.conditions?.gpsTracking !== false
    ));
    const allTimeAnomalyPolicies = mongoose.connection.readyState === 1
      ? await TimeAnomalyPolicy.find({
        companyId: company._id,
        $or: [{ departmentId: null }, { departmentId: { $exists: false } }, ...(system.departmentId ? [{ departmentId: system.departmentId }] : [])],
      }).select('name enabled priority systemIds workingHoursStart workingHoursEnd weekendDays holidays timezone authFailureWindowSeconds authFailureThreshold anomalyRiskThreshold alertCooldownSeconds baselineMinimumSamples exceptions updatedAt').sort({ priority: 1, updatedAt: -1 }).lean()
      : [];
    const timeAnomalyPolicy = allTimeAnomalyPolicies.find(policy => {
      const targets = Array.isArray(policy.systemIds) ? policy.systemIds.map(String) : [];
      return !targets.length || targets.includes(String(system._id));
    });
    const activeTimeAnomalyException = mongoose.connection.readyState === 1
      ? await TimeAnomalyException.findOne({
        companyId: company._id,
        enabled: true,
        systemIds: system._id,
        startsAt: { $lte: new Date() },
        expiresAt: { $gt: new Date() },
        $or: [{ departmentId: null }, { departmentId: { $exists: false } }, ...(system.departmentId ? [{ departmentId: system.departmentId }] : [])],
      }).sort({ expiresAt: -1 }).lean()
      : null;
    const scriptMonitoringRules = mongoose.connection.readyState === 1
      ? await ScriptMonitoringRule.find({
        companyId: company._id,
        $or: [{ departmentId: null }, { departmentId: { $exists: false } }, ...(system.departmentId ? [{ departmentId: system.departmentId }] : [])],
        $and: [{ $or: [{ systemIds: { $size: 0 } }, { systemIds: system._id }] }],
      }).select('name enabled priority systemIds interpreters trustedPaths trustedHashes trustedPublishers riskThreshold alertCooldownSeconds detectEncodedCommands detectObfuscation detectDownloadExecution detectPersistence detectExternalConnections riskWeights updatedAt').sort({ priority: 1, updatedAt: -1 }).lean()
      : [];
    const activeScriptMonitoringRules = scriptMonitoringRules.filter(rule => rule.enabled !== false);
    const wafAttackProtectionPolicy = mongoose.connection.readyState === 1
      ? await mongoose.connection.db.collection('waf_attack_protection_policies').findOne({
        company: String(company._id),
      })
      : null;
    const dnsSinkholeConfiguration = mongoose.connection.readyState === 1
      ? await DnsSinkholeConfig.findOne({ companyId: company._id }).lean()
      : null;
    const dnsCachePoisonConfiguration = mongoose.connection.readyState === 1
      ? await DnsCachePoisonConfig.findOne({ companyId: company._id }).lean()
      : null;
    const ransomwareConfiguration = mongoose.connection.readyState === 1
      ? await RansomwareConfig.findOne({ companyId: company._id }).lean()
      : null;
    const hashSignaturePolicy = mongoose.connection.readyState === 1
      ? await HashSignaturePolicy.findOne({ companyId: company._id }).lean()
      : null;
    const beaconingPolicies = mongoose.connection.readyState === 1
      ? await NetworkPolicy.find({
        companyId: company._id,
        'conditions.field': 'beaconing',
      }).select('name enabled scope conditions actions suppressionSeconds updatedAt').lean()
      : [];
    const scopedBeaconingPolicies = beaconingPolicies.filter(policy => {
      const assets = Array.isArray(policy.scope?.assetIds) ? policy.scope.assetIds.map(String) : [];
      return !assets.length || assets.includes(String(system._id));
    });
    const activeBeaconingPolicies = scopedBeaconingPolicies.filter(policy => policy.enabled !== false);
    const beaconBaselinePolicy = scopedBeaconingPolicies.find(policy => policy.name === BEACON_BASE_NAME);
    const beaconDetectionEnabled = system.networkMonitorEnabled !== false
      && (beaconBaselinePolicy ? beaconBaselinePolicy.enabled !== false : true);
    const dnsBeaconPolicy = scopedBeaconingPolicies.find(policy => policy.name === `${BEACON_POLICY_PREFIX}DNS Periodic Beacon`);
    const beaconEnabledRuleIds = BEACON_BUILTIN_RULES.filter(rule => {
      const stored = scopedBeaconingPolicies.find(policy => policy.name === `${BEACON_POLICY_PREFIX}${rule.name}`);
      return stored ? stored.enabled !== false : true;
    }).map(rule => rule.id);
    const beaconCustomRules = activeBeaconingPolicies
      .filter(policy => String(policy.name || '').startsWith(BEACON_CUSTOM_PREFIX))
      .map(policy => ({
        id: `custom:${policy._id}`,
        name: String(policy.name).slice(BEACON_CUSTOM_PREFIX.length),
        conditions: policy.conditions || [],
        severity: policy.actions?.severity || 'medium',
        risk_score: Number(policy.actions?.riskScore || 70),
      }));
    const beaconConditionValues = (field, operator) => activeBeaconingPolicies
      .flatMap(policy => policy.conditions || [])
      .filter(condition => condition.field === field && (!operator || condition.operator === operator))
      .map(condition => Number(condition.value)).filter(Number.isFinite);
    const beaconPolicyNumber = (field, operator, fallback, reducer = Math.min) => {
      const values = beaconConditionValues(field, operator);
      return values.length ? values.reduce((left, right) => reducer(left, right)) : fallback;
    };
    const beaconAlertThresholds = activeBeaconingPolicies
      .filter(policy => policy.actions?.createAlert !== false)
      .map(policy => Number(policy.actions?.riskScore)).filter(Number.isFinite);
    const beaconCooldowns = activeBeaconingPolicies
      .map(policy => Number(policy.suppressionSeconds)).filter(Number.isFinite);
    const dnsCachePoisonTargeted = !dnsCachePoisonConfiguration
      || dnsCachePoisonConfiguration.targetMode !== 'selected'
      || (dnsCachePoisonConfiguration.targetSystemIds || []).map(String).includes(String(system._id));
    const dnsCachePoisonOverrides = dnsCachePoisonConfiguration?.builtInRuleOverrides || {};
    const dnsCachePoisonTtlSettings = dnsCachePoisonOverrides['ttl-anomaly'] || {};
    const dnsSinkholeTargeted = !dnsSinkholeConfiguration
      || dnsSinkholeConfiguration.targetMode !== 'selected'
      || (dnsSinkholeConfiguration.targetSystemIds || []).map(String).includes(String(system._id));
    const dnsBuiltInRuleIds = Array.isArray(dnsSinkholeConfiguration?.builtInRuleIds)
      ? dnsSinkholeConfiguration.builtInRuleIds
      : ['company-blocklist-enforcement', 'dns-anomaly-detection', 'dns-beaconing-detection', 'sinkhole-policy-telemetry'];
    const strictDnsSinkholeDetection = dnsBuiltInRuleIds.includes('strict-dns-anomaly-detection');
    const dnsRuleOverrides = dnsSinkholeConfiguration?.builtInRuleOverrides || {};
    const dnsAnomalySettings = dnsRuleOverrides['dns-anomaly-detection'] || {};
    const strictDnsSettings = dnsRuleOverrides['strict-dns-anomaly-detection'] || {};
    const dnsBeaconSettings = dnsRuleOverrides['dns-beaconing-detection'] || {};
    const dnsTelemetrySettings = dnsRuleOverrides['sinkhole-policy-telemetry'] || {};
    const dnsBlocklistSettings = dnsRuleOverrides['company-blocklist-enforcement'] || {};
    const firewallRules = await Firewall.find({
      enabled: true,
      $and: [
        {
          $or: [
            { expiresAt: { $exists: false } },
            { expiresAt: null },
            { expiresAt: { $gt: now } },
          ]
        },
        {
          $or: [
            { level: 'global' },
            { companyId: company._id, level: 'company' },
            { companyId: company._id, level: 'department', departmentIds: system.departmentId },
            { companyId: company._id, level: 'system', systemId: system._id },
          ]
        },
      ],
    }).select('_id ruleName action direction conditions priority updatedAt').sort({ priority: 1 }).lean();
    const ipsWhitelist = await IpsWhitelist.find({ companyId: company._id })
      .select('value type updatedAt').sort({ value: 1 }).lean();
    const countryBlockPolicy = await CountryBlock.getPolicy(system);

    res.json({
      active: true,
      stop_monitoring: false,
      message: 'OK',
      system_id: system._id,
      plan_expires_at: expiresAt,
      update_available: updateAvailable,
      new_version: updateAvailable ? currentAgentVersion : null,
      heartbeat_interval_seconds: 60,
      // Server-authoritative protected policy. Agents must apply this snapshot
      // and must not accept local/company overrides for these core controls.
      security_policy: securityPolicySnapshot(system),
      commands: pendingCommands,
      country_blocks: countryBlockPolicy,
      firewall_rules: firewallRules.map(rule => ({
        ruleId: String(rule._id),
        ruleName: rule.ruleName,
        action: rule.action,
        direction: rule.direction,
        conditions: rule.conditions || {},
        priority: rule.priority,
        updatedAt: rule.updatedAt,
      })),
      // Android does not run the desktop Socket.IO policy listener, so every
      // signed heartbeat carries the authoritative allow-list snapshot.
      ips_whitelist: ipsWhitelist.map(entry => ({
        value: entry.value,
        type: entry.type,
        updatedAt: entry.updatedAt,
      })),
      is_isolated: system.isIsolated === true,
      config_update: {
        // Enrollment/network policy may change at runtime. agent_version is
        // deliberately package-owned so a heartbeat cannot fake an upgrade.
        server_proto: agentServerConnection().proto,
        server_url: agentServerConnection().url,
        server_ip: agentServerConnection().ip,
        server_port: agentServerConnection().port,
        require_tls: agentServerConnection().proto === 'https',
        mtls_required: process.env.AGENT_MTLS_REQUIRED === 'true',
        mtls_auto_enroll: process.env.AGENT_MTLS_ENABLED === 'true'
          || process.env.AGENT_MTLS_REQUIRED === 'true',
        fim_start_at: fimStartAt.toISOString ? fimStartAt.toISOString() : new Date(fimStartAt).toISOString(),
        file_monitor_start_at: fimStartAt.toISOString ? fimStartAt.toISOString() : new Date(fimStartAt).toISOString(),
        geo_enrichment_enabled: system.geoEnrichmentEnabled !== false,
        memory_scanner_enabled: system.memoryMonitorEnabled !== false,  // EDR cap #5 toggle
        memory_scanner_interval_seconds: Math.max(15, Number(process.env.MEMORY_SCANNER_INTERVAL_SECONDS) || 60),
        memory_overflow_enabled: system.memoryMonitorEnabled !== false && memoryRuleEnabled(...memoryRules.map(rule => rule.ruleId)),
        memory_collection_interval_seconds: Math.max(10, Number(process.env.MEMORY_COLLECTION_INTERVAL_SECONDS) || 30),
        memory_high_usage_threshold: Math.min(100, Math.max(1, Number(memoryRule('MEM-001')?.threshold ?? process.env.MEMORY_HIGH_USAGE_THRESHOLD) || 90)),
        memory_high_usage_duration_seconds: Math.max(30, Number(memoryRule('MEM-001')?.timeWindowSeconds ?? process.env.MEMORY_HIGH_USAGE_DURATION_SECONDS) || 300),
        memory_spike_percent_threshold: Math.max(1, Number(memoryRule('MEM-002')?.threshold ?? process.env.MEMORY_SPIKE_PERCENT_THRESHOLD) || 25),
        memory_spike_window_seconds: Math.max(10, Number(memoryRule('MEM-002')?.timeWindowSeconds ?? process.env.MEMORY_SPIKE_WINDOW_SECONDS) || 60),
        memory_leak_window_minutes: Math.max(5, Number(memoryRule('MEM-003')?.timeWindowSeconds ? memoryRule('MEM-003').timeWindowSeconds / 60 : process.env.MEMORY_LEAK_WINDOW_MINUTES) || 30),
        memory_leak_min_samples: Math.max(3, Number(memoryRule('MEM-003')?.minimumSampleCount ?? process.env.MEMORY_LEAK_MIN_SAMPLES) || 10),
        memory_leak_growth_percent: Math.max(1, Number(memoryRule('MEM-003')?.threshold ?? process.env.MEMORY_LEAK_GROWTH_PERCENT) || 30),
        memory_alert_cooldown_seconds: Math.max(30, Number(memoryRules.find(rule => rule.enabled)?.cooldownSeconds ?? process.env.MEMORY_ALERT_COOLDOWN_SECONDS) || 300),
        memory_rwx_detection_enabled: memoryRuleEnabled('MEM-006', 'MEM-007', 'MEM-013'),
        memory_process_access_detection_enabled: memoryRuleEnabled('MEM-008', 'MEM-009', 'MEM-010', 'MEM-012'),
        memory_crash_correlation_enabled: memoryRuleEnabled('MEM-005', 'MEM-014'),
        memory_detection_rules: memoryRules.map(rule => ({
          id: String(rule._id), rule_id: rule.ruleId, name: rule.name,
          enabled: rule.enabled !== false, threshold: rule.threshold,
          time_window_seconds: rule.timeWindowSeconds,
          minimum_sample_count: rule.minimumSampleCount,
          cooldown_seconds: rule.cooldownSeconds, severity: rule.severity,
          confidence: rule.confidence, risk_score: rule.riskScore,
          operating_systems: rule.operatingSystems || [],
          process_exclusions: rule.processExclusions || [], allowlist: rule.allowlist || [],
          maintenance_windows: (rule.maintenanceWindows || []).map(window => ({
            starts_at: window.startsAt, ends_at: window.endsAt, reason: window.reason,
          })),
          updated_at: rule.updatedAt,
        })),
        // Legacy agents recursively sweep broad user/system trees with YARA,
        // which can monopolize CPU. FIM, ransomware and EDR remain active.
        // v3.1.10 uses a bounded, incremental YARA scan over focused malware
        // drop locations, so signature detection can remain enabled safely.
        yara_enabled: true,
        // Process inventory is covered by several detectors; stagger the
        // expensive full-process walks instead of repeating them every 3–10s.
        lolbins_poll_interval: 30,
        process_poll_interval_seconds: 30,
        process_inventory_interval_seconds: 60,
        email_threat_monitoring_enabled: system.edrEnabled !== false,
        email_monitor_interval_seconds: Math.max(10, Number(process.env.EMAIL_MONITOR_INTERVAL_SECONDS) || 30),
        lateral_movement_monitoring_enabled: system.edrEnabled !== false,
        lateral_monitor_interval_seconds: Math.max(5, Number(process.env.LATERAL_MONITOR_INTERVAL_SECONDS) || 15),
        // Capability 12 is automatic. FIM, USB and network collectors supply
        // the event stream; this bounded process scan adds archive/export
        // context without enabling broad recursive content inspection.
        data_security_monitoring_enabled: system.edrEnabled !== false,
        data_security_monitor_interval_seconds: Math.min(3600, Math.max(10, Number(process.env.DATA_SECURITY_MONITOR_INTERVAL_SECONDS) || 20)),
        data_security_sensitive_paths: String(process.env.DATA_SECURITY_SENSITIVE_PATHS || '').split(',').map(value => value.trim()).filter(Boolean).slice(0, 24),
        ueba_monitoring_enabled: system.edrEnabled !== false,
        ueba_monitor_interval_seconds: Math.min(3600, Math.max(15, Number(process.env.UEBA_MONITOR_INTERVAL_SECONDS) || 60)),
        ueba_anomaly_multiplier: Math.min(10, Math.max(1.5, Number(process.env.UEBA_ANOMALY_MULTIPLIER) || 3)),
        input_behavior_monitoring_enabled: system.edrEnabled !== false,
        input_behavior_retry_seconds: Math.min(600, Math.max(30, Number(process.env.INPUT_BEHAVIOR_RETRY_SECONDS) || 60)),
        input_behavior_sample_interval_seconds: Math.min(10, Math.max(1, Number(process.env.INPUT_BEHAVIOR_SAMPLE_INTERVAL_SECONDS) || 1)),
        // Feed the live UEBA dashboard once per minute. The former one-hour
        // minimum (six hours by default) overrode the agent's 60-second
        // collector default, leaving current keyboard/mouse rates stale or at
        // zero for most of the day.
        input_behavior_report_interval_seconds: Math.min(3600, Math.max(60, Number(process.env.INPUT_BEHAVIOR_REPORT_INTERVAL_SECONDS) || 60)),
        input_behavior_anomaly_cooldown_seconds: Math.max(300, Number(process.env.INPUT_BEHAVIOR_ANOMALY_COOLDOWN_SECONDS) || 1800),
        input_keyboard_rate_threshold: Math.max(30, Number(process.env.INPUT_KEYBOARD_RATE_THRESHOLD) || 240),
        input_mouse_rate_threshold: Math.max(100, Number(process.env.INPUT_MOUSE_RATE_THRESHOLD) || 2500),
        // Capability 13 is automatic whenever EDR is enabled. Keeping these
        // controls server-owned prevents a stale dashboard policy from
        // silently disabling credential or lock-screen telemetry.
        credential_security_monitoring_enabled: system.edrEnabled !== false,
        credential_monitor_interval_seconds: Math.min(3600, Math.max(10, Number(process.env.CREDENTIAL_MONITOR_INTERVAL_SECONDS) || 20)),
        credential_monitor_processes_enabled: true,
        credential_monitor_stores_enabled: true,
        credential_monitor_lock_screen_enabled: true,
        credential_minimum_risk_score: 0,
        credential_enabled_rule_ids: CREDENTIAL_SECURITY_RULE_IDS,
        credential_rule_overrides: {},
        credential_policy_version: 1,
        // Capability 8 is an automatic EDR control. Collection is bounded to
        // native persistence locations and requires no dashboard-side policy.
        persistence_monitoring_enabled: system.edrEnabled !== false,
        process_asset_inventory_interval_seconds: Math.min(3600, Math.max(60, Number(process.env.PERSISTENCE_MONITOR_INTERVAL_SECONDS) || 300)),
        registry_monitor_enabled: system.edrEnabled !== false,
        registry_monitor_interval_seconds: Math.min(3600, Math.max(15, Number(process.env.REGISTRY_MONITOR_INTERVAL_SECONDS) || 60)),
        registry_monitor_paths: configuredMonitorPaths.filter(target => /^(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\/i.test(target)),
        configuration_monitor_paths: configuredMonitorPaths.filter(target => target.startsWith('/')),
        registry_policy_version: registryConfigurationControls.reduce((latest, control) => Math.max(latest, control.updatedAt ? new Date(control.updatedAt).getTime() : 0), 0),
        script_monitoring_enabled: !scriptMonitoringRules.length || activeScriptMonitoringRules.length > 0,
        script_hashing_enabled: true,
        script_hash_max_bytes: 16 * 1024 * 1024,
        script_risk_threshold: activeScriptMonitoringRules.length ? Math.min(...activeScriptMonitoringRules.map(rule => Number(rule.riskThreshold ?? 30))) : 30,
        script_alert_cooldown_seconds: activeScriptMonitoringRules.length ? Math.min(...activeScriptMonitoringRules.map(rule => Number(rule.alertCooldownSeconds ?? 900))) : 900,
        script_detect_encoded_commands: !activeScriptMonitoringRules.length || activeScriptMonitoringRules.some(rule => rule.detectEncodedCommands !== false),
        script_detect_obfuscation: !activeScriptMonitoringRules.length || activeScriptMonitoringRules.some(rule => rule.detectObfuscation !== false),
        script_detect_download_execution: !activeScriptMonitoringRules.length || activeScriptMonitoringRules.some(rule => rule.detectDownloadExecution !== false),
        script_detect_persistence: !activeScriptMonitoringRules.length || activeScriptMonitoringRules.some(rule => rule.detectPersistence !== false),
        script_detect_external_connections: !activeScriptMonitoringRules.length || activeScriptMonitoringRules.some(rule => rule.detectExternalConnections !== false),
        script_trusted_paths: [...new Set(activeScriptMonitoringRules.flatMap(rule => rule.trustedPaths || []))],
        script_trusted_hashes: [...new Set(activeScriptMonitoringRules.flatMap(rule => rule.trustedHashes || []))],
        script_trusted_publishers: [...new Set(activeScriptMonitoringRules.flatMap(rule => rule.trustedPublishers || []))],
        script_monitoring_rules: activeScriptMonitoringRules.map(rule => ({
          id: String(rule._id), name: rule.name, priority: rule.priority,
          interpreters: rule.interpreters || [], risk_threshold: rule.riskThreshold,
          alert_cooldown_seconds: rule.alertCooldownSeconds,
          detect_encoded_commands: rule.detectEncodedCommands !== false,
          detect_obfuscation: rule.detectObfuscation !== false,
          detect_download_execution: rule.detectDownloadExecution !== false,
          detect_persistence: rule.detectPersistence !== false,
          detect_external_connections: rule.detectExternalConnections !== false,
          risk_weights: rule.riskWeights || {}, updated_at: rule.updatedAt,
        })),
        ransomware_enabled: ransomwareConfiguration?.enabled !== false,
        ransomware_window_secs: Number(ransomwareConfiguration?.windowSeconds || 30),
        mass_mod_threshold: Number(ransomwareConfiguration?.massModificationThreshold || 50),
        mass_del_threshold: Number(ransomwareConfiguration?.massDeletionThreshold || 30),
        entropy_threshold: Number(ransomwareConfiguration?.entropyThreshold ?? 7),
        entropy_file_trigger: Number(ransomwareConfiguration?.entropyFileTrigger || 10),
        ransomware_alert_cooldown_seconds: Number(ransomwareConfiguration?.alertCooldownSeconds || 120),
        ransomware_extensions: ransomwareConfiguration?.customExtensions || [],
        ransomware_protected_dirs: ransomwareConfiguration?.protectedDirectories || [],
        ransomware_rule_overrides: ransomwareConfiguration?.builtInRuleOverrides || {},
        ransomware_policy_version: Number(ransomwareConfiguration?.version || 0),
        hash_monitoring_enabled: hashSignaturePolicy?.enabled !== false,
        hash_sha256_enabled: hashSignaturePolicy?.sha256Enabled !== false,
        hash_sha1_enabled: hashSignaturePolicy?.sha1Enabled !== false,
        hash_md5_enabled: hashSignaturePolicy?.md5Enabled === true,
        hash_signature_validation_enabled: hashSignaturePolicy?.signatureValidationEnabled !== false,
        hash_threat_intel_enabled: hashSignaturePolicy?.threatIntelEnabled !== false,
        hash_baseline_monitoring_enabled: hashSignaturePolicy?.baselineMonitoringEnabled !== false,
        hash_unsigned_alert_enabled: hashSignaturePolicy?.unsignedFileAlertEnabled !== false,
        hash_critical_file_monitoring_enabled: hashSignaturePolicy?.criticalFileMonitoringEnabled !== false,
        hash_risk_threshold: Math.min(100, Math.max(0, Number(hashSignaturePolicy?.riskThreshold ?? 30))),
        hash_policy_version: hashSignaturePolicy?.updatedAt
          ? new Date(hashSignaturePolicy.updatedAt).getTime()
          : 0,
        // Routine Zeek conn/dns/ssl rows can reach thousands per minute and
        // starve the security queue. Keep actionable notice/weird and all
        // Suricata alert/anomaly events, but summarize routine flow telemetry.
        send_ids_routine_telemetry: false,
        ids_detection_window_seconds: 60,
        ids_alert_cooldown_seconds: 900,
        ids_sensor_dedupe_seconds: 900,
        ids_port_scan_threshold: 15,
        ids_brute_force_threshold: 10,
        // Port inventory remains enabled, but the platform never closes a
        // listener merely because an attack targeted it. Prevention blocks
        // the malicious source/traffic while the legitimate service stays up.
        port_policy_enabled: true,
        port_policy_mode: 'audit',
        allowed_listening_ports: [],
        allowed_port_processes: {},
        port_policy_exempt_loopback: true,
        ips_auto_block: wafAttackProtectionPolicy?.enabled !== false
          && (wafAttackProtectionPolicy?.webAttackBlocking !== false
            || wafAttackProtectionPolicy?.networkAttackBlocking !== false),
        network_attack_block_enabled: wafAttackProtectionPolicy?.enabled !== false
          && wafAttackProtectionPolicy?.networkAttackBlocking !== false,
        cache_poison_enabled: dnsCachePoisonTargeted && dnsCachePoisonConfiguration?.enabled !== false,
        cache_poison_telemetry_enabled: dnsCachePoisonTargeted && dnsCachePoisonConfiguration?.telemetryEnabled !== false,
        cache_poison_watch_domains: dnsCachePoisonConfiguration?.watchDomains || [],
        cache_poison_trusted_resolvers: dnsCachePoisonConfiguration?.trustedResolvers || [],
        cache_poison_scan_interval_seconds: Number(dnsCachePoisonConfiguration?.scanIntervalSeconds || 300),
        cache_poison_min_safe_ttl: Number(dnsCachePoisonTtlSettings.minSafeTtl || dnsCachePoisonConfiguration?.minSafeTtl || 30),
        cache_poison_max_safe_ttl: Number(dnsCachePoisonTtlSettings.maxSafeTtl || dnsCachePoisonConfiguration?.maxSafeTtl || 86400),
        cache_poison_baseline_window_seconds: Number(dnsCachePoisonConfiguration?.baselineWindowSeconds || 3600),
        cache_poison_monitor_resolver_changes: dnsCachePoisonConfiguration?.monitorResolverChanges !== false,
        cache_poison_monitor_hosts_changes: dnsCachePoisonConfiguration?.monitorHostsChanges !== false,
        cache_poison_detect_private_answers: dnsCachePoisonConfiguration?.detectPrivateAnswers !== false,
        cache_poison_detect_ttl_anomaly: (dnsCachePoisonConfiguration?.builtInRuleIds || ['ttl-anomaly']).includes('ttl-anomaly'),
        cache_poison_builtin_rule_ids: dnsCachePoisonConfiguration?.builtInRuleIds || ['private-answer', 'ttl-anomaly', 'resolver-change', 'hosts-file-change'],
        cache_poison_rule_severities: {
          'private-answer': dnsCachePoisonOverrides['private-answer']?.severity || 'critical',
          'ttl-anomaly': dnsCachePoisonOverrides['ttl-anomaly']?.severity || 'high',
          'resolver-change': dnsCachePoisonOverrides['resolver-change']?.severity || 'high',
          'hosts-file-change': dnsCachePoisonOverrides['hosts-file-change']?.severity || 'high',
        },
        cache_poison_policy_version: Number(dnsCachePoisonConfiguration?.version || 0),
        dns_sinkhole_enabled: dnsSinkholeTargeted && dnsSinkholeConfiguration?.enabled !== false,
        dns_sinkhole_ip: dnsSinkholeConfiguration?.sinkholeIp || '0.0.0.0',
        dns_sinkhole_enforcement_mode: dnsSinkholeConfiguration?.enforcementMode || 'both',
        dns_sinkhole_telemetry_enabled: dnsSinkholeTargeted && dnsSinkholeConfiguration?.telemetryEnabled !== false,
        dns_sinkhole_report_interval_seconds: Number(dnsTelemetrySettings.reportIntervalSeconds || dnsSinkholeConfiguration?.reportIntervalSeconds || 300),
        dns_sinkhole_sync_blocklist: dnsSinkholeTargeted && dnsSinkholeConfiguration?.syncBlocklist !== false,
        dns_sinkhole_policy_version: Number(dnsSinkholeConfiguration?.version || 0),
        dns_sinkhole_builtin_rule_ids: dnsBuiltInRuleIds,
        dns_sinkhole_default_severity: dnsBlocklistSettings.defaultSeverity || 'high',
        dns_anomaly_detection_enabled: dnsBuiltInRuleIds.includes('dns-anomaly-detection') || strictDnsSinkholeDetection,
        dns_anomaly_threshold: Number(strictDnsSinkholeDetection ? (strictDnsSettings.alertThreshold || 30) : (dnsAnomalySettings.alertThreshold || 45)),
        dns_anomaly_cooldown_seconds: Number(strictDnsSinkholeDetection ? (strictDnsSettings.cooldownSeconds || 900) : (dnsAnomalySettings.cooldownSeconds || 1800)),
        // Beaconing Detection is an independent EDR capability. DNS Sinkhole
        // rules may tune it, but disabling sinkhole enforcement must not stop
        // passive DNS beacon analysis.
        dns_beacon_detection_enabled: beaconDetectionEnabled && (dnsBeaconPolicy ? dnsBeaconPolicy.enabled !== false : true),
        dns_beacon_alert_threshold: Number(dnsBeaconSettings.alertThreshold || (strictDnsSinkholeDetection ? 45 : 55)),
        beacon_detection_enabled: beaconDetectionEnabled,
        beacon_enabled_rule_ids: beaconEnabledRuleIds,
        beacon_custom_rules: beaconCustomRules,
        beacon_min_connections: Math.max(4, beaconPolicyNumber('connectionCount', 'gte', Number(dnsBeaconSettings.minimumConnections || 6))),
        beacon_min_interval_seconds: Math.max(1, beaconPolicyNumber('averageInterval', 'gte', Number(process.env.BEACON_MIN_INTERVAL_SECONDS || 5))),
        beacon_max_interval_seconds: Math.max(1, beaconPolicyNumber('averageInterval', 'lte', Number(process.env.BEACON_MAX_INTERVAL_SECONDS || 3600), Math.max)),
        beacon_min_observation_seconds: Math.max(0, beaconPolicyNumber('observationSeconds', 'gte', Number(process.env.BEACON_MIN_OBSERVATION_SECONDS || 60))),
        beacon_consistency_threshold: Math.min(100, Math.max(0, beaconPolicyNumber('intervalConsistency', 'gte', Number(dnsBeaconSettings.consistencyThreshold || 75)))),
        beacon_alert_threshold: Math.min(100, Math.max(25, Number(beaconBaselinePolicy?.actions?.riskScore ?? (beaconAlertThresholds.length ? Math.min(...beaconAlertThresholds) : Number(process.env.BEACON_ALERT_THRESHOLD || 70))))),
        beacon_alert_cooldown_seconds: Math.max(60, Number(beaconBaselinePolicy?.suppressionSeconds ?? (beaconCooldowns.length ? Math.min(...beaconCooldowns) : Number(dnsBeaconSettings.cooldownSeconds || 1800)))),
        beacon_policy_version: activeBeaconingPolicies.reduce((latest, policy) => Math.max(latest, new Date(policy.updatedAt || 0).getTime()), 0),
        ips_threat_threshold: wafAttackProtectionPolicy?.networkMinimumSeverity || 'high',
        waf_direct_block_enabled: wafAttackProtectionPolicy?.enabled !== false
          && wafAttackProtectionPolicy?.webAttackBlocking !== false,
        waf_direct_block_threshold: wafAttackProtectionPolicy?.webMinimumSeverity || 'medium',
        geo_fence_enabled: Boolean(locationPolicy) || system.geoFenceEnabled === true,
        geo_fence_latitude: locationPolicy?.conditions?.latitude ?? system.geoFenceLat ?? null,
        geo_fence_longitude: locationPolicy?.conditions?.longitude ?? system.geoFenceLon ?? null,
        geo_fence_radius_meters: Number(locationPolicy?.conditions?.radiusMeters || system.geoFenceRadiusMeters || 500),
        geo_fence_lock_on_violation: /block|isolate/i.test(locationPolicy?.action || '') || system.geoFenceLockOnViolation === true,
        geo_fence_action: locationPolicy?.conditions?.outsideAction || locationPolicy?.action || 'ALERT',
        gps_tracking_enabled: Boolean(gpsTrackingPolicy),
        geolocation_forensics_enabled: Boolean(gpsTrackingPolicy),
        gps_collection_interval_seconds: Math.min(3600, Math.max(30, Number(gpsTrackingPolicy?.conditions?.gpsIntervalSeconds || 300))),
        gps_required_accuracy_meters: Math.min(50, Math.max(5, Number(gpsTrackingPolicy?.conditions?.gpsAccuracyMeters || 50))),
        gps_policy_id: gpsTrackingPolicy ? String(gpsTrackingPolicy._id) : '',
        gps_policy_name: gpsTrackingPolicy?.name || '',
        gps_policy_category: gpsTrackingPolicy?.category || '',
        gps_policy_action: gpsTrackingPolicy?.action || '',
        gps_policy_version: Number(gpsTrackingPolicy?.version || 0),
        high_risk_geo_countries: highRiskCountries,
        allowed_geo_countries: allowedCountries,
        geo_max_travel_speed_kmh: Number(travelPolicy?.conditions?.maxSpeed || 0),
        geo_min_travel_distance_km: Number(travelPolicy?.conditions?.minDistanceKm || 500),
        geo_risk_score_cutoff: Number(travelPolicy?.conditions?.riskCutoff || 0),
        geolocation_policies: geolocationPolicies.map(policy => ({
          id: String(policy._id), name: policy.name, category: policy.category,
          severity: policy.severity, action: policy.action, priority: policy.priority,
          conditions: policy.conditions || {}, version: policy.version, updated_at: policy.updatedAt,
        })),
        time_anomaly_enabled: timeAnomalyPolicy ? timeAnomalyPolicy.enabled !== false : true,
        working_hours_start: Number(timeAnomalyPolicy?.workingHoursStart ?? 8),
        working_hours_end: Number(timeAnomalyPolicy?.workingHoursEnd ?? 20),
        time_anomaly_weekends: (timeAnomalyPolicy?.weekendDays || [5, 6]).length > 0,
        time_anomaly_weekend_days: timeAnomalyPolicy?.weekendDays || [5, 6],
        time_anomaly_holidays: timeAnomalyPolicy?.holidays || [],
        time_anomaly_timezone: timeAnomalyPolicy?.timezone || 'endpoint-local',
        time_auth_failure_window_seconds: Number(timeAnomalyPolicy?.authFailureWindowSeconds ?? 300),
        time_auth_failure_threshold: Number(timeAnomalyPolicy?.authFailureThreshold ?? 5),
        auth_password_spray_window_seconds: Math.max(30, Number(process.env.AUTH_PASSWORD_SPRAY_WINDOW_SECONDS) || Number(timeAnomalyPolicy?.authFailureWindowSeconds ?? 300)),
        auth_password_spray_user_threshold: Math.max(3, Number(process.env.AUTH_PASSWORD_SPRAY_USER_THRESHOLD) || 5),
        time_anomaly_risk_threshold: Number(timeAnomalyPolicy?.anomalyRiskThreshold ?? 45),
        time_anomaly_cooldown_seconds: Number(timeAnomalyPolicy?.alertCooldownSeconds ?? 3600),
        time_baseline_minimum_samples: Number(timeAnomalyPolicy?.baselineMinimumSamples ?? 20),
        time_anomaly_exceptions: (timeAnomalyPolicy?.exceptions || []).map(exception => ({
          type: exception.type,
          value: exception.value,
          reason: exception.reason,
          expires_at: exception.expiresAt || null,
        })),
        time_anomaly_bypass_active: Boolean(activeTimeAnomalyException),
        time_anomaly_bypass_until: activeTimeAnomalyException?.expiresAt || null,
        time_anomaly_bypass_reason: activeTimeAnomalyException?.reason || '',
        time_anomaly_bypass_id: activeTimeAnomalyException?._id ? String(activeTimeAnomalyException._id) : '',
        time_anomaly_policy_version: Math.max(
          timeAnomalyPolicy?.updatedAt ? new Date(timeAnomalyPolicy.updatedAt).getTime() : 0,
          activeTimeAnomalyException?.updatedAt ? new Date(activeTimeAnomalyException.updatedAt).getTime() : 0,
        ),
        usb_policies: usbPolicies.map(policy => ({
          id: String(policy._id), name: policy.name, description: policy.description,
          rule_type: policy.ruleType, action: policy.action, values: policy.values || [],
          max_bytes: Number(policy.maxBytes || 0), updated_at: policy.updatedAt,
        })),
        usb_policy_version: usbPolicies.reduce((latest, policy) => Math.max(
          latest,
          policy.updatedAt ? new Date(policy.updatedAt).getTime() : 0,
        ), 0),
      },
    });
  } catch (err) {
    console.error('[agent/heartbeat]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/agent/system/:id/offline — signed agent uninstall callback ────────
router.post('/system/:id/offline', async (req, res) => {
  try {
    const auth = await verifySignedAgentRequest(req, { agentKey: req.body.agent_key });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message });
    if (String(auth.system._id) !== String(req.params.id)) {
      return res.status(403).json({ message: 'Agent identity does not match system' });
    }
    const system = await System.findByIdAndUpdate(
      req.params.id,
      {
        status: 'disconnected',
        isActive: true,
        agentVersion: null,
        installDate: null,
        fimStartAt: null,
        lastSeen: new Date(),
      },
      { new: true }
    );

    if (!system) {
      return res.status(404).json({ message: 'System not found' });
    }

    res.json({ message: 'System marked offline', system: system.name });
  } catch (err) {
    console.error('[agent/offline]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/agent/version — lightweight version check (no JWT needed) ──────
router.get('/version', (req, res) => {
  res.json({
    version: AGENT_VERSION,
    versions: { desktop: AGENT_VERSION, android: ANDROID_AGENT_VERSION },
    updatedAt: new Date().toISOString(),
  });
});

// The public half of the local test signing identity. Windows test machines
// import this certificate into LocalMachine\Root and TrustedPublisher. Never
// expose the PFX, its password, or the private key. Production uses a publicly
// trusted code-signing certificate and therefore does not serve this endpoint.
router.get('/windows-signing-certificate', (req, res) => {
  if (String(process.env.WINDOWS_CODE_SIGN_MODE || '').toLowerCase() !== 'local-test') {
    return res.status(404).json({ message: 'Not found' });
  }
  const certificatePath = String(process.env.WINDOWS_CODE_SIGN_PUBLIC_CERT || '').trim();
  if (!certificatePath || !fs.existsSync(certificatePath)) {
    return res.status(503).json({ message: 'Local Windows signing certificate is unavailable' });
  }
  const certificate = fs.readFileSync(certificatePath);
  setAgentPackageIntegrityHeaders(res, certificate);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/pkix-cert');
  res.setHeader('Content-Disposition', 'attachment; filename="AJNAT-Local-Test-Publisher.cer"');
  return res.send(certificate);
});

// Authenticated, uncompressed dependency feed used when an older Windows
// endpoint has AJNAT installed but was never enrolled in Velociraptor.
router.get('/self-update/dependency/velociraptor/windows', async (req, res) => {
  try {
    const agentKey = req.query.agent_key || req.query.agentKey || req.headers['x-agent-key'] || '';
    const secret = req.headers['x-integration-secret'];
    const hasIntegrationSecret = secret && secret === process.env.INTEGRATION_SECRET;
    const auth = await verifySignedAgentRequest(req, { agentKey });
    if (!auth.ok && !hasIntegrationSecret) {
      return res.status(auth.status || 401).json({ message: auth.message || 'Unauthorized' });
    }
    const system = auth.ok
      ? auth.system
      : await System.findOne({ agentKey }).select('_id agentKey').lean();
    if (!system) return res.status(404).json({ message: 'Unknown agent key' });
    const { getWindowsVelociraptorBundle } = require('../services/packageBuilder.service');
    const bundle = getWindowsVelociraptorBundle();
    if (!bundle) return res.status(503).json({ message: 'Windows Velociraptor enrollment bundle is unavailable' });
    const dependency = fs.readFileSync(bundle.path);
    setAgentPackageIntegrityHeaders(res, dependency);
    res.setHeader('Content-Type', bundle.extension === 'msi' ? 'application/x-msi' : 'application/vnd.microsoft.portable-executable');
    res.setHeader('Content-Disposition', `attachment; filename="velociraptor_client_repacked.${bundle.extension}"`);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    return res.send(dependency);
  } catch (err) {
    console.error('[agent/velociraptor-dependency]', err.message);
    if (!res.headersSent) return res.status(500).json({ message: err.message });
  }
});

// ── GET /api/agent/self-update/package/:type — agent-authenticated OTA download ──
// The running agent pulls its own fresh package here (no dashboard JWT). Authenticated
// by signed agent request OR x-integration-secret, exactly like /heartbeat.
router.get('/self-update/package/:type', async (req, res) => {
  const { type } = req.params;
  const map = {
    deb: ['deb', 'linux.deb'],
    rpm: ['rpm', 'linux.rpm'],
    exe: ['exe', 'windows-exe.exe'],
    msi: ['msi', 'windows-msi.msi'],
    pkg: ['macpkg', 'macos.pkg'],
    macpkg: ['macpkg', 'macos.pkg'],
    dmg: ['dmg', 'macos.dmg'],
    apk: ['apk', 'android.apk'],
    solaris: ['solaris', 'solaris-zfs.sh'],
  };
  if (!map[type]) return res.status(400).json({ message: 'Invalid type. Use: deb, rpm, exe, msi, pkg, macpkg, dmg, apk, solaris' });
  const [buildFn, ext] = map[type];
  await sendAgentSelfUpdatePackage(req, res, buildFn, ext);
});

// ── All routes below require JWT ──────────────────────────────────────────────
router.use(authenticate);

// version endpoint moved above authenticate middleware

// ── Helper: build config JSON for a system ────────────────────────────────────
function buildConfig(system, company) {
  const { proto, ip, port, url } = agentServerConnection();
  const packageProfile = resolvePackageForSystem(system, 'auto');
  const windowsTarget = packageProfile.platform === 'windows';
  const macTarget = packageProfile.platform === 'macos';

  // IPS Webhook Server v3.0 settings
  const ipsWebhookUrl = process.env.IPS_WEBHOOK_URL || 'http://localhost:5050';
  const ipsWebhookSecret = process.env.IPS_WEBHOOK_SECRET || '';
  const velociraptorClientId = system.velociraptorClientId || '';
  const quarantineExcludePaths = String(
    process.env.AGENT_QUARANTINE_EXCLUDE_PATHS ||
    process.env.SOC_AGENT_QUARANTINE_EXCLUDE ||
    '/home/chaudahry/Desktop/soc4'
  ).split(path.delimiter).map(p => p.trim()).filter(Boolean);

  return {
    company_id: company._id.toString(),
    company_name: company.name,
    department_id: system.departmentId?._id?.toString() || '',
    department_name: system.departmentId?.name || '',
    system_id: system._id.toString(),
    system_name: system.name,
    hostname: system.hostname || system.name || '',
    velociraptor_client_id: velociraptorClientId,
    velociraptor_client_id_status: velociraptorClientId ? 'configured' : 'pending',
    velociraptor_client_id_note: velociraptorClientId
      ? 'Use this C.xxxx id for targeted Velociraptor hunts.'
      : 'Pending: install/enroll Velociraptor client, then set VELOCIRAPTOR_CLIENT_ID or send it in agent heartbeat.',
    agent_type: system.agentType || 'system',
    expected_device_role: system.agentType || 'system',
    agent_profile: `${system.agentType || 'system'}-${packageProfile.platform}`,
    target_platform: packageProfile.platform,
    preferred_package_type: packageProfile.type,
    agent_key: system.agentKey,
    server_proto: proto,
    server_url: url,
    server_ip: ip,
    server_port: port,
    require_tls: proto === 'https',
    mtls_required: process.env.AGENT_MTLS_REQUIRED === 'true',
    mtls_auto_enroll: process.env.AGENT_MTLS_ENABLED === 'true' || process.env.AGENT_MTLS_REQUIRED === 'true',
    // Per-agent encrypted transport + HMAC replaces the legacy fleet-wide
    // integration secret. Never embed that global credential in installers.
    integration_secret: '',
    agent_version: currentAgentVersionFor(system),

    heartbeat_interval_seconds: 60,
    scan_interval_seconds: 300,
    log_scan_interval_seconds: 30,

    // ── Security module flags (ALL ENABLED BY DEFAULT) ──────────────────
    edr_enabled: true,
    ids_enabled: true,
    ips_enabled: true,
    network_ids_sensors_enabled: true,
    packet_ids_mode: windowsTarget
      ? 'suricata-windivert-inline'
      : macTarget ? 'suricata-passive' : 'suricata-nfqueue-inline',
    ips_enforcement_mode: windowsTarget
      ? 'suricata-inline-windivert+defender-firewall'
      : macTarget ? 'suricata-detect+pf-source-block' : 'suricata-inline-nfqueue+native-firewall',
    // The Windows installer flips this only after verifying a running
    // WinDivert-capable Suricata service, so failed installs are not reported
    // as inline enforcement.
    inline_packet_verdict: false,
    send_ids_routine_telemetry: false,
    ids_detection_window_seconds: 60,
    ids_alert_cooldown_seconds: 900,
    ids_sensor_dedupe_seconds: 900,
    ids_port_scan_threshold: 15,
    ids_brute_force_threshold: 10,
    suricata_eve_path: windowsTarget
      ? 'C:\\ProgramData\\AJNAT\\suricata\\log\\eve.json'
      : macTarget ? '/opt/homebrew/var/log/suricata/eve.json' : '/var/log/suricata/eve.json',
    zeek_log_paths: windowsTarget ? [] : [
      '/opt/zeek/logs/current/notice.log',
      '/opt/zeek/logs/current/conn.log',
      '/var/log/zeek/current/notice.log',
      '/var/log/zeek/current/conn.log',
    ],
    ids_sensor_mirror_to_agent_alerts: false,
    firewall_enabled: true,
    yara_enabled: true,
    waf_enabled: true,
    waf_proxy_enabled: false,
    waf_intercept: false,
    waf_monitor_ports: [],
    waf_direct_block_enabled: true,
    waf_direct_block_threshold: 'medium',
    network_monitor_enabled: true,
    usb_monitor_enabled: true,
    fim_start_at: system.fimStartAt ? system.fimStartAt.toISOString() : '',
    file_monitor_start_at: system.fimStartAt ? system.fimStartAt.toISOString() : '',
    process_monitor_enabled: true,
    advanced_process_monitor_enabled: true,
    registry_monitor_enabled: true,
    registry_monitor_interval_seconds: Math.min(3600, Math.max(15, Number(process.env.REGISTRY_MONITOR_INTERVAL_SECONDS) || 60)),
    registry_monitor_paths: String(process.env.REGISTRY_MONITOR_PATHS || '').split(',').map(value => value.trim()).filter(Boolean).slice(0, 64),
    configuration_monitor_paths: String(process.env.CONFIGURATION_MONITOR_PATHS || '').split(',').map(value => value.trim()).filter(Boolean).slice(0, 64),
    kernel_monitoring_enabled: true,
    kernel_monitor_interval_seconds: 300,
    kernel_vulnerable_driver_hashes: [],
    service_monitoring_enabled: true,
    patch_inventory_enabled: true,
    patch_inventory_interval_seconds: 21600,
    workload_activity_monitor_enabled: true,
    container_monitor_enabled: true,
    process_poll_interval_seconds: 10,
    process_inventory_interval_seconds: 10,
    process_lifecycle_alerts_enabled: true,
    process_cpu_threshold_percent: 90,
    process_memory_threshold_percent: 15,
    unauthorized_process_paths: [],
    response_enabled: true,
    geo_enrichment_enabled: system.geoEnrichmentEnabled !== false,
    geo_fence_enabled: system.geoFenceEnabled === true,
    geo_fence_latitude: system.geoFenceLat ?? null,
    geo_fence_longitude: system.geoFenceLon ?? null,
    geo_fence_radius_meters: Number(system.geoFenceRadiusMeters || 200),
    geo_fence_lock_on_violation: system.geoFenceLockOnViolation === true,
    gps_tracking_enabled: false,
    geolocation_forensics_enabled: false,
    gps_collection_interval_seconds: 300,
    gps_required_accuracy_meters: 50,
    geo_fence_allowed_location: {
      latitude: system.geoFenceLat ?? null,
      longitude: system.geoFenceLon ?? null,
      radius_meters: Number(system.geoFenceRadiusMeters || 200),
      enabled: system.geoFenceEnabled === true,
      lock_on_violation: system.geoFenceLockOnViolation === true,
    },
    geo_fence_note: system.geoFenceEnabled === true
      ? `Allowed within ${Number(system.geoFenceRadiusMeters || 200)} meters of configured latitude/longitude.`
      : 'Geo-fence location not enabled for this system.',
    high_risk_geo_countries: ['RU', 'CN', 'KP', 'IR', 'SY', 'BY', 'CU'],
    allowed_geo_countries: [],
    quarantine_exclude_paths: quarantineExcludePaths,

    virustotal_api_key: process.env.VIRUSTOTAL_API_KEY || '',

    // ── IPS Webhook Server v3.0 ─────────────────────────────────────────
    ips_webhook_url: ipsWebhookUrl,
    ips_webhook_secret: ipsWebhookSecret,
    ips_auto_block: true,
    ips_block_ttl_hours: 24,
    ips_threat_threshold: 'medium',
    ids_ips_capabilities_enabled: true,
    ids_ips_capability_groups: CAPABILITY_GROUPS,
    ids_ips_attack_types: listAttackTypes(),
    ids_packet_sensor_required: [
      'SYN Scan', 'FIN Scan', 'NULL Scan', 'XMAS Scan', 'ACK Scan',
      'ICMP Flood', 'Network Packets',
    ],

    plan_limit: getAgentLicenseLimit(company),
    generated_at: new Date().toISOString(),
  };
}

function persistVelociraptorClientId(system, config) {
  if (!system?.velociraptorClientId && config?.velociraptor_client_id) {
    System.findByIdAndUpdate(system._id, { velociraptorClientId: config.velociraptor_client_id }).catch(() => { });
  }
}

// Export for use in prebuild service
module.exports.buildConfig = buildConfig;

// ── Helper: recursively add a directory to an AdmZip instance ─────────────────
function addDirToZip(zip, dirPath, zipPrefix, excludeNames = []) {
  if (!fs.existsSync(dirPath)) return;
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    if (excludeNames.some(ex => entry.name.startsWith(ex))) continue;
    if (entry.name.startsWith('.')) continue;
    const fullPath = path.join(dirPath, entry.name);
    const zipPath = zipPrefix ? `${zipPrefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      addDirToZip(zip, fullPath, zipPath, excludeNames);
    } else {
      try {
        zip.addLocalFile(fullPath, path.dirname(zipPath));
      } catch (_) { }
    }
  }
}

// ── GET /api/agent/config/:systemId — download single config JSON ─────────────
router.get('/config/:systemId', requireCompanyAdmin, async (req, res) => {
  try {
    const [system, company] = await Promise.all([
      System.findOne({ _id: req.params.systemId, companyId: req.user.companyId })
        .populate('departmentId', 'name'),
      Company.findById(req.user.companyId),
    ]);
    if (!system) return res.status(404).json({ message: 'System not found' });
    if (!company) return res.status(404).json({ message: 'Company not found' });

    const resolvedSystem = await refreshSystemVelociraptorClientId(system);
    const config = buildConfig(resolvedSystem, company);
    persistVelociraptorClientId(system, config);
    const filename = [
      company.name.replace(/[^a-zA-Z0-9]/g, '_'),
      system.name.replace(/[^a-zA-Z0-9]/g, '_'),
      'config.json',
    ].join('_');

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.json(config);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── GET /api/agent/bundle/:systemId — download full agent ZIP + pre-filled config ──
router.get('/bundle/:systemId', requireCompanyAdmin, async (req, res) => {
  try {
    const [system, company] = await Promise.all([
      System.findOne({ _id: req.params.systemId, companyId: req.user.companyId })
        .populate('departmentId', 'name'),
      Company.findById(req.user.companyId),
    ]);
    if (!system) return res.status(404).json({ message: 'System not found' });
    if (!company) return res.status(404).json({ message: 'Company not found' });

    const entitlement = await getSubscriptionEntitlement(company);
    if (!entitlement.licenseActive) {
      return res.status(403).json({ message: 'Your subscription is not active. Please complete payment to download agents.' });
    }

    let AdmZip;
    try { AdmZip = require('adm-zip'); }
    catch (_) {
      return res.status(500).json({ message: 'adm-zip not installed. Run: cd backend && npm install adm-zip' });
    }

    const resolvedSystem = await refreshSystemVelociraptorClientId(system);
    const config = buildConfig(resolvedSystem, company);
    persistVelociraptorClientId(system, config);
    const configJson = JSON.stringify(config, null, 2);
    const zip = new AdmZip();
    const dirName = 'soc-agent';

    const os = require('os');
    // Search for agent source directory — most specific / latest first
    const searchPaths = [
      // ── Repo source first: downloads must include latest edited agent files ──
      path.resolve(__dirname, '..', '..', 'soc-agent'),
      path.resolve(process.cwd(), 'soc-agent'),
      path.resolve(process.cwd(), '..', 'soc-agent'),
      path.resolve(__dirname, '..', '..', '..', 'soc-agent'),
      // ── Custom agent folder (soc-Anant) ─────────────────────────────────
      path.resolve(os.homedir(), 'Downloads', 'soc4', 'soc-Anant'),     // ← custom deployment
      path.resolve(os.homedir(), 'Downloads', 'soc-Anant'),
      path.resolve(__dirname, '..', '..', 'soc-Anant'),                  // backend/soc-Anant
      path.resolve(__dirname, '..', '..', '..', 'soc-Anant'),            // sibling of backend/
      path.resolve(process.cwd(), 'soc-Anant'),
      path.resolve(process.cwd(), '..', 'soc-Anant'),
      '/opt/soc-Anant',
      // ── Standard agent folders ───────────────────────────────────────────
      path.resolve(os.homedir(), 'Downloads', 'soc4', 'fixed-agent-v2'), // dev latest
      path.resolve(__dirname, '..', '..', '..', 'fixed-agent-v2'),
      path.resolve(process.cwd(), '..', 'fixed-agent-v2'),
      path.resolve(os.homedir(), 'Downloads', 'soc-agent'),
      path.resolve(os.homedir(), 'Downloads', 'fixed-agent-v2'),
      '/opt/soc-agent',
    ];
    const agentDir = searchPaths.find(p => {
      try { return fs.existsSync(p) && fs.statSync(p).isDirectory(); } catch { return false; }
    });

    // Collect files with correct zip paths (no leading slash, no //)
    const SKIP_DIRS = new Set(['__pycache__', '.git', '.DS_Store', 'node_modules', 'venv', '.venv']);
    const SKIP_FILES = new Set(['agent_state.json', 'vt_cache.json', '.probe', 'integrity_manifest.json']);

    function collectFiles(dir, prefix) {
      prefix = prefix || '';
      if (!dir || !fs.existsSync(dir)) return [];
      const results = [];
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        if (SKIP_FILES.has(entry.name) || entry.name.endsWith('.pyc')) continue;
        const full = path.join(dir, entry.name);
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
          results.push(...collectFiles(full, rel));
        } else {
          try { results.push({ full, rel, buf: fs.readFileSync(full) }); } catch { /* skip */ }
        }
      }
      return results;
    }

    let integrityManifest = null;
    if (agentDir) {
      const files = collectFiles(agentDir);
      for (const f of files) {
        if (f.rel === 'config/company_config.json') continue; // inject our own below
        const relNorm = f.rel.replace(/\\/g, '/');
        const dirPart = relNorm.includes('/') ? relNorm.substring(0, relNorm.lastIndexOf('/')) : '';
        const fileName = path.basename(relNorm);
        const entry = dirPart ? `${dirName}/${dirPart}/${fileName}` : `${dirName}/${fileName}`;
        zip.addFile(entry, f.buf);
      }
      const manifestFiles = {};
      for (const file of files.filter(file => file.rel.endsWith('.py')).sort((a, b) => a.rel.localeCompare(b.rel))) {
        manifestFiles[file.rel.replace(/\\/g, '/')] = crypto.createHash('sha256').update(file.buf).digest('hex');
      }
      const aggregate = crypto.createHash('sha256');
      for (const relative of Object.keys(manifestFiles).sort()) {
        aggregate.update(`${relative}\0${manifestFiles[relative]}\n`, 'utf8');
      }
      integrityManifest = { version: 1, algorithm: 'sha256', files: manifestFiles, fleetSha256: aggregate.digest('hex') };
      zip.addFile(`${dirName}/integrity_manifest.json`, Buffer.from(`${JSON.stringify(integrityManifest, null, 2)}\n`, 'utf8'));
    } else {
      // No source found — add a helpful README
      const noSrc = `SOC Agent — Config-Only Bundle
================================
Company : ${company.name}
System  : ${system.name}

The agent source was not found on the server.
Your pre-filled config is included in this zip at:
  soc-agent/config/company_config.json

To install:
1. Download the full agent from your SOC dashboard
2. Copy config/company_config.json into the agent folder
3. Follow the install steps on the Download Agent page
`;
      zip.addFile(`${dirName}/README.txt`, Buffer.from(noSrc, 'utf8'));
    }

    // Always inject the pre-filled config
    zip.addFile(`${dirName}/config/company_config.json`, Buffer.from(configJson, 'utf8'));
    addVelociraptorBundle(zip, dirName);

    // Always add a clean INSTALL.txt
    const serverUrl = config.server_url;
    const installTxt = `SOC Agent — Quick Install Guide
================================
Company : ${company.name}
System  : ${system.name}
Server  : ${serverUrl}
================================

LINUX (Debian/Ubuntu)
  cd soc-agent
  sudo bash install.sh
  systemctl status soc-agent
  journalctl -u soc-agent -f

LINUX (RHEL/CentOS/Fedora)
  cd soc-agent
  sudo bash install.sh
  systemctl status soc-agent

WINDOWS (PowerShell as Administrator)
  cd soc-agent
  Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
  .\\install.ps1

MACOS
  cd soc-agent
  sudo bash install.sh
  launchctl list | grep soc.agent

TEST (all platforms — no root needed)
  python3 soc-agent/agent.py test

VERIFY
  System "${system.name}" shows "Active" in dashboard within 60 seconds.
`;
    zip.addFile(`${dirName}/INSTALL.txt`, Buffer.from(installTxt, 'utf8'));

    const zipName = `soc-agent_${system.name.replace(/[^a-zA-Z0-9]/g, '_')}.zip`;
    const buf = zip.toBuffer();
    const artifactSha256 = setAgentPackageIntegrityHeaders(res, buf);

    // Fire-and-forget: increment download count
    const integritySet = integrityManifest?.fleetSha256
      ? { [system.agentExpectedIntegrityHash ? 'agentPendingIntegrityHash' : 'agentExpectedIntegrityHash']: integrityManifest.fleetSha256 }
      : {};
    System.findByIdAndUpdate(system._id, {
      $inc: { downloadCount: 1 },
      ...(Object.keys(integritySet).length ? { $set: integritySet } : {}),
    }).catch(() => { });

    // Log download to the Download table
    Download.create({
      companyId: req.user.companyId,
      systemId: system._id,
      downloadType: 'bundle',
      downloadCategory: 'universal',
      fileName: zipName,
      artifactSha256,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent'),
      userId: req.user._id,
    }).catch(() => { });

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);
    res.setHeader('Content-Length', buf.length);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.send(buf);

  } catch (err) {
    console.error('[agent/bundle]', err.message);
    res.status(500).json({ message: 'Bundle creation failed: ' + err.message });
  }
});


// ── GET /api/agent/configs — all configs as JSON array ────────────────────────
router.get('/configs', requireCompanyAdmin, async (req, res) => {
  try {
    const [systems, company] = await Promise.all([
      System.find({ companyId: req.user.companyId, isActive: true })
        .populate('departmentId', 'name'),
      Company.findById(req.user.companyId),
    ]);
    res.json(systems.map(s => buildConfig(s, company)));
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── GET /api/agent/stats — plan usage + per-OS counts ─────────────────────────
router.get('/stats', requireManager, async (req, res) => {
  try {
    if (req.user.role === 'department_admin' && !req.user.departmentId) {
      return res.status(403).json({ message: 'Department assignment required' });
    }
    const departmentScoped = req.user.role === 'department_admin';
    const systemFilter = {
      companyId: req.user.companyId,
      isActive: true,
      ...(departmentScoped ? { departmentId: req.user.departmentId } : {}),
    };
    const [systems, company, department] = await Promise.all([
      System.find(systemFilter)
        .populate('departmentId', 'name'),
      Company.findById(req.user.companyId),
      departmentScoped
        ? Department.findOne({ _id: req.user.departmentId, companyId: req.user.companyId }).lean()
        : Promise.resolve(null),
    ]);
    if (departmentScoped && !department) return res.status(404).json({ message: 'Department not found' });
    const downloadScope = {
      companyId: req.user.companyId,
      ...(departmentScoped ? { systemId: { $in: systems.map(system => system._id) } } : {}),
    };

    // Count TOTAL DOWNLOADS from Download collection (actual click counts)
    // This is independent of systems - if you delete a system, download count stays
    const legacyUncategorized = {
      $or: [
        { downloadCategory: { $exists: false } },
        { downloadCategory: null },
        { downloadCategory: '' },
      ],
    };
    const [
      totalDownloads,
      systemDownloads,
      serverDownloads,
      androidDownloads,
      universalDownloads,
    ] = await Promise.all([
      Download.countDocuments({ ...downloadScope, downloadType: { $not: /^update-/ } }),
      Download.countDocuments({
        ...downloadScope,
        $or: [
          { downloadCategory: 'system' },
          { ...legacyUncategorized, downloadType: { $in: ['deb', 'rpm', 'exe', 'msi', 'pkg', 'macpkg', 'dmg'] } },
        ],
      }),
      Download.countDocuments({
        ...downloadScope,
        $or: [
          { downloadCategory: 'server' },
          { ...legacyUncategorized, downloadType: 'solaris' },
        ],
      }),
      Download.countDocuments({
        ...downloadScope,
        $or: [
          { downloadCategory: 'android' },
          { ...legacyUncategorized, downloadType: 'apk' },
        ],
      }),
      Download.countDocuments({
        ...downloadScope,
        $or: [
          { downloadCategory: 'universal' },
          { ...legacyUncategorized, downloadType: { $in: ['zip', 'bundle'] } },
        ],
      }),
    ]);

    const byOs = { linux: 0, windows: 0, macos: 0, android: 0, solaris: 0, unknown: 0 };
    const byDevice = { systems: 0, servers: 0, android: 0, universal: 0 };

    for (const s of systems) {
      const agentType = s.agentType || 'system';
      const o = `${s.os || ''} ${s.osType || ''}`.toLowerCase();
      const n = `${s.name || ''} ${s.hostname || ''}`.toLowerCase();
      const platformText = `${o} ${n}`;
      const isMobile = /android|iphone|ipad|ios|ipados/.test(platformText);
      const isServer = agentType === 'server' || /server|solaris|sunos/.test(platformText);

      if (agentType === 'phone' || isMobile) byDevice.android++;
      else if (isServer) byDevice.servers++;
      else byDevice.systems++;

      if (isMobile) byOs.android++;
      else if (o.includes('solaris') || o.includes('sunos')) byOs.solaris++;
      else if (o.includes('linux') || o.includes('ubuntu') || o.includes('centos') || o.includes('debian')) byOs.linux++;
      else if (o.includes('win')) byOs.windows++;
      else if (o.includes('darwin') || o.includes('mac')) byOs.macos++;
      else if (s.status === 'active') byOs.unknown++;
    }

    const downloadsByDevice = {
      systems: systemDownloads,
      servers: serverDownloads,
      android: androidDownloads,
      universal: universalDownloads,
    };

    const purchasedSystems = departmentScoped ? Number(department?.assignedSystemCount || 0) : Number(company?.plan?.systemCount || 0);
    const purchasedServers = departmentScoped ? Number(department?.assignedServerCount || 0) : Number(company?.plan?.serverCount || 0);
    const purchasedPhones = departmentScoped ? Number(department?.assignedPhoneCount || 0) : Number(company?.plan?.phoneCount || 0);
    const limit = departmentScoped
      ? purchasedSystems + purchasedServers + purchasedPhones
      : getAgentLicenseLimit(company);
    const used = systems.filter(s => s.agentVersion).length;  // Only count systems where agent is actually installed

    res.json({
      plan: {
        type: departmentScoped ? 'department allocation' : (company.plan?.type || 'none'),
        isActive: company.plan?.isActive || false,
        limit,
        systemCount: purchasedSystems,
        serverCount: purchasedServers,
        phoneCount: purchasedPhones,
        used,
        remaining: Math.max(0, limit - used),
        pct: limit > 0 ? Math.round((used / limit) * 100) : 0,
      },
      totalDownloads,
      currentVersion: AGENT_VERSION,   // latest agent version available on server
      currentVersions: { desktop: AGENT_VERSION, android: ANDROID_AGENT_VERSION },
      byOs,
      byDevice,
      downloadsByDevice,
      byStatus: {
        active: systems.filter(s => s.status === 'active').length,
        pending: systems.filter(s => s.status === 'pending').length,
        disconnected: systems.filter(s => s.status === 'disconnected').length,
        inactive: systems.filter(s => s.status === 'inactive').length,
      },
      systems: systems.map(s => {
        const updateStatus = effectiveUpdateStatus(s);
        const currentVersion = currentAgentVersionFor(s);
        return {
          _id: s._id,
          name: s.name,
          status: s.status,
          agentType: s.agentType || 'system',
          os: s.os,
          osType: s.osType,
          hostname: s.hostname,
          ip: s.ip,
          macAddress: s.macAddress || null,
          lastSeen: s.lastSeen,
          installDate: s.installDate,
          fimStartAt: s.fimStartAt || null,
          downloadCount: s.downloadCount || 0,
          agentVersion: s.agentVersion || null,
          currentVersion,
          updateAvailable: s.agentVersion
            ? compareVersions(s.agentVersion, currentVersion) < 0
            : false,
          updateStatus,
          updateError: updateStatus === 'failed' ? (s.updateError || 'Update timed out') : null,
          updateTargetVersion: s.updateTargetVersion || null,
          updateRequestedAt: s.updateRequestedAt || null,
          departmentId: s.departmentId,
          edrEnabled: s.edrEnabled || false,
          idsEnabled: s.idsEnabled || false,
          ipsEnabled: s.ipsEnabled || false,
          firewallEnabled: s.firewallEnabled || false,
          yaraEnabled: s.yaraEnabled || false,
        };
      }),
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});


// ── Package downloads: .deb / .rpm / .exe / .pkg ──────────────────────────────
// Agent packages include system-specific secrets (company_id/system_id/agent_key).
// Build them at download time and never store completed packages on the server.

const PKG_TYPE_NAMES = { deb: 'deb', rpm: 'rpm', exe: 'exe', msi: 'msi', pkg: 'pkg', macpkg: 'macpkg', dmg: 'dmg', apk: 'apk', solaris: 'solaris' };

function packageContentType(buildFn) {
  return buildFn === 'apk' ? 'application/vnd.android.package-archive'
    : buildFn === 'exe' ? 'application/vnd.microsoft.portable-executable'
      : buildFn === 'msi' ? 'application/x-msi'
        : buildFn === 'macpkg' ? 'application/vnd.apple.installer+xml'
          : buildFn === 'dmg' ? 'application/x-apple-diskimage'
            : buildFn === 'deb' ? 'application/vnd.debian.binary-package'
              : buildFn === 'rpm' ? 'application/x-rpm'
                : buildFn === 'solaris' ? 'text/x-shellscript'
                  : 'application/zip';
}

async function persistPackagedIntegrityHash(system, isAgentUpdate) {
  const { getAgentIntegrityManifest } = require('../services/packageBuilder.service');
  const manifest = getAgentIntegrityManifest();
  const fleetSha256 = cleanSha256(manifest?.fleetSha256);
  if (!fleetSha256 || !Object.keys(manifest?.files || {}).length) return manifest;
  const field = isAgentUpdate && system.agentExpectedIntegrityHash
    ? 'agentPendingIntegrityHash'
    : 'agentExpectedIntegrityHash';
  await System.findByIdAndUpdate(system._id, { $set: { [field]: fleetSha256 } });
  system[field] = fleetSha256;
  return manifest;
}

// Build the requested package for an already-resolved system/company and stream it.
// Shared by the JWT dashboard route (buildPackageResponse) and the agent-authenticated
// self-update route (sendAgentSelfUpdatePackage). Returns the download filename.
async function sendBuiltPackage(res, { system, company, buildFn, ext, isAgentUpdate, updateRequestId = '' }) {
  const { buildDeb, buildRpm, buildExe, buildMsi, buildPkg, buildMacPkg, buildDmg, buildApk, buildSolaris } = require('../services/packageBuilder.service');
  const builders = { deb: buildDeb, rpm: buildRpm, exe: buildExe, msi: buildMsi, pkg: buildPkg, macpkg: buildMacPkg, dmg: buildDmg, apk: buildApk, solaris: buildSolaris };
  const resolvedSystem = await refreshSystemVelociraptorClientId(system);
  const packageProfile = resolvePackageForSystem(resolvedSystem, buildFn);
  buildFn = packageProfile.buildFn;
  ext = packageProfile.ext;
  const agentConfig = buildConfig(resolvedSystem, company);
  agentConfig.installer_type = buildFn === 'msi' ? 'msi' : (buildFn === 'exe' ? 'exe' : buildFn);
  if (updateRequestId) agentConfig.update_request_id = updateRequestId;
  persistVelociraptorClientId(system, agentConfig);
  // An already-updated endpoint may still predate automatic forensic
  // enrollment. Include the Windows client bundle only for endpoints that the
  // server has not seen in Velociraptor; normal OTA packages stay small.
  const includeVelociraptor = ['exe', 'msi'].includes(buildFn)
    && !resolvedSystem.velociraptorClientId;
  const buf = await builders[buildFn](resolvedSystem, company, agentConfig, {
    isAgentUpdate,
    includeVelociraptor,
  });
  if (buildFn !== 'apk') await persistPackagedIntegrityHash(system, isAgentUpdate);

  const filename = `soc-agent_${isAgentUpdate ? 'update_' : ''}${system.name}_${company.name}_${ext}`
    .replace(/[^a-zA-Z0-9_.-]/g, '_');
  const artifactSha256 = setAgentPackageIntegrityHeaders(res, buf);

  res.setHeader('Content-Type', packageContentType(buildFn));
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Length', buf.length);
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('X-AJNAT-Build-Mode', 'just-in-time');
  res.setHeader('X-AJNAT-Package-Type', buildFn);
  res.send(buf);
  return { filename, artifactSha256, buildFn };
}

async function buildPackageResponse(req, res, buildFn, ext) {
  try {
    const requestedUpdate = req.query.update === '1' || req.query.update === 'true';
    const [system, company] = await Promise.all([
      System.findOne({ _id: req.params.systemId, companyId: req.user.companyId })
        .populate('departmentId', 'name'),
      Company.findById(req.user.companyId),
    ]);
    if (!system) return res.status(404).json({ message: 'System not found' });
    if (!company) return res.status(404).json({ message: 'Company not found' });
    const packageProfile = resolvePackageForSystem(system, buildFn);
    buildFn = packageProfile.buildFn;
    ext = packageProfile.ext;
    // A repeat manual download is an update/recovery package. It is allowed
    // before the first heartbeat too, so a failed installation can be retried.
    const isAgentUpdate = requestedUpdate || (Number(system.downloadCount) || 0) > 0;

    // ── Enforce download limit ────────────────────────────────────────────
    if (!isAgentUpdate) {
      const limitCheck = await checkDownloadLimit(req.user.companyId);
      if (!limitCheck.allowed) {
        return res.status(403).json({
          message: limitCheck.reason,
          current: limitCheck.current,
          limit: limitCheck.limit,
          type: 'limit_exceeded',
        });
      }
    }

    const { filename, artifactSha256 } = await sendBuiltPackage(res, { system, company, buildFn, ext, isAgentUpdate });

    // Only the first package consumes capacity; update/recovery downloads do not.
    if (!isAgentUpdate) {
      System.findByIdAndUpdate(system._id, { $inc: { downloadCount: 1 } }).catch(() => { });
    }
    Download.create({
      companyId: req.user.companyId,
      systemId: system._id,
      downloadType: isAgentUpdate ? `update-${PKG_TYPE_NAMES[buildFn] || 'zip'}` : (PKG_TYPE_NAMES[buildFn] || 'zip'),
      downloadCategory: classifyDownloadCategory(buildFn, system.agentType),
      fileName: filename,
      artifactSha256,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent'),
      userId: req.user._id,
    }).catch(() => { });
  } catch (err) {
    console.error(`[agent/${buildFn}]`, err.message);
    res.status(err.status || 500).json({ message: err.message, ...(err.code && { code: err.code }) });
  }
}

// Agent-authenticated self-update download. Resolves the system from the agent's own
// credentials (signed request or integration secret) rather than a dashboard JWT, so a
// running agent can pull its own fresh package. Always update mode → does not consume the
// one-time download quota. Shares sendBuiltPackage with the dashboard route.
async function sendAgentSelfUpdatePackage(req, res, buildFn, ext) {
  try {
    const agentKey = req.query.agent_key || req.query.agentKey || req.headers['x-agent-key'] || '';
    const secret = req.headers['x-integration-secret'];
    const hasIntegrationSecret = secret && secret === process.env.INTEGRATION_SECRET;
    const auth = await verifySignedAgentRequest(req, { agentKey });
    if (!auth.ok && !hasIntegrationSecret) {
      return res.status(auth.status || 401).json({ message: auth.message || 'Unauthorized' });
    }

    const systemFilter = auth.ok ? { _id: auth.system._id } : { agentKey };
    const system = await System.findOne(systemFilter).populate('departmentId', 'name');
    if (!system) return res.status(404).json({ message: 'Unknown agent key' });
    const company = await Company.findById(system.companyId);
    if (!company) return res.status(404).json({ message: 'Company not found' });
    if (!system.agentVersion) {
      return res.status(400).json({ message: 'Agent is not installed on this system yet.', code: 'AGENT_NOT_INSTALLED' });
    }

    const requestedUpdateId = String(req.query.update_request_id || '').trim();
    const pendingUpdates = (system.pendingCommands || []).filter(item => item?.command === 'update');
    const pendingUpdate = requestedUpdateId
      ? pendingUpdates.find(item => String(item.id) === requestedUpdateId)
      : pendingUpdates[pendingUpdates.length - 1];
    if (requestedUpdateId && !pendingUpdate) {
      return res.status(409).json({ message: 'Update request is no longer pending', code: 'UPDATE_REQUEST_NOT_PENDING' });
    }

    // Mark that the agent has started fetching its update package.
    System.findByIdAndUpdate(system._id, { $set: { updateStatus: 'downloading' } }).catch(() => { });

    const { filename, artifactSha256 } = await sendBuiltPackage(res, {
      system,
      company,
      buildFn,
      ext,
      isAgentUpdate: true,
      updateRequestId: pendingUpdate ? String(pendingUpdate.id) : '',
    });

    Download.create({
      companyId: system.companyId,
      systemId: system._id,
      downloadType: `update-${PKG_TYPE_NAMES[buildFn] || 'zip'}`,
      downloadCategory: classifyDownloadCategory(buildFn, req.query.category),
      fileName: filename,
      artifactSha256,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent'),
    }).catch(() => { });
  } catch (err) {
    console.error(`[agent/self-update/${buildFn}]`, err.message);
    if (!res.headersSent) res.status(500).json({ message: err.message });
  }
}

// GET /api/agent/package/:systemId/:type  — type: deb | rpm | exe | msi | pkg | macpkg | dmg | apk | solaris
router.get('/package/:systemId/:type', requireCompanyAdmin, async (req, res) => {
  const { type } = req.params;
  const map = {
    deb: ['deb', 'linux.deb'],
    rpm: ['rpm', 'linux.rpm'],
    exe: ['exe', 'windows-exe.exe'],
    msi: ['msi', 'windows-msi.msi'],
    pkg: ['macpkg', 'macos.pkg'],
    macpkg: ['macpkg', 'macos.pkg'],
    dmg: ['dmg', 'macos.dmg'],
    apk: ['apk', 'android.apk'],
    solaris: ['solaris', 'solaris-zfs.sh'],
    auto: ['auto', 'auto'],
  };
  if (!map[type]) return res.status(400).json({ message: 'Invalid type. Use: auto, deb, rpm, exe, msi, pkg, macpkg, dmg, apk, solaris' });
  const [buildFn, ext] = map[type];
  await buildPackageResponse(req, res, buildFn, ext);
});

// Map a system's platform to the package type its self-updater should pull.
function packageTypeForSystem(system) {
  return defaultPackageForSystem(system);
}

// ── POST /api/agent/:id/update — trigger a remote OTA update for one system ─────
// Queues an `update` command the agent picks up on its next heartbeat, and records
// update tracking state the dashboard polls via /agent/stats.
router.post('/:id/update', requireCompanyAdmin, async (req, res) => {
  try {
    const system = await System.findOne({ _id: req.params.id, companyId: req.user.companyId });
    if (!system) return res.status(404).json({ message: 'System not found' });
    if (!system.agentVersion) {
      return res.status(400).json({ message: 'Agent is not installed on this system yet.', code: 'AGENT_NOT_INSTALLED' });
    }
    const targetVersion = currentAgentVersionFor(system);
    if (compareVersions(system.agentVersion, targetVersion) >= 0) {
      if (system.updateStatus !== 'success' || system.updateError) {
        await System.updateOne({ _id: system._id }, {
          $set: { updateStatus: 'success', updateFinishedAt: new Date(), updateError: null },
        });
      }
      return res.status(400).json({
        message: `Agent v${system.agentVersion} is already current (server release v${targetVersion}).`,
        code: 'AGENT_ALREADY_UPDATED',
      });
    }

    const now = new Date();
    let type = packageTypeForSystem(system);
    if (type === 'exe') {
      // Preserve the registered Windows package owner. An EXE installation
      // must receive EXE updates; changing it to MSI creates a second installer
      // registration and cannot bypass WDAC publisher policy.
      const lastWindowsPackage = await Download.findOne({
        systemId: system._id,
        // Update downloads are attempts, not proof of how the registered agent
        // is owned. Using the latest update-* row can permanently switch an
        // EXE installation to MSI after one fallback and leave it stuck.
        downloadType: { $in: ['exe', 'msi'] },
      }).sort({ createdAt: -1 }).select('downloadType').lean();
      type = String(lastWindowsPackage?.downloadType || type);
    }
    const command = {
      id: `${Date.now()}-manual-update`,
      command: 'update',
      systemId: String(system._id),
      fromVersion: system.agentVersion,
      targetVersion,
      type,
      createdAt: now,
    };

    // A manual retry supersedes any stale update command; response/IPS
    // commands remain untouched.
    await System.updateOne(
      { _id: system._id },
      { $pull: { pendingCommands: { command: 'update' } } },
    );
    await System.findByIdAndUpdate(system._id, {
      $push: { pendingCommands: command },
      $set: {
        updateStatus: 'pending',
        updateRequestedAt: now,
        updateTargetVersion: targetVersion,
        updateError: null,
        updateFinishedAt: null,
      },
    });

    // Real-time hint for agents connected via socket.io (heartbeat is the reliable path).
    const io = req.app?.get?.('io') || global.io;
    if (io) io.to(`system_${system._id}`).emit('agent:command', command);
    io?.to(`company:${system.companyId}`).emit('agent:update-status', {
      systemId: String(system._id),
      agentVersion: system.agentVersion,
      currentVersion: targetVersion,
      updateStatus: 'pending',
      updateError: null,
      updateTargetVersion: targetVersion,
      lastSeen: system.lastSeen || null,
    });

    res.json({
      message: 'Agent update command sent',
      updateStatus: 'pending',
      targetVersion,
      currentVersion: system.agentVersion,
      type: type || 'auto',
    });
  } catch (err) {
    console.error('[agent/update]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// Immediately deny the pinned certificate while preserving its fingerprint
// for audit and preventing silent re-enrollment with a stolen agent key.
router.post('/:id/certificate/revoke', requireCompanyAdmin, async (req, res) => {
  try {
    const system = await System.findOne({ _id: req.params.id, companyId: req.user.companyId })
      .select('+agentCertificateFingerprint256 +agentCertificateSerial +agentCertificateRevokedAt');
    if (!system) return res.status(404).json({ message: 'System not found' });
    if (!system.agentCertificateFingerprint256) {
      return res.status(400).json({ message: 'This AJNAT agent has no enrolled client certificate' });
    }
    system.agentCertificateRevokedAt = new Date();
    await system.save();
    return res.json({
      revoked: true,
      systemId: String(system._id),
      revokedAt: system.agentCertificateRevokedAt,
    });
  } catch (err) {
    console.error('[agent/certificate/revoke]', err.message);
    return res.status(500).json({ message: 'Unable to revoke AJNAT client certificate' });
  }
});

// ── GET /api/agent/download/:type — LICENSE-BASED download (no systemId) ──────
// Uses the first available system in the company for config.
// Enforces license limit: blocks download if all licenses are used.
router.get('/download/:type', requireCompanyAdmin, async (req, res) => {
  const { type } = req.params;
  const builderMap = {
    deb: 'deb',
    rpm: 'rpm',
    exe: 'exe',
    msi: 'msi',
    pkg: 'macpkg',
    macpkg: 'macpkg',
    dmg: 'dmg',
    zip: 'universal',
    apk: 'apk',
    solaris: 'solaris',
  };
  if (!builderMap[type]) return res.status(400).json({ message: 'Invalid type. Use: deb, rpm, exe, msi, pkg, macpkg, dmg, zip, apk, solaris' });

  try {
    const company = await Company.findById(req.user.companyId);
    if (!company) return res.status(404).json({ message: 'Company not found' });

    // License enforcement
    const entitlement = await getSubscriptionEntitlement(company);
    if (!entitlement.licenseActive) {
      return res.status(403).json({ message: 'Your subscription is not active. Please complete payment to download agents.' });
    }

    // ── Enforce download limit ────────────────────────────────────────────
    const limitCheck = await checkDownloadLimit(req.user.companyId);
    if (!limitCheck.allowed) {
      return res.status(403).json({
        message: limitCheck.reason,
        current: limitCheck.current,
        limit: limitCheck.limit,
        type: 'limit_exceeded',
      });
    }
    // Package credentials are endpoint-specific. Never bind a macOS download
    // to the first Windows/Linux system in the company (or vice versa).
    const candidateSystems = await System.find({ companyId: req.user.companyId, isActive: true })
      .populate('departmentId', 'name')
      .sort({ createdAt: 1 });
    const buildFn = builderMap[type];
    let system = buildFn === 'universal'
      ? candidateSystems[0]
      : candidateSystems.find(candidate => {
        try {
          resolvePackageForSystem(candidate, buildFn);
          return true;
        } catch {
          return false;
        }
      });

    // Require at least one system to be added before downloading
    if (!system) {
      return res.status(400).json({
        message: candidateSystems.length
          ? `Please create a ${buildFn === 'macpkg' || buildFn === 'dmg' ? 'macOS' : buildFn} agent before downloading this package.`
          : 'Please add a system first before downloading the agent.',
        code: candidateSystems.length ? 'NO_COMPATIBLE_SYSTEM' : 'NO_SYSTEM_FOUND',
        redirect: '/systems'
      });
    }

    const { buildDeb, buildRpm, buildUniversal, buildExe, buildMsi, buildPkg, buildMacPkg, buildDmg, buildApk, buildSolaris } = require('../services/packageBuilder.service');
    const builders = { deb: buildDeb, rpm: buildRpm, universal: buildUniversal, exe: buildExe, msi: buildMsi, pkg: buildPkg, macpkg: buildMacPkg, dmg: buildDmg, apk: buildApk, solaris: buildSolaris };
    const resolvedSystem = await refreshSystemVelociraptorClientId(system);
    const agentConfig = buildConfig(resolvedSystem, company);
    persistVelociraptorClientId(system, agentConfig);
    const buf = await builders[buildFn](system, company, agentConfig);
    if (buildFn !== 'apk') {
      await persistPackagedIntegrityHash(system, (Number(system.downloadCount) || 0) > 0);
    }

    const suffix = { deb: 'linux', rpm: 'linux', exe: 'windows-exe', msi: 'windows-msi', pkg: 'macos', macpkg: 'macos', dmg: 'macos', zip: 'universal', apk: 'android', solaris: 'solaris-zfs' }[type];
    const ext = type === 'apk' ? 'apk' : type === 'exe' ? 'exe' : type === 'msi' ? 'msi' : (type === 'pkg' || type === 'macpkg') ? 'pkg' : type === 'dmg' ? 'dmg' : type === 'deb' ? 'deb' : type === 'rpm' ? 'rpm' : type === 'solaris' ? 'sh' : 'zip';
    const filename = `soc-agent_${company.name}_${suffix}.${ext}`.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const artifactSha256 = setAgentPackageIntegrityHeaders(res, buf);

    res.setHeader('Content-Type', type === 'apk' ? 'application/vnd.android.package-archive' : type === 'exe' ? 'application/vnd.microsoft.portable-executable' : type === 'msi' ? 'application/x-msi' : (type === 'pkg' || type === 'macpkg') ? 'application/vnd.apple.installer+xml' : type === 'dmg' ? 'application/x-apple-diskimage' : type === 'deb' ? 'application/vnd.debian.binary-package' : type === 'rpm' ? 'application/x-rpm' : type === 'solaris' ? 'text/x-shellscript' : 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', buf.length);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.send(buf);

    // Track download
    if (system) {
      System.findByIdAndUpdate(system._id, { $inc: { downloadCount: 1 } }).catch(() => { });
    }
    Download.create({
      companyId: req.user.companyId,
      systemId: system?._id || null,
      downloadType: type,
      downloadCategory: classifyDownloadCategory(type, req.query.category),
      fileName: filename,
      artifactSha256,
      ipAddress: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent'),
      userId: req.user._id,
    }).catch(() => { });
  } catch (err) {
    console.error(`[agent/download/${type}]`, err.message);
    res.status(500).json({ message: err.message });
  }
});

// heartbeat endpoint moved above authenticate middleware to allow agent access

// ── GET /api/agent/subscription-check/:agentKey — public check ───────────────
router.get('/subscription-check/:agentKey', async (req, res) => {
  try {
    const secret = req.headers['x-integration-secret'];
    if (!secret || secret !== process.env.INTEGRATION_SECRET) {
      return res.status(401).json({ message: 'Unauthorized' });
    }

    const system = await System.findOne({ agentKey: req.params.agentKey })
      .populate('companyId', 'plan status partnerId')
      .lean();

    if (!system) return res.json({ active: false, reason: 'unknown_agent' });

    const company = system.companyId;
    const entitlement = await getSubscriptionEntitlement(company);
    const planActive = entitlement.licenseActive;
    const baseExpiresAt = company?.plan?.expiresAt ? new Date(company.plan.expiresAt) : null;
    const expiresAt = entitlement.baseActive
      ? baseExpiresAt
      : (entitlement.batchExpiresAt || baseExpiresAt);
    const expired = !planActive && Boolean(baseExpiresAt && new Date() > baseExpiresAt);

    res.json({
      active: planActive && company?.status === 'active',
      planActive,
      expired,
      expiresAt,
      entitlement,
      companyStatus: company?.status,
      partnerLicenseActive: true,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/agent/prebuild — Prepare package builders ─────────────────────
// Finished packages are not cached because company_config.json is injected at
// download time. This endpoint only refreshes/validates builder state.
router.post('/prebuild', requireCompanyAdmin, async (req, res) => {
  try {
    const { prebuildPackages } = require('../services/prebuild.service');

    const company = await Company.findById(req.user.companyId);
    if (!company) return res.status(404).json({ message: 'Company not found' });

    const result = await prebuildPackages(company);
    res.json({
      message: 'Agent package builders are ready. Company/system config will be added at download time.',
      status: 'ready',
      result,
    });
  } catch (err) {
    console.error(`[agent/prebuild]`, err.message);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
module.exports.buildConfig = buildConfig;
