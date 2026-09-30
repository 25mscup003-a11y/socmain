const router = require('express').Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const Company = require('../models/Company.model');
const User = require('../models/User.model');
const Tenant = require('../models/Tenant.model');
const Partner = require('../models/Partner.model');
const Referral = require('../models/Referral.model');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const Department = require('../models/Department.model');
const PaymentHistory = require('../models/PaymentHistory.model');
const LoginActivity = require('../models/LoginActivity.model');
const AgentSecurityAudit = require('../models/AgentSecurityAudit.model');
const PartnerNotification = require('../models/PartnerNotification.model');
const PartnerSupportTicket = require('../models/PartnerSupportTicket.model');
const { authenticate, requireSuperAdmin } = require('../middleware/auth.middleware');
const { normalizeSlug, buildRegistrationUrl } = require('../utils/tenant');
const { sendMail, partnerInvitationEmailHtml } = require('../utils/email');
const { agreementUpload } = require('../middleware/upload.middleware');
const { ensureDefaultSoarPlaybooks } = require('../services/defaultSoarPlaybooks.service');

router.use(authenticate, requireSuperAdmin);

function withTimeout(promise, fallback, ms = 10000) {
  return Promise.race([
    promise,
    new Promise(resolve => setTimeout(() => resolve(fallback), ms)),
  ]).catch(() => fallback);
}

function hasConfiguredEnv(...keys) {
  return keys.every((key) => {
    const value = String(process.env[key] || '').trim();
    if (!value) return false;
    return !/^(your[_-]|change[_-]?me|replace|placeholder|todo|xxx|example|<.*>)/i.test(value);
  });
}

const SECURITY_BOOLEAN_FIELDS = new Set([
  'selfProtection', 'tamperProtection', 'antiDebugging',
  'antiReverseEngineering', 'antiDumpProtection', 'integrityVerification',
  'secureCommunication', 'configurationEncryption', 'certificateValidation',
  'codeIntegrityMonitoring', 'lockdownMode', 'maintenanceMode',
]);

function securitySourceIp(req) {
  const value = String(req.ip || req.socket?.remoteAddress || 'unknown').trim();
  if (value === '::1') return '127.0.0.1';
  return value.replace(/^::ffff:/, '') || 'unknown';
}

function enabledSecurityFlag(value) {
  return value === true || value === 'true';
}

function certificatePosture(system, now = Date.now()) {
  const fingerprint256 = String(system.agentCertificateFingerprint256 || '').toLowerCase();
  const expiresAt = system.agentCertificateExpiresAt
    ? new Date(system.agentCertificateExpiresAt)
    : null;
  const revokedAt = system.agentCertificateRevokedAt
    ? new Date(system.agentCertificateRevokedAt)
    : null;
  const expired = Boolean(expiresAt && expiresAt.getTime() <= now);
  return {
    enrolled: Boolean(fingerprint256),
    fingerprint256,
    expiresAt,
    revokedAt,
    status: revokedAt ? 'revoked' : !fingerprint256 ? 'not_enrolled' : expired ? 'expired' : 'active',
  };
}

async function requireActiveSuperadminSession(req, res, next) {
  try {
    const userId = req.user?.id || req.user?._id;
    const user = userId
      ? await User.findOne({
        _id: userId, role: 'superadmin', isActive: true,
        $or: [{ accountStatus: 'active' }, { accountStatus: { $exists: false } }],
      })
        .select('_id name email role passwordChangedAt').lean()
      : null;
    if (!user) return res.status(401).json({ message: 'Superadmin session is no longer active' });
    if (user.passwordChangedAt && req.user.iat
      && user.passwordChangedAt.getTime() > Number(req.user.iat) * 1000) {
      return res.status(401).json({ message: 'Session expired after credential change' });
    }
    req.activeUser = user;
    next();
  } catch (err) {
    next(err);
  }
}

function serializeSecurityAgent(system, now = Date.now()) {
  const lastSeen = system.lastSeen ? new Date(system.lastSeen) : null;
  const ageMs = lastSeen ? now - lastSeen.getTime() : Infinity;
  const controls = system.securityControls || {};
  const enabled = [...SECURITY_BOOLEAN_FIELDS]
    .filter(key => key !== 'maintenanceMode')
    .filter(key => controls[key] !== false).length;
  const expected = SECURITY_BOOLEAN_FIELDS.size - 1;
  const online = ageMs <= 180000 && system.status === 'active' && system.isActive;
  const posturePenalty = {
    verified: 0, unknown: 25, missing: 50, error: 60, mismatch: 80,
  }[system.agentIntegrityStatus || 'unknown'];
  const controlScore = Math.round((enabled / expected) * 100);
  const integrityScore = Math.max(0, controlScore - posturePenalty - (online ? 0 : 10));
  const incidentActive = system.agentSecurityIncidentActive === true;
  const transportSecurity = system.agentTransportSecurity || {};
  const configurationEncrypted = Object.prototype.hasOwnProperty.call(
    transportSecurity, 'configuration_encrypted',
  ) ? enabledSecurityFlag(transportSecurity.configuration_encrypted) : null;
  return {
    id: system._id,
    agentId: system.agentId || String(system._id),
    name: system.hostname || system.name,
    company: system.companyId?.name || 'Unknown company',
    companyId: system.companyId?._id || system.companyId,
    tenantId: system.tenantId,
    os: system.os || system.osType || 'Unknown',
    ip: system.ip || '—',
    version: system.agentVersion || '—',
    status: !online ? 'offline' : incidentActive ? 'critical' : integrityScore === 100 ? 'protected' : 'warning',
    integrityScore,
    integrityStatus: system.agentIntegrityStatus || 'unknown',
    expectedIntegrityHash: system.agentExpectedIntegrityHash || '',
    pendingIntegrityHash: system.agentPendingIntegrityHash || '',
    reportedIntegrityHash: system.agentReportedIntegrityHash || '',
    integrityCheckedAt: system.agentIntegrityCheckedAt,
    findings: system.agentSecurityFindings || [],
    debuggerDetected: system.agentDebuggerDetected === true,
    analysisTools: system.agentAnalysisTools || [],
    lockdownActive: system.agentSecurityLockdown === true,
    incidentActive,
    securityLastEventAt: system.agentSecurityLastEventAt,
    transportSecurity,
    certificate: certificatePosture(system, now),
    configurationEncrypted,
    apiPayloadEncryption: String(transportSecurity.api_payload_encryption || ''),
    lastSeen,
    controls: {
      selfProtection: controls.selfProtection !== false,
      tamperProtection: controls.tamperProtection !== false,
      antiDebugging: controls.antiDebugging !== false,
      antiReverseEngineering: controls.antiReverseEngineering !== false,
      antiDumpProtection: controls.antiDumpProtection !== false,
      integrityVerification: controls.integrityVerification !== false,
      secureCommunication: controls.secureCommunication !== false,
      configurationEncryption: controls.configurationEncryption !== false,
      certificateValidation: controls.certificateValidation !== false,
      codeIntegrityMonitoring: controls.codeIntegrityMonitoring !== false,
      lockdownMode: controls.lockdownMode !== false,
      maintenanceMode: controls.maintenanceMode === true,
      protectionLevel: controls.protectionLevel || 'hardened',
      policyVersion: controls.policyVersion || 1,
    },
  };
}

// Actual heartbeat-backed security inventory. All endpoints in this module are
// already JWT + superadmin protected; sensitive operations also revalidate the
// live database session immediately before access.
router.get('/agent-security', requireActiveSuperadminSession, async (req, res) => {
  try {
    const auditPage = Math.max(1, Number.parseInt(req.query.auditPage, 10) || 1);
    const auditLimit = 5;
    const serverProtocol = String(process.env.SERVER_PROTO || 'http').toLowerCase();
    const tlsEnabled = process.env.TLS_ENABLED === 'true' || process.env.TRUSTED_TLS_PROXY === 'true';
    const mtlsRequired = process.env.AGENT_MTLS_REQUIRED === 'true'
      || process.env.AGENT_MTLS_AT_PROXY === 'true';
    const systems = await System.find({}).select(
      'name hostname agentId tenantId companyId os osType ip agentVersion lastSeen status isActive securityControls '
      + 'agentExpectedIntegrityHash agentPendingIntegrityHash agentReportedIntegrityHash agentIntegrityStatus '
      + 'agentIntegrityCheckedAt agentSecurityFindings agentDebuggerDetected agentAnalysisTools '
      + 'agentSecurityLockdown agentSecurityIncidentActive agentSecurityLastEventAt agentTransportSecurity '
      + '+agentCertificateFingerprint256 agentCertificateExpiresAt +agentCertificateRevokedAt'
    ).populate('companyId', 'name').sort({ lastSeen: -1 }).lean();
    const agents = systems.map(system => serializeSecurityAgent(system));
    const [audits, auditTotal] = await Promise.all([
      AgentSecurityAudit.find({}).sort({ createdAt: -1 })
        .skip((auditPage - 1) * auditLimit).limit(auditLimit).lean(),
      AgentSecurityAudit.countDocuments({}),
    ]);
    res.set('Cache-Control', 'no-store');
    res.json({
      agents,
      audits,
      auditPagination: {
        page: auditPage,
        limit: auditLimit,
        total: auditTotal,
        totalPages: Math.max(1, Math.ceil(auditTotal / auditLimit)),
      },
      requestSourceIp: securitySourceIp(req),
      serverSecurity: {
        protocol: serverProtocol,
        tlsEnabled,
        mtlsEnabled: process.env.AGENT_MTLS_ENABLED === 'true'
          || process.env.AGENT_MTLS_REQUIRED === 'true'
          || process.env.AGENT_MTLS_AT_PROXY === 'true',
        mtlsRequired,
        identityMode: serverProtocol === 'https' && tlsEnabled && mtlsRequired
          ? 'mtls'
          : 'aes256-hmac',
        apiPayloadEncryption: 'aes-256-gcm-v1',
        signedRequestsRequired: process.env.AGENT_REQUIRE_SIGNED !== 'false',
        minimumSecurityReportVersion: process.env.AGENT_VERSION || '0.1.10',
      },
      serverTime: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.patch('/agent-security/:systemId/controls', requireActiveSuperadminSession, async (req, res) => {
  try {
    const changes = req.body?.changes;
    if (!changes || typeof changes !== 'object' || Array.isArray(changes)) {
      return res.status(400).json({ message: 'A controls change object is required' });
    }
    const keys = Object.keys(changes);
    if (!keys.length || keys.some(key => !SECURITY_BOOLEAN_FIELDS.has(key))) {
      return res.status(400).json({ message: 'One or more security controls are not allowed' });
    }
    if (keys.some(key => typeof changes[key] !== 'boolean')) {
      return res.status(400).json({ message: 'Security control values must be boolean' });
    }
    const system = await System.findById(req.params.systemId);
    if (!system) return res.status(404).json({ message: 'Agent not found' });
    const previousValue = {};
    const set = {};
    for (const key of keys) {
      previousValue[key] = system.securityControls?.[key];
      set[`securityControls.${key}`] = changes[key];
    }
    set['securityControls.updatedAt'] = new Date();
    set['securityControls.updatedBy'] = req.activeUser._id;
    set['securityControls.policyVersion'] = Number(system.securityControls?.policyVersion || 1) + 1;
    set.pendingCommands = [
      ...(system.pendingCommands || []),
      { command: 'security-policy-sync', controls: changes, requestedAt: new Date() },
    ].slice(-50);
    const updated = await System.findByIdAndUpdate(system._id, { $set: set }, { new: true })
      .populate('companyId', 'name').lean();
    const audit = await AgentSecurityAudit.create({
      tenantId: system.tenantId, companyId: system.companyId, systemId: system._id,
      userId: req.activeUser._id, username: req.activeUser.email || req.activeUser.name,
      role: 'superadmin', action: 'SECURITY_CONTROLS_UPDATED',
      previousValue, newValue: changes, sourceIp: securitySourceIp(req),
      device: String(req.headers['user-agent'] || '').slice(0, 300), result: 'success',
    });
    const payload = { agent: serializeSecurityAgent(updated), audit };
    req.app.get('io')?.to('superadmin').emit('agent-security:update', payload);
    res.json(payload);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/agent-security/:systemId/action', requireActiveSuperadminSession, async (req, res) => {
  try {
    const action = String(req.body?.action || '');
    const certificateActions = new Set(['revokeCertificate', 'resetCertificateIdentity']);
    const commandTypes = {
      forceUpdate: 'update',
      forceRecovery: 'security-force-recovery',
      verifyIntegrity: 'verify-integrity',
      securityLockdown: 'security-lockdown',
      securityUnlock: 'security-unlock',
    };
    if (!commandTypes[action] && !certificateActions.has(action)) {
      return res.status(400).json({ message: 'Unsupported security action' });
    }
    const system = await System.findById(req.params.systemId)
      .select('+agentCertificateFingerprint256 +agentCertificateSerial +agentCertificateRevokedAt');
    if (!system) return res.status(404).json({ message: 'Agent not found' });

    if (certificateActions.has(action)) {
      if (action === 'revokeCertificate' && !system.agentCertificateFingerprint256) {
        return res.status(400).json({ message: 'This AJNAT agent has no enrolled client certificate' });
      }
      if (action === 'revokeCertificate' && system.agentCertificateRevokedAt) {
        return res.status(409).json({ message: 'This AJNAT client certificate is already revoked' });
      }
      if (action === 'resetCertificateIdentity'
          && system.agentCertificateFingerprint256
          && !system.agentCertificateRevokedAt
          && String(process.env.SERVER_PROTO || 'http').toLowerCase() === 'https'
          && (process.env.TLS_ENABLED === 'true' || process.env.TRUSTED_TLS_PROXY === 'true')
          && (process.env.AGENT_MTLS_REQUIRED === 'true' || process.env.AGENT_MTLS_AT_PROXY === 'true')) {
        return res.status(409).json({ message: 'Revoke the current certificate before resetting agent identity' });
      }

      const previousValue = {
        certificateStatus: certificatePosture(system).status,
        fingerprint256: system.agentCertificateFingerprint256,
        revokedAt: system.agentCertificateRevokedAt,
      };
      let message;
      let auditAction;
      let newValue;
      if (action === 'revokeCertificate') {
        system.agentCertificateRevokedAt = new Date();
        auditAction = 'CERTIFICATE_REVOKED';
        newValue = { revokedAt: system.agentCertificateRevokedAt };
        message = 'AJNAT client certificate revoked immediately';
      } else {
        system.agentKey = crypto.randomBytes(32).toString('hex');
        system.agentCertificateFingerprint256 = '';
        system.agentCertificateSerial = '';
        system.agentCertificateExpiresAt = null;
        system.agentCertificateRevokedAt = null;
        system.agentTransportSecurity = {};
        auditAction = 'CERTIFICATE_IDENTITY_RESET';
        newValue = { agentKeyRotated: true, freshPackageRequired: true };
        message = 'Agent identity reset; download and install a fresh AJNAT package';
      }
      await system.save();
      await system.populate('companyId', 'name');
      const audit = await AgentSecurityAudit.create({
        tenantId: system.tenantId, companyId: system.companyId?._id || system.companyId,
        systemId: system._id, userId: req.activeUser._id,
        username: req.activeUser.email || req.activeUser.name,
        role: 'superadmin', action: auditAction, previousValue, newValue,
        sourceIp: securitySourceIp(req),
        device: String(req.headers['user-agent'] || '').slice(0, 300), result: 'success',
      });
      const payload = { message, audit, agent: serializeSecurityAgent(system.toObject()) };
      req.app.get('io')?.to('superadmin').emit('agent-security:update', payload);
      return res.json(payload);
    }

    const audit = await AgentSecurityAudit.create({
      tenantId: system.tenantId, companyId: system.companyId, systemId: system._id,
      userId: req.activeUser._id, username: req.activeUser.email || req.activeUser.name,
      role: 'superadmin', action: action.toUpperCase(), previousValue: null,
      newValue: { command: commandTypes[action] }, sourceIp: securitySourceIp(req),
      device: String(req.headers['user-agent'] || '').slice(0, 300), result: 'queued',
    });
    system.pendingCommands = [...(system.pendingCommands || []), {
      command: commandTypes[action], auditId: audit._id,
      requestedAt: new Date(), requestedBy: req.activeUser._id,
    }].slice(-50);
    if (action === 'forceUpdate') {
      system.updateStatus = 'pending';
      system.updateRequestedAt = new Date();
      system.updateTargetVersion = process.env.AGENT_VERSION || '0.1.10';
      system.updateError = null;
    }
    await system.save();
    req.app.get('io')?.to('superadmin').emit('agent-security:update', { systemId: system._id, audit });
    res.status(202).json({ message: 'Security command queued for the next agent heartbeat', audit });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/superadmin/integrations/status
// Reports configuration state only. Secret values are never returned.
router.get('/integrations/status', (req, res) => {
  const velociraptorAuth = (
    hasConfiguredEnv('VELOCIRAPTOR_KEY') ||
    hasConfiguredEnv('VELOCIRAPTOR_SERVER_CONFIG') ||
    hasConfiguredEnv('VELOCIRAPTOR_API_CONFIG')
  );
  const fraudEnabled = process.env.FRAUD_ENABLED !== 'false';
  const ipsMode = process.env.IPS_MODE || 'host-firewall';
  const integrations = [
    {
      id: 'virustotal',
      name: 'VirusTotal',
      configured: hasConfiguredEnv('VIRUSTOTAL_API_KEY'),
      enabled: hasConfiguredEnv('VIRUSTOTAL_API_KEY'),
      detail: 'File, URL and hash reputation',
    },
    {
      id: 'abuseipdb',
      name: 'AbuseIPDB',
      configured: hasConfiguredEnv('ABUSEIPDB_KEY'),
      enabled: hasConfiguredEnv('ABUSEIPDB_KEY'),
      detail: 'IP reputation and abuse confidence',
    },
    {
      id: 'otx',
      name: 'AlienVault OTX',
      configured: hasConfiguredEnv('OTX_API_KEY'),
      enabled: hasConfiguredEnv('OTX_API_KEY'),
      detail: 'Threat-intelligence pulse lookup',
    },
    {
      id: 'ipinfo',
      name: 'IPinfo',
      configured: hasConfiguredEnv('IPINFO_TOKEN'),
      enabled: hasConfiguredEnv('IPINFO_TOKEN'),
      detail: 'IP geolocation and network enrichment',
    },
    {
      id: 'smtp',
      name: 'SMTP Email',
      configured: hasConfiguredEnv('SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM'),
      enabled: hasConfiguredEnv('SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS', 'SMTP_FROM'),
      detail: 'Email alerts and notifications',
    },
    {
      id: 'razorpay',
      name: 'Razorpay',
      configured: hasConfiguredEnv('RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET'),
      enabled: hasConfiguredEnv('RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET'),
      detail: 'Subscriptions and payments',
    },
    {
      id: 'stytch',
      name: 'Stytch',
      configured: hasConfiguredEnv('STYTCH_PROJECT_ID', 'STYTCH_SECRET', 'STYTCH_PUBLIC_TOKEN'),
      enabled: fraudEnabled,
      detail: fraudEnabled ? 'Fraud telemetry enabled' : 'Fraud telemetry disabled',
    },
    {
      id: 'ips-webhook',
      name: 'IPS Webhook',
      configured: hasConfiguredEnv('IPS_WEBHOOK_URL', 'IPS_WEBHOOK_SECRET'),
      enabled: hasConfiguredEnv('IPS_WEBHOOK_URL', 'IPS_WEBHOOK_SECRET'),
      detail: `Mode: ${ipsMode}`,
    },
    {
      id: 'velociraptor',
      name: 'Velociraptor',
      configured: hasConfiguredEnv('VELOCIRAPTOR_URL') && velociraptorAuth,
      enabled: process.env.VELOCIRAPTOR_SIEM_AUTOSCAN === 'true',
      detail: process.env.VELOCIRAPTOR_SIEM_AUTOSCAN === 'true'
        ? 'SIEM auto-scan enabled'
        : 'Manual forensics mode',
    },
  ];

  res.json({
    integrations,
    summary: {
      total: integrations.length,
      configured: integrations.filter(item => item.configured).length,
      active: integrations.filter(item => item.configured && item.enabled).length,
    },
    checkedAt: new Date().toISOString(),
  });
});

function emitPartnerRealtime(req, partnerId, type, payload = {}) {
  const io = req.app.get('io');
  if (!io || !partnerId) return;
  const data = { type, partnerId: String(partnerId), ...payload, ts: new Date().toISOString() };
  const notification = buildPartnerNotification(type, payload.partner);
  if (notification) {
    PartnerNotification.create({
      partnerId,
      type,
      title: notification.title,
      message: notification.message,
      meta: { status: payload.partner?.status || '', resourceStatus: payload.partner?.resourceRequest?.status || '' },
    }).then(doc => {
      io.to(`partner:${partnerId}`).emit('partner:notification', { notification: doc });
    }).catch(err => console.warn('[partner-notification]', err.message));
  }
  io.to('superadmin').emit('partner:update', data);
  io.to(`partner:${partnerId}`).emit('partner:update', data);
}

function latestResourceHistoryIndex(partner) {
  const history = Array.isArray(partner?.resourceRequestHistory) ? partner.resourceRequestHistory : [];
  if (!history.length) return -1;
  let index = history.length - 1;
  for (let i = history.length - 1; i >= 0; i -= 1) {
    if (history[i]?.status === 'pending' || history[i]?.status === 'negotiation') {
      index = i;
      break;
    }
  }
  return index;
}

function normalizeResourceRequestHistory(partner) {
  const history = Array.isArray(partner?.resourceRequestHistory) ? partner.resourceRequestHistory : [];
  const resource = partner?.resourceRequest || {};
  if (!resource.status || resource.status === 'none') return history;
  const current = {
    requestId: `REQ-${String(partner?._id || '000001').slice(-6).toUpperCase()}`,
    status: resource.status,
    numberOfCompanies: resource.numberOfCompanies || 0,
    numberOfAgents: resource.numberOfAgents || 0,
    expectedMonthlyVolume: resource.expectedMonthlyVolume || 0,
    proposedCommission: resource.proposedCommission || 0,
    additionalNotes: resource.additionalNotes || '',
    adminNote: resource.adminNote || '',
    requestedAt: resource.requestedAt || partner.createdAt,
    reviewedAt: resource.reviewedAt || null,
    reviewedBy: resource.reviewedBy || null,
  };
  if (!history.length) return [current];
  const currentRequestedAt = new Date(current.requestedAt || 0).getTime();
  const currentIndex = history.findIndex(item => (
    new Date(item.requestedAt || 0).getTime() === currentRequestedAt &&
    Number(item.numberOfCompanies || 0) === Number(current.numberOfCompanies || 0) &&
    Number(item.numberOfAgents || 0) === Number(current.numberOfAgents || 0)
  ));
  if (currentIndex >= 0) {
    return history.map((item, index) => (index === currentIndex ? { ...item, ...current, requestId: item.requestId || current.requestId } : item));
  }
  return [...history, current];
}

function buildPartnerNotification(type, partner) {
  const name = partner?.name || 'Your partner account';
  const map = {
    settings_updated: ['Partner Profile Updated', `${name} details were updated by Super Admin.`],
    resource_limit_approved: ['Resource Limit Approved', 'Company creation, agent download and subscription access were approved.'],
    approved: ['Partner Approved', 'Your partner account has been approved by Super Admin.'],
    rejected: ['Partner Rejected', 'Your partner account was rejected by Super Admin.'],
    resource_approve: ['Resource Request Approved', 'Your resource request was approved by Super Admin.'],
    resource_reject: ['Resource Request Rejected', 'Your resource request was rejected by Super Admin.'],
    resource_negotiate: ['Resource Request Needs Discussion', 'Super Admin requested negotiation on your resource request.'],
    quote_updated: ['Subscription Quote Ready', 'Super Admin has generated a subscription quote.'],
    plan_rejected: ['Subscription Request Rejected', 'Your subscription request was rejected by Super Admin.'],
  };
  const value = map[type];
  return value ? { title: value[0], message: value[1] } : null;
}

function uploadPathExists(relativePath) {
  const cleanPath = String(relativePath || '').replace(/^\/+/, '');
  if (!cleanPath) return false;
  const uploadRoot = path.resolve(__dirname, '../../uploads');
  const uploadPath = path.resolve(uploadRoot, cleanPath);
  return uploadPath.startsWith(uploadRoot + path.sep) && fs.existsSync(uploadPath);
}

function sanitizePartnerUploadedFiles(partner) {
  if (!partner) return partner;
  if (partner.profile?.avatarFilePath && !uploadPathExists(partner.profile.avatarFilePath)) {
    partner.profile.avatarFileName = '';
    partner.profile.avatarFilePath = '';
  }
  if (partner.agreementFilePath && !uploadPathExists(partner.agreementFilePath)) {
    partner.agreementFileName = '';
    partner.agreementFileType = '';
    partner.agreementFilePath = '';
  }
  const docs = partner.profile?.kycDocuments;
  if (docs) {
    ['gstCertificate', 'panCard', 'businessRegistration'].forEach(docType => {
      const nameKey = `${docType}Name`;
      const typeKey = `${docType}Type`;
      const pathKey = `${docType}FilePath`;
      if (!docs[pathKey] || uploadPathExists(docs[pathKey])) return;
      docs[nameKey] = '';
      docs[typeKey] = '';
      docs[pathKey] = '';
    });
  }
  return partner;
}

function recalcAgentLicenses(partner) {
  if (!partner) return partner;
  const now = new Date();
  const purchases = Array.isArray(partner.agentLicensePurchases) ? partner.agentLicensePurchases : [];
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
  return partner;
}

// ── Tenants / Partners ───────────────────────────────
router.get('/tenants', async (_req, res) => {
  try {
    const tenants = await Tenant.find().sort({ createdAt: -1 });
    res.json(tenants);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/partners', async (_req, res) => {
  try {
    const partners = await Partner.find()
      .select('-profile.avatarDataUrl -profile.kycDocuments.gstCertificateDataUrl -profile.kycDocuments.panCardDataUrl -profile.kycDocuments.businessRegistrationDataUrl')
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email phone forcePasswordReset')
      .lean()
      .sort({ createdAt: -1 });
    res.json(partners.map(partner => sanitizePartnerUploadedFiles(recalcAgentLicenses(partner))));
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.post('/partners', async (req, res) => {
  const { name, slug, adminName, adminEmail, adminPassword, phone, mobile, branding } = req.body;
  const cleanName = String(name || '').trim();
  const cleanSlug = normalizeSlug(slug || name);
  const cleanEmail = String(adminEmail || '').trim().toLowerCase();
  const cleanMobile = String(mobile || phone || '').trim();

  if (!cleanName || !cleanSlug || !cleanEmail) {
    return res.status(400).json({ message: 'Partner name, slug and adminEmail are required' });
  }

  try {
    const existing = await Promise.all([
      Tenant.findOne({ $or: [{ slug: cleanSlug }, { subdomain: cleanSlug }] }),
      Partner.findOne({ slug: cleanSlug }),
      User.findOne({ email: cleanEmail }),
    ]);
    if (existing[0] || existing[1]) return res.status(400).json({ message: 'Partner slug/subdomain already exists' });
    if (existing[2]) return res.status(400).json({ message: 'Admin email already registered' });

    const tenant = await Tenant.create({
      name: cleanName,
      slug: cleanSlug,
      type: 'partner',
      subdomain: cleanSlug,
      branding: branding || {},
      status: 'active',
      createdBy: req.user.id,
    });

    const password = adminPassword || 'PartnerAdmin123!@#';
    const partner = await Partner.create({
      tenantId: tenant._id,
      name: cleanName,
      slug: cleanSlug,
      mobile: cleanMobile,
      status: 'approved',
      approvedAt: new Date(),
      capabilities: {
        createCompany: false,
        downloadAgent: false,
        subscriptionPurchase: false,
      },
      createdBy: req.user.id,
    });

    const referral = await Referral.create({
      tenantId: tenant._id,
      partnerId: partner._id,
      slug: cleanSlug,
      url: buildRegistrationUrl(cleanSlug),
      createdBy: req.user.id,
    });

    const partnerAdmin = await User.create({
      name: adminName || `${cleanName} Admin`,
      email: cleanEmail,
      password,
      phone: cleanMobile,
      role: 'partner_admin',
      tenantId: tenant._id,
      partnerId: partner._id,
      isActive: true,
      isEmailVerified: true,
      forcePasswordReset: true,
    });

    partner.ownerUserId = partnerAdmin._id;
    await partner.save();

    const loginLink = `${process.env.COMPANY_ORIGIN || 'http://localhost:3000'}/login`;
    sendMail({
      to: cleanEmail,
      subject: 'Partner Invitation',
      text: `Your SOC SaaS partner account has been created for ${cleanName}. Login: ${loginLink}. Email: ${cleanEmail}. Temporary password: ${password}. Please reset your password after first login.`,
      html: partnerInvitationEmailHtml({
        partnerName: cleanName,
        adminName: adminName || `${cleanName} Admin`,
        email: cleanEmail,
        password,
        loginLink,
      }),
    }).catch(err => console.warn('[partner invite email]', err.message));

    emitPartnerRealtime(req, partner._id, 'created', { partner });
    res.status(201).json({ tenant, partner, referral, partnerAdmin });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.get('/partners/:id/overview', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid partner id' });
    }

    const partner = await withTimeout(Partner.findById(req.params.id)
      .select('-profile.avatarDataUrl -profile.kycDocuments.gstCertificateDataUrl -profile.kycDocuments.panCardDataUrl -profile.kycDocuments.businessRegistrationDataUrl')
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email phone forcePasswordReset')
      .lean(), null);
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    sanitizePartnerUploadedFiles(recalcAgentLicenses(partner));

    const filter = { partnerId: partner._id };
    const loginFilter = {
      $or: [
        ...(partner.ownerUserId?._id ? [{ userId: partner.ownerUserId._id }] : []),
        ...(partner.ownerUserId?.email ? [{ email: partner.ownerUserId.email }] : []),
      ],
    };
    const [
      companies,
      agents,
      payments,
      supportTickets,
      loginActivities,
      companyCount,
      activeCompanies,
      inactiveCompanies,
      totalAgents,
      activeAgents,
      offlineAgents,
      activePlans,
      expiringPlans,
      revenueAgg,
      pendingAgg,
      monthlyTrend,
    ] = await Promise.all([
      withTimeout(Company.find(filter).sort({ createdAt: -1 }).limit(50).lean(), []),
      withTimeout(System.find(filter).populate('companyId', 'name').sort({ updatedAt: -1 }).limit(50).lean(), []),
      withTimeout(PaymentHistory.find(filter).populate('companyId', 'name').sort({ createdAt: -1 }).limit(50).lean(), []),
      withTimeout(PartnerSupportTicket.find(filter).sort({ createdAt: -1 }).limit(100).lean(), []),
      loginFilter.$or.length ? withTimeout(LoginActivity.find(loginFilter).sort({ createdAt: -1 }).limit(50).lean(), []) : Promise.resolve([]),
      withTimeout(Company.countDocuments(filter), 0),
      withTimeout(Company.countDocuments({ ...filter, status: 'active' }), 0),
      withTimeout(Company.countDocuments({ ...filter, status: { $ne: 'active' } }), 0),
      withTimeout(System.countDocuments(filter), 0),
      withTimeout(System.countDocuments({ ...filter, status: 'active' }), 0),
      withTimeout(System.countDocuments({ ...filter, status: { $in: ['inactive', 'disconnected', 'pending'] } }), 0),
      withTimeout(Company.countDocuments({ ...filter, 'plan.isActive': true }), 0),
      withTimeout(Company.countDocuments({
        ...filter,
        'plan.isActive': true,
        'plan.expiresAt': { $lte: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000) },
      }), 0),
      withTimeout(PaymentHistory.aggregate([
        { $match: { partnerId: partner._id, status: 'captured', source: { $ne: 'partner_checkout' }, planType: { $ne: 'partner_enterprise' } } },
        { $group: { _id: null, total: { $sum: '$amountInr' } } },
      ]), []),
      withTimeout(PaymentHistory.aggregate([
        { $match: { partnerId: partner._id, status: 'created', source: { $ne: 'partner_checkout' }, planType: { $ne: 'partner_enterprise' } } },
        { $group: { _id: null, total: { $sum: '$amountInr' } } },
      ]), []),
      withTimeout(PaymentHistory.aggregate([
        { $match: { partnerId: partner._id, status: 'captured', paidAt: { $ne: null }, source: { $ne: 'partner_checkout' }, planType: { $ne: 'partner_enterprise' } } },
        {
          $group: {
            _id: { $dateToString: { format: '%Y-%m', date: '$paidAt' } },
            total: { $sum: '$amountInr' },
          }
        },
        { $sort: { _id: 1 } },
        { $limit: 12 },
      ]), []),
    ]);

    const paidRevenue = revenueAgg[0]?.total || 0;
    const pendingRevenue = pendingAgg[0]?.total || 0;
    const resourceRequests = normalizeResourceRequestHistory(partner);
    const recentActivity = [
      {
        type: 'Partner Created',
        detail: `${partner.name || 'Partner'} account created${partner.ownerUserId?.email ? ` for ${partner.ownerUserId.email}` : ''}`,
        date: partner.createdAt,
      },
      {
        type: 'Partner Updated',
        detail: `Current status: ${partner.status || 'unknown'}`,
        date: partner.updatedAt,
      },
      ...(partner.approvedAt ? [{
        type: 'Partner Approved',
        detail: `${partner.name || 'Partner'} was approved`,
        date: partner.approvedAt,
      }] : []),
      ...(partner.rejectedAt ? [{
        type: 'Partner Rejected',
        detail: partner.rejectionReason || `${partner.name || 'Partner'} was rejected`,
        date: partner.rejectedAt,
      }] : []),
      ...supportTickets.slice(0, 10).map(ticket => ({
        type: `Support Ticket ${ticket.status || 'Open'}`,
        detail: `${ticket.ticketId}: ${ticket.subject || ticket.category}`,
        date: ticket.updatedAt || ticket.createdAt,
      })),
      ...resourceRequests.slice(0, 10).map(request => ({
        type: `Resource Request ${request.status || 'pending'}`,
        detail: `${request.numberOfCompanies || 0} companies, ${request.numberOfAgents || 0} agents, ${request.proposedCommission || 0}% commission`,
        date: request.reviewedAt || request.requestedAt,
      })),
      ...loginActivities.slice(0, 10).map(log => ({
        type: log.action.replace(/_/g, ' '),
        detail: `${log.email}${log.ipAddress ? ` from ${log.ipAddress}` : ''}${log.success === false ? ' failed' : ''}`,
        date: log.createdAt,
      })),
      ...payments.slice(0, 5).map(payment => ({
        type: 'Payment Received',
        detail: `₹${Number(payment.amountInr || 0).toLocaleString('en-IN')} via Razorpay`,
        date: payment.paidAt || payment.createdAt,
      })),
      ...agents.slice(0, 5).map(agent => ({
        type: 'Agent Installed',
        detail: `${agent.name || agent.hostname || 'Agent'}${agent.companyId?.name ? ` on ${agent.companyId.name}` : ''}`,
        date: agent.installDate || agent.createdAt,
      })),
      ...companies.slice(0, 5).map(company => ({
        type: 'Company Created',
        detail: company.name,
        date: company.createdAt,
      })),
    ].sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0)).slice(0, 50);

    res.json({
      partner,
      summary: {
        companyCount,
        activeCompanies,
        inactiveCompanies,
        totalAgents,
        activeAgents,
        offlineAgents,
        paidRevenue,
        pendingRevenue,
        totalRevenue: paidRevenue + pendingRevenue,
        totalCollected: paidRevenue,
        totalDue: pendingRevenue,
        platformCommission: Math.round(paidRevenue * 0.2),
        partnerProfit: paidRevenue - Math.round(paidRevenue * 0.2),
        activePlans,
        expiringPlans,
      },
      companies,
      agents,
      payments,
      monthlyTrend,
      resourceRequests,
      supportTickets,
      activity: recentActivity,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.patch('/partners/:id', async (req, res) => {
  const statusMap = {
    active: 'active',
    suspended: 'suspended',
    pending: 'pending_request',
    pending_request: 'pending_request',
    approved: 'approved',
    rejected: 'rejected',
    pending_payment: 'pending_payment',
  };
  const status = statusMap[String(req.body.status || '').toLowerCase()];

  try {
    const partner = await Partner.findById(req.params.id).populate('ownerUserId', 'name email phone');
    if (!partner) return res.status(404).json({ message: 'Partner not found' });

    const companyLimit = Number(req.body.companyLimit ?? partner.resourceRequest?.numberOfCompanies ?? 0);
    const agentLimit = Number(req.body.agentLimit ?? partner.resourceRequest?.numberOfAgents ?? 0);
    const commission = Number(req.body.commissionPercent ?? partner.commissionPercent ?? partner.resourceRequest?.proposedCommission ?? 0);
    const platformPaymentAmount = Number(req.body.platformPaymentAmount ?? req.body.amountInr ?? partner.plan?.quote?.amountInr ?? 0);

    if (req.body.name !== undefined) partner.name = String(req.body.name || '').trim() || partner.name;
    if (status) partner.status = status;
    if (req.body.phone !== undefined || req.body.mobile !== undefined) partner.mobile = String(req.body.phone || req.body.mobile || '').trim();
    if (Number.isFinite(companyLimit)) partner.resourceRequest.numberOfCompanies = Math.max(companyLimit, 0);
    if (Number.isFinite(agentLimit)) partner.resourceRequest.numberOfAgents = Math.max(agentLimit, 0);
    if (Number.isFinite(commission)) {
      partner.commissionPercent = Math.max(commission, 0);
      partner.resourceRequest.proposedCommission = Math.max(commission, 0);
    }
    if (req.body.platformPaymentAmount !== undefined || req.body.amountInr !== undefined) {
      const amount = Math.max(platformPaymentAmount, 0);
      partner.plan = partner.plan || {};
      partner.plan.quote = partner.plan.quote || {};
      partner.plan.quote.amountInr = amount;
      partner.plan.quote.billingCycle = partner.plan.quote.billingCycle || partner.plan.billingCycle || 'monthly';
      partner.plan.quote.quotedBy = req.user.id;
      partner.plan.quote.quotedAt = new Date();
      if (amount > 0 && !(partner.plan.paymentStatus === 'paid' && partner.plan.isActive)) {
        partner.plan.requestStatus = 'quoted';
        partner.plan.paymentStatus = 'unpaid';
        partner.plan.isActive = false;
        partner.status = 'pending_payment';
      }
    }
    if (req.body.pricingPlan !== undefined) partner.plan.type = String(req.body.pricingPlan || 'enterprise').trim();
    if (req.body.partnerLinkedAccountId !== undefined || req.body.partner_linked_account_id !== undefined) {
      partner.partner_linked_account_id = String(req.body.partnerLinkedAccountId || req.body.partner_linked_account_id || '').trim();
    }
    if (req.body.agentPricing) {
      partner.agentPricing = partner.agentPricing || {};
      ['monthly', 'sixMonthly', 'yearly'].forEach(key => {
        if (req.body.agentPricing[key] !== undefined) partner.agentPricing[key] = Math.max(Number(req.body.agentPricing[key] || 0), 0);
      });
      partner.agentPricing.currency = 'INR';
      partner.agentPricing.updatedAt = new Date();
    }
    if (req.body.razorpayStatus !== undefined) partner.profile.razorpayKeyId = req.body.razorpayStatus === 'connected'
      ? (partner.profile.razorpayKeyId || 'connected')
      : '';
    if (req.body.kycStatus !== undefined && ['not_submitted', 'pending', 'verified', 'rejected'].includes(req.body.kycStatus)) {
      partner.profile.kycStatus = req.body.kycStatus;
      if (req.body.kycStatus === 'verified') {
        partner.profile.gstVerified = true;
        partner.profile.panVerified = true;
        partner.profile.businessVerified = true;
      }
      if (req.body.kycStatus === 'rejected') {
        partner.profile.gstVerified = false;
        partner.profile.panVerified = false;
        partner.profile.businessVerified = false;
      }
    }
    if (req.body.notes !== undefined) partner.notes = String(req.body.notes || '').trim();
    if (req.body.agreementDetails !== undefined) partner.agreementDetails = String(req.body.agreementDetails || '').trim();
    // agreementFileName / agreementFilePath are now set only via POST /partners/:id/agreement (multer)
    // Do NOT accept agreementDataUrl from body anymore (base64 removed)

    await partner.save();

    if (partner.ownerUserId?._id) {
      const userUpdate = {};
      if (req.body.adminName !== undefined) userUpdate.name = String(req.body.adminName || '').trim();
      if (req.body.adminEmail !== undefined) userUpdate.email = String(req.body.adminEmail || '').trim().toLowerCase();
      if (req.body.phone !== undefined || req.body.mobile !== undefined) userUpdate.phone = String(req.body.phone || req.body.mobile || '').trim();
      if (status) userUpdate.isActive = !['suspended', 'rejected'].includes(status);
      if (Object.keys(userUpdate).length) await User.findByIdAndUpdate(partner.ownerUserId._id, userUpdate);
    }

    await LoginActivity.create({
      userId: req.user.id,
      email: req.user.email || 'superadmin',
      action: 'partner_updated',
      success: true,
      failReason: `partner:${partner._id}`,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const fresh = await Partner.findById(partner._id)
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email phone role tenantId partnerId forcePasswordReset');
    const realtimePartner = fresh.toObject ? fresh.toObject() : fresh;
    // agreementDataUrl field no longer exists (replaced by agreementFilePath)
    if (realtimePartner.profile?.avatarDataUrl) delete realtimePartner.profile.avatarDataUrl;
    if (realtimePartner.profile?.kycDocuments) {
      delete realtimePartner.profile.kycDocuments.gstCertificateDataUrl;
      delete realtimePartner.profile.kycDocuments.panCardDataUrl;
      delete realtimePartner.profile.kycDocuments.businessRegistrationDataUrl;
    }
    emitPartnerRealtime(req, fresh._id, 'settings_updated', { partner: realtimePartner });
    res.json(fresh);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// ── POST /superadmin/partners/:id/agreement — Multer PDF upload ─────────────
router.post('/partners/:id/agreement', agreementUpload.single('agreement'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No PDF file uploaded' });

    const partner = await Partner.findById(req.params.id);
    if (!partner) {
      // Clean up uploaded file if partner not found
      fs.unlink(req.file.path, () => { });
      return res.status(404).json({ message: 'Partner not found' });
    }

    // Delete old agreement file from disk if it exists
    if (partner.agreementFilePath) {
      const oldPath = path.join(__dirname, '../../uploads', partner.agreementFilePath);
      if (fs.existsSync(oldPath)) fs.unlink(oldPath, () => { });
    }

    // Store relative path (e.g. "agreements/agreement-xxx-timestamp.pdf")
    const relativePath = path.relative(
      path.join(__dirname, '../../uploads'),
      req.file.path
    );

    partner.agreementFileName = req.file.originalname;
    partner.agreementFileType = req.file.mimetype;
    partner.agreementFilePath = relativePath;
    // Clear legacy base64 field if it still exists on old records
    if (partner.agreementDataUrl !== undefined) partner.agreementDataUrl = '';
    await partner.save();

    const fresh = await Partner.findById(partner._id)
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email phone role tenantId partnerId forcePasswordReset');
    emitPartnerRealtime(req, fresh._id, 'settings_updated', { partner: fresh });
    res.json({
      success: true,
      agreementFileName: partner.agreementFileName,
      agreementFileType: partner.agreementFileType,
      agreementFilePath: partner.agreementFilePath,
      partner: fresh,
    });
  } catch (err) {
    if (req.file?.path && fs.existsSync(req.file.path)) fs.unlink(req.file.path, () => { });
    res.status(400).json({ message: err.message });
  }
});

router.post('/partners/:id/reset-password', async (req, res) => {
  try {
    const partner = await Partner.findById(req.params.id).populate('ownerUserId', 'name email phone');
    if (!partner?.ownerUserId) return res.status(404).json({ message: 'Partner admin not found' });

    const password = req.body.password || `Partner${crypto.randomBytes(4).toString('hex')}!1`;
    const user = await User.findById(partner.ownerUserId._id);
    user.password = password;
    user.forcePasswordReset = true;
    await user.save();

    await LoginActivity.create({
      userId: req.user.id,
      email: req.user.email || 'superadmin',
      action: 'password_reset',
      success: true,
      failReason: `partner:${partner._id}`,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    res.json({ message: 'Partner admin password reset.', temporaryPassword: password });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/partners/:id/approve-resource-limit', async (req, res) => {
  try {
    const existingPartner = await Partner.findById(req.params.id).select('resourceRequest resourceRequestHistory');
    if (!existingPartner) return res.status(404).json({ message: 'Partner not found' });
    const reviewedAt = new Date();
    const update = {
      'resourceRequest.status': 'approved',
      'resourceRequest.reviewedAt': reviewedAt,
      'resourceRequest.reviewedBy': req.user.id,
      'capabilities.createCompany': true,
      'capabilities.downloadAgent': true,
      'capabilities.subscriptionPurchase': true,
    };
    const historyIndex = latestResourceHistoryIndex(existingPartner);
    if (historyIndex >= 0) {
      update[`resourceRequestHistory.${historyIndex}.status`] = 'approved';
      update[`resourceRequestHistory.${historyIndex}.reviewedAt`] = reviewedAt;
      update[`resourceRequestHistory.${historyIndex}.reviewedBy`] = req.user.id;
    } else if (existingPartner.resourceRequest?.status && existingPartner.resourceRequest.status !== 'none') {
      update.$push = {
        resourceRequestHistory: {
          requestId: `REQ-${String(existingPartner._id || '000001').slice(-6).toUpperCase()}`,
          status: 'approved',
          numberOfCompanies: existingPartner.resourceRequest.numberOfCompanies || 0,
          numberOfAgents: existingPartner.resourceRequest.numberOfAgents || 0,
          expectedMonthlyVolume: existingPartner.resourceRequest.expectedMonthlyVolume || 0,
          proposedCommission: existingPartner.resourceRequest.proposedCommission || 0,
          additionalNotes: existingPartner.resourceRequest.additionalNotes || '',
          adminNote: existingPartner.resourceRequest.adminNote || '',
          requestedAt: existingPartner.resourceRequest.requestedAt || existingPartner.createdAt,
          reviewedAt,
          reviewedBy: req.user.id,
        },
      };
    }

    const partner = await Partner.findByIdAndUpdate(req.params.id, update, { new: true })
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email phone');
    emitPartnerRealtime(req, partner._id, 'resource_limit_approved', { partner });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.post('/partners/:id/impersonate', async (req, res) => {
  try {
    const partner = await Partner.findById(req.params.id)
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email phone role tenantId partnerId forcePasswordReset');
    if (!partner?.ownerUserId) return res.status(404).json({ message: 'Partner admin not found' });

    const user = partner.ownerUserId;
    const token = jwt.sign({
      id: user._id,
      email: user.email,
      role: user.role,
      tenantId: user.tenantId || partner.tenantId?._id || partner.tenantId,
      partnerId: partner._id,
      companyId: null,
      departmentId: null,
      impersonatedBy: req.user.id,
      impersonatedByRole: 'superadmin',
      impersonationMode: 'support_debug',
    }, process.env.JWT_SECRET, { expiresIn: '4h' });

    await LoginActivity.create({
      userId: user._id,
      email: user.email,
      action: 'superadmin_impersonation_started',
      success: true,
      failReason: `by:${req.user.id}`,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    res.json({
      token,
      user,
      partner,
      tenant: partner.tenantId,
      impersonation: {
        active: true,
        by: req.user.id,
        mode: 'support_debug',
        banner: 'You are logged in as Partner Admin via Super Admin',
      },
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/support-tickets/:id', async (req, res) => {
  try {
    const allowedStatuses = ['Open', 'In Progress', 'Resolved', 'Closed'];
    const update = {};
    if (req.body.status !== undefined) {
      if (!allowedStatuses.includes(req.body.status)) return res.status(400).json({ message: 'Invalid ticket status' });
      update.status = req.body.status;
      update.resolvedAt = ['Resolved', 'Closed'].includes(req.body.status) ? new Date() : null;
    }
    if (req.body.solution !== undefined) update.solution = String(req.body.solution || '').trim();

    const ticket = await PartnerSupportTicket.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!ticket) return res.status(404).json({ message: 'Support ticket not found' });
    emitPartnerRealtime(req, ticket.partnerId, 'support_ticket_updated', { ticket });
    res.json(ticket);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// POST /api/superadmin/support-tickets/:ticketId/messages
router.post('/support-tickets/:ticketId/messages', async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });

    const ticket = await PartnerSupportTicket.findById(req.params.ticketId);
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    ticket.messages.push({
      senderId: req.user.id,
      senderName: req.user.name || 'Super Admin',
      senderRole: req.user.role,
      message,
    });
    if (ticket.status === 'Open') {
      ticket.status = 'In Progress';
    }
    await ticket.save();

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('support:message_new', { ticketId: ticket.ticketId, ticket });
      io.to(`partner:${ticket.partnerId}`).emit('support:message_new', { ticketId: ticket.ticketId, ticket });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.patch('/partners/:id/approve', async (req, res) => {
  try {
    const partner = await Partner.findByIdAndUpdate(req.params.id, {
      status: 'approved',
      approvedAt: new Date(),
      rejectedAt: null,
      rejectionReason: '',
      'capabilities.createCompany': false,
      'capabilities.downloadAgent': false,
      'capabilities.subscriptionPurchase': false,
    }, { new: true }).populate('ownerUserId', 'name email phone');

    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    if (partner.ownerUserId?._id) {
      await User.findByIdAndUpdate(partner.ownerUserId._id, { isActive: true, isEmailVerified: true });
    }

    if (partner.ownerUserId?.email) {
      sendMail({
        to: partner.ownerUserId.email,
        subject: 'Partner Account Approved',
        text: `Your partner account has been approved. Login at ${process.env.COMPANY_ORIGIN || 'http://localhost:3000'}/login and complete the Platform Commission payment to unlock your dashboard, company creation and server/agent usage.`,
        html: `<p>Your partner account has been approved.</p><p><a href="${process.env.COMPANY_ORIGIN || 'http://localhost:3000'}/login">Login to Partner Portal</a></p><p>Complete the Platform Commission payment to unlock your dashboard, company creation and server/agent usage.</p>`,
      }).catch(err => console.warn('[partner approval email]', err.message));
    }

    emitPartnerRealtime(req, partner._id, 'approved', { partner });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/partners/:id/reject', async (req, res) => {
  try {
    const partner = await Partner.findByIdAndUpdate(req.params.id, {
      status: 'rejected',
      rejectedAt: new Date(),
      rejectionReason: String(req.body?.reason || '').trim(),
      'capabilities.createCompany': false,
      'capabilities.downloadAgent': false,
      'capabilities.subscriptionPurchase': false,
    }, { new: true }).populate('ownerUserId', 'name email phone');

    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    if (partner.ownerUserId?._id) await User.findByIdAndUpdate(partner.ownerUserId._id, { isActive: false });
    emitPartnerRealtime(req, partner._id, 'rejected', { partner });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/partners/:id/resources/:action', async (req, res) => {
  const action = req.params.action;
  if (!['approve', 'reject', 'negotiate'].includes(action)) {
    return res.status(400).json({ message: 'Invalid resource action' });
  }

  const update = {
    'resourceRequest.adminNote': String(req.body?.note || '').trim(),
    'resourceRequest.reviewedAt': new Date(),
    'resourceRequest.reviewedBy': req.user.id,
  };

  if (action === 'approve') {
    Object.assign(update, {
      'resourceRequest.status': 'approved',
      'capabilities.createCompany': true,
      'capabilities.downloadAgent': true,
      'capabilities.subscriptionPurchase': true,
      'plan.requestStatus': 'quoted',
    });
  } else if (action === 'reject') {
    Object.assign(update, {
      'resourceRequest.status': 'rejected',
      'capabilities.createCompany': false,
      'capabilities.downloadAgent': false,
      'capabilities.subscriptionPurchase': false,
    });
  } else {
    Object.assign(update, {
      'resourceRequest.status': 'negotiation',
      'capabilities.createCompany': false,
      'capabilities.downloadAgent': false,
      'capabilities.subscriptionPurchase': false,
    });
  }

  try {
    const existingPartner = await Partner.findById(req.params.id).select('resourceRequest resourceRequestHistory');
    if (!existingPartner) return res.status(404).json({ message: 'Partner not found' });
    const historyIndex = latestResourceHistoryIndex(existingPartner);
    if (historyIndex >= 0) {
      update[`resourceRequestHistory.${historyIndex}.status`] = update['resourceRequest.status'];
      update[`resourceRequestHistory.${historyIndex}.adminNote`] = update['resourceRequest.adminNote'];
      update[`resourceRequestHistory.${historyIndex}.reviewedAt`] = update['resourceRequest.reviewedAt'];
      update[`resourceRequestHistory.${historyIndex}.reviewedBy`] = update['resourceRequest.reviewedBy'];
    } else if (existingPartner.resourceRequest?.status && existingPartner.resourceRequest.status !== 'none') {
      update.$push = {
        resourceRequestHistory: {
          requestId: `REQ-${String(existingPartner._id || '000001').slice(-6).toUpperCase()}`,
          status: update['resourceRequest.status'],
          numberOfCompanies: existingPartner.resourceRequest.numberOfCompanies || 0,
          numberOfAgents: existingPartner.resourceRequest.numberOfAgents || 0,
          expectedMonthlyVolume: existingPartner.resourceRequest.expectedMonthlyVolume || 0,
          proposedCommission: existingPartner.resourceRequest.proposedCommission || 0,
          additionalNotes: existingPartner.resourceRequest.additionalNotes || '',
          adminNote: update['resourceRequest.adminNote'],
          requestedAt: existingPartner.resourceRequest.requestedAt || existingPartner.createdAt,
          reviewedAt: update['resourceRequest.reviewedAt'],
          reviewedBy: update['resourceRequest.reviewedBy'],
        },
      };
    }

    const partner = await Partner.findByIdAndUpdate(req.params.id, update, { new: true })
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email phone');
    emitPartnerRealtime(req, partner._id, `resource_${action}`, { partner });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/partners/:id/quote', async (req, res) => {
  const { amountInr, billingCycle = 'monthly', notes = '' } = req.body;
  const amount = Number(amountInr);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ message: 'Valid quote amount is required' });
  }
  if (!['monthly', 'yearly'].includes(billingCycle)) {
    return res.status(400).json({ message: 'billingCycle must be monthly or yearly' });
  }

  try {
    const partner = await Partner.findByIdAndUpdate(req.params.id, {
      status: 'pending_payment',
      'plan.requestStatus': 'quoted',
      'plan.quote.amountInr': amount,
      'plan.quote.billingCycle': billingCycle,
      'plan.quote.notes': String(notes || '').trim(),
      'plan.quote.quotedBy': req.user.id,
      'plan.quote.quotedAt': new Date(),
      'plan.paymentStatus': 'unpaid',
      'plan.isActive': false,
    }, { new: true })
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email');

    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    emitPartnerRealtime(req, partner._id, 'quote_updated', { partner });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/partners/:id/reject-plan', async (req, res) => {
  try {
    const partner = await Partner.findByIdAndUpdate(req.params.id, {
      status: 'pending_request',
      'plan.requestStatus': 'rejected',
      'plan.quote.amountInr': 0,
      'plan.quote.notes': String(req.body?.notes || '').trim(),
      'plan.quote.quotedBy': req.user.id,
      'plan.quote.quotedAt': new Date(),
    }, { new: true })
      .populate('tenantId', 'name slug subdomain status')
      .populate('ownerUserId', 'name email');

    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    emitPartnerRealtime(req, partner._id, 'plan_rejected', { partner });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// ── Overview ──────────────────────────────────────────
router.get('/overview', async (req, res) => {
  try {
    const directFilter = {
      $and: [
        { $or: [{ partnerId: null }, { partnerId: { $exists: false } }] },
        { source: { $ne: 'partner_referral' } }
      ]
    };
    const partnerFilter = {
      $or: [
        { partnerId: { $ne: null } },
        { source: 'partner_referral' }
      ]
    };

    const [
      totalCompaniesCount, users, alerts, systems, tenants, partners, partnerAdmins, agents,
      directCompanies, directActiveCompanies, directSuspendedCompanies,
      socManagers, paymentsCount, partnerCompanies, revenueData
    ] = await Promise.all([
      Company.countDocuments(),
      User.countDocuments(),
      Alert.countDocuments(),
      System.countDocuments({ isActive: true }),
      Tenant.countDocuments(),
      Partner.countDocuments(),
      User.countDocuments({ role: 'partner_admin' }),
      User.countDocuments({ role: { $in: ['analyst', 'department_admin'] } }),
      Company.countDocuments(directFilter),
      Company.countDocuments({ ...directFilter, status: 'active' }),
      Company.countDocuments({ ...directFilter, status: 'suspended' }),
      User.countDocuments({ role: 'soc_manager' }),
      PaymentHistory.countDocuments({ status: { $ne: 'failed' } }),
      Company.countDocuments(partnerFilter),
      PaymentHistory.aggregate([
        { $match: { status: { $ne: 'failed' } } },
        { $group: { _id: null, total: { $sum: '$amountInr' } } }
      ])
    ]);
    const totalRevenue = revenueData[0]?.total || 0;

    const companiesByTenant = await Company.aggregate([
      { $group: { _id: '$tenantId', companies: { $sum: 1 } } },
      { $sort: { companies: -1 } },
      { $limit: 8 },
    ]);
    const tenantIds = companiesByTenant.map(x => x._id).filter(Boolean);
    const tenantDocs = await Tenant.find({ _id: { $in: tenantIds } }).select('name slug type subdomain').lean();
    const tenantMap = tenantDocs.reduce((acc, tenant) => {
      acc[String(tenant._id)] = tenant;
      return acc;
    }, {});
    const alertsByDay = await Alert.aggregate([
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
      { $sort: { _id: -1 } },
      { $limit: 30 },
    ]);
    const usersByRole = await User.aggregate([
      { $group: { _id: '$role', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);
    res.json({
      companies: directCompanies,
      totalCompaniesCount,
      users,
      alerts,
      systems,
      tenants,
      partners,
      partnerAdmins,
      agents,
      activeCompanies: directActiveCompanies,
      suspendedCompanies: directSuspendedCompanies,
      directCompanies,
      directActiveCompanies,
      directSuspendedCompanies,
      socManagers,
      paymentsCount,
      partnerCompanies,
      totalRevenue,
      usersByRole,
      companiesByTenant: companiesByTenant.map(row => ({
        tenant: row._id ? tenantMap[String(row._id)] || null : null,
        companies: row.companies,
      })),
      alertsByDay,
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Companies ─────────────────────────────────────────
router.get('/companies', async (req, res) => {
  try {
    const companies = await Company.find()
      .populate('tenantId', 'name slug type subdomain')
      .populate('partnerId', 'name slug')
      .sort({ createdAt: -1 });
    res.json(companies);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.post('/companies', async (req, res) => {
  const { name, email, phone, adminName, adminPassword } = req.body;
  if (!name || !email) return res.status(400).json({ message: 'Company name and email are required' });

  try {
    const { getOrCreateMainTenant } = require('../utils/tenant');
    const mainTenant = await getOrCreateMainTenant(req.user.id);
    const cleanEmail = email.trim().toLowerCase();

    const existing = await Promise.all([
      Company.findOne({ email: cleanEmail }),
      User.findOne({ email: cleanEmail }),
    ]);
    if (existing[0] || existing[1]) return res.status(400).json({ message: 'Company/admin email already exists' });

    const company = await Company.create({
      name: name.trim(),
      email: cleanEmail,
      phone: phone?.trim() || '',
      tenantId: mainTenant._id,
      source: 'admin_created',
      status: 'active',
    });

    const user = await User.create({
      name: adminName || `${name.trim()} Admin`,
      email: cleanEmail,
      password: adminPassword || 'CompanyAdmin123!@#',
      phone: phone?.trim() || '',
      role: 'company_admin',
      tenantId: mainTenant._id,
      companyId: company._id,
      isActive: true,
      isEmailVerified: true,
    });

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: req.user.id,
      companyId: company._id,
      email: req.user.email,
      action: 'company_created',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    await ensureDefaultSoarPlaybooks({
      companyId: company._id,
      tenantId: company.tenantId,
      partnerId: company.partnerId,
      createdBy: user._id,
    }).catch(error => console.error('[superadmin/company-create] default SOAR playbooks:', error.message));

    res.status(201).json({ company, user });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// GET single company
router.get('/companies/:id', async (req, res) => {
  try {
    const company = await Company.findById(req.params.id);
    if (!company) return res.status(404).json({ message: 'Company not found' });
    res.json(company);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.patch('/companies/:id', async (req, res) => {
  try {
    const company = await Company.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!company) return res.status(404).json({ message: 'Company not found' });

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: req.user.id,
      companyId: company._id,
      email: req.user.email,
      action: 'company_status_updated',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const CompanyNotification = require('../models/CompanyNotification.model');
    await CompanyNotification.create({
      companyId: company._id,
      title: 'Company Settings Modified',
      message: `Your company administrative settings (Status: ${company.status}) have been updated by Super Admin.`,
      source: 'superadmin'
    });

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('company:update', { companyId: company._id, company });
      io.to(`company:${company._id}`).emit('company:update', { companyId: company._id, company });
      io.to(`company:${company._id}`).emit('notification:new', { companyId: company._id });
    }
    res.json(company);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

router.patch('/companies/:id/plan', async (req, res) => {
  const { type, systemLimit } = req.body;
  const limits = { basic: 20, pro: 50, enterprise: 999 };
  const limit = systemLimit || limits[type] || 20;
  try {
    const company = await Company.findByIdAndUpdate(req.params.id, {
      'plan.type': type,
      'plan.systemLimit': limit,
      'plan.isActive': true,
      'plan.expiresAt': new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      status: 'active',
    }, { new: true });

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: req.user.id,
      companyId: company._id,
      email: req.user.email,
      action: 'company_plan_updated',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const CompanyNotification = require('../models/CompanyNotification.model');
    await CompanyNotification.create({
      companyId: company._id,
      title: 'Plan Updated',
      message: `Your company plan has been updated to ${type.toUpperCase()} (Limit: ${limit} systems) by Super Admin.`,
      source: 'superadmin'
    });

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('company:update', { companyId: company._id, company });
      io.to(`company:${company._id}`).emit('company:update', { companyId: company._id, company });
      io.to(`company:${company._id}`).emit('notification:new', { companyId: company._id });
    }
    res.json(company);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// POST /api/superadmin/companies/:id/impersonate — login as company admin
router.post('/companies/:id/impersonate', async (req, res) => {
  try {
    const company = await Company.findById(req.params.id);
    if (!company) return res.status(404).json({ message: 'Company not found' });

    let user = await User.findOne({ companyId: company._id, role: 'company_admin' });
    if (!user) {
      user = await User.findOne({ companyId: company._id });
    }
    if (!user) {
      user = await User.findOne({ email: company.email });
    }
    if (!user) {
      user = await User.create({
        name: `${company.name} Admin`,
        email: company.email,
        password: 'CompanyAdmin123!@#',
        role: 'company_admin',
        tenantId: company.tenantId,
        companyId: company._id,
        isActive: true,
        isEmailVerified: true,
      });
    }

    const token = jwt.sign({
      id: user._id,
      email: user.email,
      role: user.role,
      tenantId: user.tenantId || company.tenantId,
      companyId: company._id,
      departmentId: user.departmentId || null,
      impersonatedBy: req.user.id,
      impersonatedByRole: 'superadmin',
      impersonationMode: 'company_admin_login',
    }, process.env.JWT_SECRET, { expiresIn: '4h' });

    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: user._id,
      companyId: null,
      email: user.email,
      action: 'superadmin_company_impersonation_started',
      success: true,
      failReason: `by:${req.user.id}`,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const companyPortalUrl = process.env.COMPANY_PORTAL_URL || 'http://localhost:3000';
    res.json({
      token,
      user,
      company,
      redirectUrl: `${companyPortalUrl}/?impersonationToken=${token}`,
      impersonation: {
        active: true,
        by: req.user.id,
        mode: 'company_admin_login',
        banner: `You are logged in as ${company.name} Admin via Super Admin`,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/superadmin/companies/:id/payments — get payment history for a specific company
router.get('/companies/:id/payments', async (req, res) => {
  try {
    const payments = await PaymentHistory.find({ companyId: req.params.id })
      .sort({ paidAt: -1 })
      .lean();
    res.json(payments);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.delete('/companies/:id', async (req, res) => {
  try {
    await Company.findByIdAndDelete(req.params.id);
    res.json({ message: 'Company deleted' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Company → Departments ─────────────────────────────
router.get('/companies/:companyId/departments', async (req, res) => {
  try {
    const depts = await Department.find({ companyId: req.params.companyId })
      .populate('adminId', 'name email').sort({ createdAt: -1 });
    res.json(depts);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/companies/:companyId/departments/:deptId', async (req, res) => {
  try {
    const dept = await Department.findOne({
      _id: req.params.deptId,
      companyId: req.params.companyId,
    }).populate('adminId', 'name email');
    if (!dept) return res.status(404).json({ message: 'Department not found' });
    res.json(dept);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Company → Systems ──────────────────────────────
router.get('/companies/:companyId/systems', async (req, res) => {
  try {
    const systems = await System.find({
      companyId: req.params.companyId,
      isActive: true,
    }).sort({ createdAt: -1 });
    res.json(systems);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Company → Departments → Systems ──────────────────
router.get('/companies/:companyId/departments/:deptId/systems', async (req, res) => {
  try {
    const systems = await System.find({
      companyId: req.params.companyId,
      departmentId: req.params.deptId,
      isActive: true,
    }).sort({ createdAt: -1 });
    res.json(systems);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/companies/:companyId/departments/:deptId/systems/:systemId', async (req, res) => {
  try {
    const system = await System.findOne({
      _id: req.params.systemId,
      companyId: req.params.companyId,
      departmentId: req.params.deptId,
    });
    if (!system) return res.status(404).json({ message: 'System not found' });
    res.json(system);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Company → Alerts ──────────────────────────────────
router.get('/companies/:companyId/alerts', async (req, res) => {
  try {
    const alerts = await Alert.find({ companyId: req.params.companyId })
      .sort({ createdAt: -1 }).limit(30)
      .populate('departmentId', 'name')
      .populate('systemId', 'name hostname');
    res.json({ alerts });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Company → System → Alerts ─────────────────────────
router.get('/companies/:companyId/systems/:systemId/alerts', async (req, res) => {
  try {
    const alerts = await Alert.find({
      companyId: req.params.companyId,
      systemId: req.params.systemId,
    }).sort({ createdAt: -1 }).limit(50);
    res.json({ alerts });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Company → Users ───────────────────────────────────
router.get('/companies/:companyId/users', async (req, res) => {
  try {
    const users = await User.find({ companyId: req.params.companyId })
      .populate('departmentId', 'name').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Company → AddSystemSubscriptions ──────────────────
router.get('/companies/:companyId/add-system-subscriptions', async (req, res) => {
  try {
    const AddSystemSubscription = require('../models/AddSystemSubscription.model');
    const batches = await AddSystemSubscription.find({ companyId: req.params.companyId }).sort({ createdAt: -1 });
    res.json(batches);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── All Users ─────────────────────────────────────────
router.get('/users', async (req, res) => {
  try {
    const filter = req.query.role === 'analyst'
      ? {
          superadminManaged: true,
          role: { $in: ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'] },
        }
      : {};
    const users = await User.find(filter)
      .populate('companyId', 'name')
      .populate('tenantId', 'name slug type subdomain')
      .populate('partnerId', 'name slug')
      .populate('departmentId', 'name')
      .sort({ createdAt: -1 });
    res.json(users);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.patch('/users/:id', async (req, res) => {
  try {
    // Prevent escalation to superadmin role
    if (req.body.role && !['analyst', 'department_admin', 'company_admin', 'soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(req.body.role))
      return res.status(400).json({ message: 'Invalid role' });
    const { email, password, tenantId, partnerId, companyId, ...safeUpdates } = req.body;
    const user = await User.findByIdAndUpdate(req.params.id, safeUpdates, { new: true, runValidators: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('user:update', { userId: user._id, companyId: user.companyId, user });
      io.to(`company:${user.companyId}`).emit('user:update', { userId: user._id, companyId: user.companyId, user });
    }
    res.json(user);
  } catch (err) { res.status(400).json({ message: err.message }); }
});


// ── GET /api/superadmin/alerts — all alerts with company/dept filter ──────────
router.get('/alerts', async (req, res) => {
  const { companyId, departmentId, severity, status, category, page = 1, limit = 30 } = req.query;
  const filter = {};
  if (companyId) filter.companyId = companyId;
  if (departmentId) filter.departmentId = departmentId;
  if (severity) filter.severity = severity;
  if (status) filter.status = status;
  if (category) filter.eventCategory = category;
  try {
    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(Number(limit))
        .populate('departmentId', 'name')
        .populate('systemId', 'name hostname')
        .populate('companyId', 'name').lean(),
      Alert.countDocuments(filter),
    ]);
    res.json({ alerts, total, page: Number(page) });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Revenue Analytics ─────────────────────────────────────────────────────────

// GET /api/superadmin/revenue/analytics — MRR, ARR, monthly trend
router.get('/revenue/analytics', async (req, res) => {
  try {
    const now = new Date();
    const month0 = new Date(now.getFullYear(), now.getMonth(), 1);
    const month1 = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const year0 = new Date(now.getFullYear(), 0, 1);

    const [companies, activeLicensesAgg, currentMonthRevenue, lastMonthRevenue, yearlyRevenue, byPlan, monthlyTrend] =
      await Promise.all([
        Company.countDocuments({ status: 'active' }),

        Company.aggregate([
          { $match: { status: 'active', 'plan.isActive': true } },
          {
            $group: {
              _id: null,
              systems: { $sum: '$plan.systemCount' },
              servers: { $sum: '$plan.serverCount' },
              phones: { $sum: '$plan.phoneCount' },
            }
          },
        ]),

        PaymentHistory.aggregate([
          { $match: { status: 'captured', paidAt: { $gte: month0 } } },
          { $group: { _id: null, total: { $sum: '$amountInr' }, payments: { $sum: 1 } } },
        ]),

        PaymentHistory.aggregate([
          { $match: { status: 'captured', paidAt: { $gte: month1, $lt: month0 } } },
          { $group: { _id: null, total: { $sum: '$amountInr' }, payments: { $sum: 1 } } },
        ]),

        // Yearly revenue from PaymentHistory (actual)
        PaymentHistory.aggregate([
          { $match: { status: 'captured', paidAt: { $gte: year0 } } },
          { $group: { _id: null, total: { $sum: '$amountInr' }, payments: { $sum: 1 } } },
        ]),

        // By plan type
        Company.aggregate([
          { $match: { status: 'active' } },
          {
            $group: {
              _id: '$plan.type',
              count: { $sum: 1 },
              systems: { $sum: '$plan.systemCount' },
              servers: { $sum: '$plan.serverCount' },
              phones: { $sum: '$plan.phoneCount' },
            }
          },
          { $sort: { count: -1 } },
        ]),

        // Monthly payment trend (last 12 months from PaymentHistory)
        PaymentHistory.aggregate([
          { $match: { status: 'captured', paidAt: { $gte: new Date(now.getFullYear() - 1, now.getMonth(), 1) } } },
          {
            $group: {
              _id: { $dateToString: { format: '%Y-%m', date: '$paidAt' } },
              revenue: { $sum: '$amountInr' },
              payments: { $sum: 1 },
            }
          },
          { $sort: { _id: 1 } },
        ]),
      ]);

    const mrrInr = currentMonthRevenue[0]?.total || 0;
    const lastMonthMrrInr = lastMonthRevenue[0]?.total || 0;
    const mrrGrowth = lastMonthMrrInr > 0
      ? Math.round(((mrrInr - lastMonthMrrInr) / lastMonthMrrInr) * 100)
      : 0;
    const activeLicenses = activeLicensesAgg[0] || { systems: 0, servers: 0, phones: 0 };
    const activeLicenseTotal = Number(activeLicenses.systems || 0) + Number(activeLicenses.servers || 0) + Number(activeLicenses.phones || 0);

    res.json({
      mrr: mrrInr,
      arr: mrrInr * 12,
      mrrGrowth,
      activeSystems: Number(activeLicenses.systems || 0),
      activeServers: Number(activeLicenses.servers || 0),
      activePhones: Number(activeLicenses.phones || 0),
      activeLicenses: activeLicenseTotal,
      activeCompanies: companies,
      yearlyRevenue: yearlyRevenue[0]?.total || 0,
      currentMonthPayments: currentMonthRevenue[0]?.payments || 0,
      yearlyPayments: yearlyRevenue[0]?.payments || 0,
      byPlan,
      monthlyTrend,
      currency: 'INR',
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/superadmin/revenue/history — paginated payment history
router.get('/revenue/history', async (req, res) => {
  try {
    const { page = 1, limit = 20, companyId } = req.query;
    const filter = { status: 'captured' };
    if (companyId) filter.companyId = companyId;

    const [payments, total] = await Promise.all([
      PaymentHistory.find(filter)
        .sort({ paidAt: -1 })
        .skip((page - 1) * Number(limit))
        .limit(Number(limit))
        .populate('companyId', 'name email')
        .lean(),
      PaymentHistory.countDocuments(filter),
    ]);

    res.json({ payments, total, page: Number(page) });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/superadmin/revenue/top-companies — top revenue companies
router.get('/revenue/top-companies', async (req, res) => {
  try {
    const companies = await Company.find({ status: 'active' })
      .sort({ createdAt: -1 })
      .select('name email plan status riskScore createdAt razorpay')
      .lean();

    // Calculate MRR per company from active systems
    const result = await Promise.all(companies.map(async c => {
      const systemCount = await System.countDocuments({ companyId: c._id, isActive: true, status: 'active' });
      const totalPaid = await PaymentHistory.aggregate([
        { $match: { companyId: c._id, status: 'captured' } },
        { $group: { _id: null, total: { $sum: '$amountInr' } } },
      ]);
      return {
        ...c,
        systemCount,
        monthlyRevenue: systemCount * 200,
        totalRevenue: totalPaid[0]?.total || (c.plan?.isActive ? systemCount * 200 : 0),
      };
    }));

    result.sort((a, b) => b.monthlyRevenue - a.monthlyRevenue);
    res.json(result.slice(0, 20));
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Subscription Management (Super Admin) ─────────────────────────────────────

// GET /api/superadmin/subscriptions — direct superadmin company subscriptions
router.get('/subscriptions', async (req, res) => {
  try {
    const directFilter = {
      $and: [
        { $or: [{ partnerId: null }, { partnerId: { $exists: false } }] },
        { source: { $ne: 'partner_referral' } }
      ]
    };
    const companies = await Company.find(directFilter)
      .select('name email phone plan razorpay status createdAt partnerId source')
      .sort({ createdAt: -1 })
      .lean();

    res.json(companies);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/superadmin/payments — direct superadmin company payment history
router.get('/payments', async (req, res) => {
  const { limit = 100, page = 1 } = req.query;
  try {
    const directCompanies = await Company.find({
      $and: [
        { $or: [{ partnerId: null }, { partnerId: { $exists: false } }] },
        { source: { $ne: 'partner_referral' } }
      ]
    }).select('_id').lean();
    const directCompanyIds = directCompanies.map(c => c._id);

    const filter = {
      status: { $ne: 'failed' },
      companyId: { $in: directCompanyIds }
    };

    const [payments, total] = await Promise.all([
      PaymentHistory.find(filter)
        .sort({ paidAt: -1, createdAt: -1 })
        .skip((page - 1) * Number(limit))
        .limit(Number(limit))
        .populate('companyId', 'name email')
        .lean(),
      PaymentHistory.countDocuments(filter),
    ]);
    res.json(payments);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/superadmin/subscriptions/:companyId/autopay — toggle autopay for a company
router.patch('/subscriptions/:companyId/autopay', async (req, res) => {
  const { enabled } = req.body;
  try {
    const company = await Company.findByIdAndUpdate(
      req.params.companyId,
      { 'plan.autoPay': !!enabled },
      { new: true }
    ).select('name plan status');
    if (!company) return res.status(404).json({ message: 'Company not found' });

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: req.user.id,
      companyId: company._id,
      email: req.user.email,
      action: 'company_autopay_updated',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const CompanyNotification = require('../models/CompanyNotification.model');
    await CompanyNotification.create({
      companyId: company._id,
      title: 'AutoPay Status Changed',
      message: `Your company AutoPay settings have been ${enabled ? 'ENABLED' : 'DISABLED'} by Super Admin.`,
      source: 'superadmin'
    });

    res.json({ success: true, company });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// ── GET /api/superadmin/add-systems-log — all "Add Systems" upgrade records ───
router.get('/add-systems-log', async (req, res) => {
  try {
    const { page = 1, limit = 50, companyId } = req.query;
    const filter = { status: 'captured', isUpgrade: true };
    if (companyId) filter.companyId = companyId;

    const [records, total, stats] = await Promise.all([
      PaymentHistory.find(filter)
        .sort({ paidAt: -1 })
        .skip((page - 1) * Number(limit))
        .limit(Number(limit))
        .populate('companyId', 'name email plan status')
        .lean(),
      PaymentHistory.countDocuments(filter),
      PaymentHistory.aggregate([
        { $match: filter },
        {
          $group: {
            _id: null,
            totalRevenue: { $sum: '$amountInr' },
            totalSystems: { $sum: '$addedSystems' },
            totalServers: { $sum: '$addedServers' },
            totalUpgrades: { $sum: 1 },
            uniqueCompanies: { $addToSet: '$companyId' },
          }
        },
      ]),
    ]);

    const s = stats[0] || {};
    res.json({
      records,
      total,
      page: Number(page),
      summary: {
        totalRevenue: s.totalRevenue || 0,
        totalSystems: s.totalSystems || 0,
        totalServers: s.totalServers || 0,
        totalUpgrades: s.totalUpgrades || 0,
        uniqueCompanies: (s.uniqueCompanies || []).length,
      },
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/superadmin/companies/:id/support-tickets
router.get('/companies/:id/support-tickets', async (req, res) => {
  try {
    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const tickets = await CompanySupportTicket.find({ companyId: req.params.id })
      .sort({ createdAt: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/superadmin/companies/:id/support-tickets/:ticketId/messages
router.post('/companies/:id/support-tickets/:ticketId/messages', async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });

    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const ticket = await CompanySupportTicket.findOne({
      _id: req.params.ticketId,
      companyId: req.params.id
    });
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    ticket.messages.push({
      senderId: req.user.id,
      senderName: req.user.name || req.user.email,
      senderRole: req.user.role,
      message,
    });
    if (ticket.status === 'Open') {
      ticket.status = 'In Progress';
    }
    await ticket.save();

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('support:message_new', { ticketId: ticket.ticketId, ticket });
      io.to(`company:${req.params.id}`).emit('support:message_new', { ticketId: ticket.ticketId, ticket });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PATCH /api/superadmin/companies/:id/support-tickets/:ticketId/status
router.patch('/companies/:id/support-tickets/:ticketId/status', async (req, res) => {
  try {
    const { status } = req.body;
    if (!status || !['Open', 'In Progress', 'Resolved', 'Closed'].includes(status)) {
      return res.status(400).json({ message: 'Valid status required' });
    }

    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const ticket = await CompanySupportTicket.findOne({
      _id: req.params.ticketId,
      companyId: req.params.id
    });
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    ticket.status = status;
    await ticket.save();

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('support:ticket_updated', { ticketId: ticket.ticketId, ticket });
      io.to(`company:${req.params.id}`).emit('support:ticket_updated', { ticketId: ticket.ticketId, ticket });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── Correlation routes for Superadmin ──────────────────────────────────────────
router.get('/correlation', async (req, res) => {
  try {
    const { companyId, severity, status, page = 1, limit = 20, search, sort = 'newest', from, to } = req.query;
    const safePage = Math.max(1, Number.parseInt(page, 10) || 1);
    const safeLimit = Math.min(100, Math.max(1, Number.parseInt(limit, 10) || 20));
    const filter = {};
    if (companyId && !mongoose.isValidObjectId(companyId)) return res.status(400).json({ message: 'Invalid company' });
    if (severity && !['low', 'medium', 'high', 'critical'].includes(severity)) return res.status(400).json({ message: 'Invalid severity' });
    if (status && !['all', 'open', 'investigating', 'resolved', 'false_positive'].includes(status)) return res.status(400).json({ message: 'Invalid status' });
    if (companyId) filter.companyId = new mongoose.Types.ObjectId(companyId);
    if (severity) filter.severity = severity;
    if (status && status !== 'all') filter.status = status;
    else if (!status) filter.status = { $in: ['open', 'investigating'] };
    if (search) {
      const escaped = String(search).slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = [
        { incidentId: { $regex: escaped, $options: 'i' } },
        { patternName: { $regex: escaped, $options: 'i' } },
        { agentName: { $regex: escaped, $options: 'i' } },
      ];
    }
    if (from || to) {
      const fromDate = from ? new Date(from) : null;
      const toDate = to ? new Date(to) : null;
      if ((fromDate && Number.isNaN(fromDate.getTime())) || (toDate && Number.isNaN(toDate.getTime()))) {
        return res.status(400).json({ message: 'Invalid date range' });
      }
      filter.createdAt = {};
      if (fromDate) filter.createdAt.$gte = fromDate;
      if (toDate) filter.createdAt.$lte = toDate;
    }

    const CorrelationEvent = require('../models/CorrelationEvent.model');
    const [events, total] = await Promise.all([
      CorrelationEvent.find(filter)
        .sort(sort === 'risk' ? { riskScore: -1, lastActivityAt: -1 } : { lastActivityAt: -1, createdAt: -1 })
        .skip((safePage - 1) * safeLimit)
        .limit(safeLimit)
        .populate('companyId', 'name')
        .populate('alertIds', 'description severity eventCategory source ruleId createdAt')
        .populate('systemId', 'name hostname')
        .lean(),
      CorrelationEvent.countDocuments(filter),
    ]);
    res.json({ events, total, page: safePage, limit: safeLimit, totalPages: Math.max(1, Math.ceil(total / safeLimit)) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/correlation/stats', async (req, res) => {
  try {
    const { companyId } = req.query;
    if (companyId && !mongoose.isValidObjectId(companyId)) return res.status(400).json({ message: 'Invalid company' });
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const base = { createdAt: { $gte: since } };
    if (companyId) base.companyId = new mongoose.Types.ObjectId(companyId);
    const activeBase = { ...base, status: { $in: ['open', 'investigating'] } };

    const CorrelationEvent = require('../models/CorrelationEvent.model');
    const Alert = require('../models/Alert.model');
    const alertBase = { createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } };
    if (companyId) alertBase.companyId = new mongoose.Types.ObjectId(companyId);
    const [total, active, rejected, bySeverity, byPattern, openCritical, eventsAnalyzed24h, latestAlert] = await Promise.all([
      CorrelationEvent.countDocuments(base),
      CorrelationEvent.countDocuments({ ...base, status: { $in: ['open', 'investigating'] } }),
      CorrelationEvent.countDocuments({ ...base, status: 'false_positive' }),
      CorrelationEvent.aggregate([
        { $match: activeBase },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ]),
      CorrelationEvent.aggregate([
        { $match: activeBase },
        { $group: { _id: '$patternName', count: { $sum: 1 }, severity: { $first: '$severity' } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      CorrelationEvent.countDocuments({ ...base, severity: 'critical', status: { $in: ['open', 'investigating'] } }),
      Alert.countDocuments(alertBase),
      Alert.findOne(alertBase).sort({ createdAt: -1 }).select('createdAt agentName eventCategory').lean(),
    ]);

    res.json({
      total, active, rejected, bySeverity, byPattern, openCritical, period: '7d',
      eventsAnalyzed24h, lastEventAt: latestAlert?.createdAt || null,
      ruleCount: require('../services/correlation.service').PATTERNS.length,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/correlation/run', async (req, res) => {
  try {
    const { companyId } = req.body;
    const { detectCorrelations } = require('../services/correlation.service');
    let detected = [];
    if (companyId) {
      if (!mongoose.isValidObjectId(companyId)) return res.status(400).json({ message: 'Invalid company' });
      detected = await detectCorrelations(companyId, { io: req.app.get('io') });
    } else {
      const companies = await Company.find({ status: 'active' }).select('_id').lean();
      for (const company of companies) {
        detected.push(...await detectCorrelations(String(company._id), { io: req.app.get('io') }));
      }
    }
    res.json({ ok: true, detected: detected.length, events: detected });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/correlation/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid incident' });
    const CorrelationEvent = require('../models/CorrelationEvent.model');
    const event = await CorrelationEvent.findById(req.params.id)
      .populate('companyId', 'name').populate('systemId', 'name hostname ip os')
      .populate('alertIds', 'description severity eventCategory source ruleId srcip destip domain fileHash createdAt')
      .populate('relatedAlertIds', 'description severity eventCategory source ruleId srcip destip domain fileHash createdAt')
      .populate('assignedTo', 'name email').lean();
    if (!event) return res.status(404).json({ message: 'Correlation event not found' });
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
