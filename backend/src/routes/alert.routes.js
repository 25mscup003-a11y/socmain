const router  = require('express').Router();
const mongoose = require('mongoose');
const Alert   = require('../models/Alert.model');
const System  = require('../models/System.model');
const GeolocationPolicy = require('../models/GeolocationPolicy.model');
const { authenticate, requireManager, requireAnalyst } = require('../middleware/auth.middleware');
const { runSoarForAlert } = require('../services/soar.service');
const { evaluatePlaybooksForAlert } = require('../services/automatedResponse.service');
const { resolveScope, scopeForUser } = require('../utils/tenantScope');
const { getUserDataFilter, socWorkItemFilter, assertCompanyScope } = require('../services/socAccess.service');
const vt          = require('../services/virustotal.service');
const threatIntel = require('../services/threat-intel.service');
const { getCompanyIngestionStatus, sendIngestionBlocked } = require('../utils/agentEntitlement');
const {
  enrichFimHashFields,
  enrichFimPermissionFields,
} = require('../security/agentTelemetry');
const { boundedInteger, enforceBatchLimit } = require('../utils/requestLimits');
const { verifySignedAgentRequest } = require('../utils/agentRequestAuth');
const { brokerEnabled, getEventBroker } = require('../services/eventBroker.service');
const { ingestionEvents } = require('../observability/httpObservability');
const { isAuthCapabilityTelemetry } = require('../utils/authCapability');
const { isShiftActiveAt } = require('../services/soarEmailRecipients.service');
const { inferSecurityModule, normalizeSecurityEvent, normalizeEventCategory, calculateSecurityRisk } = require('../utils/securityEventNormalizer');
const { ingestNetworkTelemetry } = require('../services/networkMonitoring.service');
const { enrichHashSignatureEvent } = require('../services/hashSignature.service');
const { scheduleGeolocationEnrichment, persistCurrentGpsState } = require('../services/geolocation.service');
const { isRoutineSecurityTelemetry } = require('../utils/routineTelemetry');
const { applySystemChangeControls } = require('../services/systemChangeControl.service');
const { applyRegistryConfigurationPolicies } = require('../services/registryConfigurationPolicy.service');

const ALERT_CONSOLE_LOGS = String(process.env.ALERT_CONSOLE_LOGS || '').toLowerCase() === 'true';
const geoPolicyCache = new Map();

async function hasActiveGeoPolicy(companyId) {
  const key = String(companyId);
  const cached = geoPolicyCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.active;
  const active = Boolean(await GeolocationPolicy.exists({ companyId, enabled: true }));
  geoPolicyCache.set(key, { active, expiresAt: Date.now() + 5000 });
  return active;
}

async function activeGpsPolicyAccuracyLimit(companyId, systemId) {
  const policies = await GeolocationPolicy.find({
    companyId,
    enabled: true,
    category: { $in: ['Device GPS Tracking', 'Location-Based'] },
    'conditions.gpsTracking': { $ne: false },
  }).select('conditions.systemIds conditions.gpsAccuracyMeters').lean();
  const applicable = policies.filter(policy => {
    const targets = Array.isArray(policy.conditions?.systemIds) ? policy.conditions.systemIds.map(String) : [];
    return targets.length === 0 || targets.includes(String(systemId));
  });
  if (!applicable.length) return null;
  return Math.min(50, ...applicable.map(policy => {
    const configured = Number(policy.conditions?.gpsAccuracyMeters ?? 50);
    return Number.isFinite(configured) ? Math.max(5, configured) : 50;
  }));
}

// DNS-related ruleId patterns from dns_monitor.py
const DNS_RULE_PATTERNS = /dns_tunnel|dga|net_tor|net_dns|dns_monitor|net_c2|onion|dns_spoof|cache_poison/i;

function numberOrUndefined(...values) {
  for (const value of values) {
    if (value === null || value === undefined || value === '') continue;
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function processCreateDate(value) {
  if (value === null || value === undefined || value === '') return undefined;
  const n = Number(value);
  // Agents use both Unix seconds (desktop) and Unix milliseconds (Android).
  const date = Number.isFinite(n) ? new Date(n < 100000000000 ? n * 1000 : n) : new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date;
}

function eventDateFromBody(body = {}) {
  const value = body.file_mtime || body.fileMtime || body.fileModifiedAt || body.file_modified_at
    || body.timestamp || body.createdAt || body.event_time || body.eventTime;
  const date = value ? new Date(value) : new Date();
  return Number.isNaN(date.getTime()) ? new Date() : date;
}

function memoryMetricExpiry(body = {}) {
  const metricType = body.memoryMetricType || body.memory_metric_type || body.raw?.memoryMetricType || body.raw?.memory_metric_type;
  const isMetric = Boolean(metricType) || body.eventType === 'memory.metric' || body.event_type === 'memory.metric';
  const capabilityIds = [
    body.capabilityId, body.capability_id, body.raw?.capabilityId, body.raw?.capability_id,
    ...(Array.isArray(body.capabilityIds) ? body.capabilityIds : []),
    ...(Array.isArray(body.capability_ids) ? body.capability_ids : []),
  ].map(Number);
  if (!isMetric && !capabilityIds.includes(29)) return undefined;
  const configured = isMetric ? process.env.MEMORY_METRIC_RETENTION_DAYS : process.env.MEMORY_EVENT_RETENTION_DAYS;
  const fallback = isMetric ? 30 : 180;
  const days = Math.min(3650, Math.max(1, Number(configured) || fallback));
  return new Date(Date.now() + days * 86400000);
}

function hasCapability(alert, capabilityId) {
  return Number(alert?.capabilityId) === capabilityId
    || (Array.isArray(alert?.capabilityIds) && alert.capabilityIds.map(Number).includes(capabilityId));
}

function normalizeActionTaken(value) {
  const action = String(value || '').trim().toLowerCase();
  if (!action) return null;
  if (['block', 'blocked', 'drop', 'dropped', 'deny', 'denied'].includes(action)) return 'Blocked';
  if (['allow', 'allowed', 'permit', 'permitted'].includes(action)) return 'Allowed';
  if (['quarantine', 'quarantined'].includes(action)) return 'Quarantined';
  if (['delete', 'deleted', 'remove', 'removed'].includes(action)) return 'Deleted';
  if (['system logout', 'logout', 'logged out', 'force logoff'].includes(action)) return 'Logged Out';
  if (['isolate', 'isolated', 'endpoint isolation'].includes(action)) return 'Isolated';
  // File lifecycle/telemetry actions belong in fileAction/eventType, not in
  // the security-response action enum.
  return 'None';
}

function higherSeverity(left, right) {
  const rank = { low: 0, medium: 1, high: 2, critical: 3 };
  const a = String(left || 'low').toLowerCase();
  const b = String(right || 'low').toLowerCase();
  return (rank[b] || 0) > (rank[a] || 0) ? b : a;
}

function severityFromRisk(score) {
  const value = Number(score || 0);
  if (value >= 80) return 'critical';
  if (value >= 60) return 'high';
  if (value >= 40) return 'medium';
  return 'low';
}

async function enrichHashAlertThreatIntel(alert, io) {
  if (!alert || !hasCapability(alert, 25) || !alert.fileHash
    || alert.vtScore != null || alert.hashSignatureThreatIntelEnabled === false
    || !vt.isEnabled()) return;

  try {
    const vtResult = await vt.scanHash(alert.fileHash);
    if (!vtResult) return; // Unknown is telemetry, never malware by itself.
    const detections = Number(vtResult.detections || 0);
    const total = Number(vtResult.total || 0);
    const vtApplied = applyVtRules({
      malicious: detections,
      total,
      score: Number(vtResult.score || 0),
      verdict: vtResult.verdict,
    }, alert.eventCategory, alert.severity, alert.description);
    const hashTelemetry = await enrichHashSignatureEvent({
      ...(alert.rawEvent || {}),
      filePath: alert.filePath,
      fileHash: alert.fileHash,
      signatureStatus: alert.signatureStatus,
      publisher: alert.publisher,
      vtVerdict: vtApplied.vtVerdict || vtResult.verdict,
      virustotal: {
        malicious: detections,
        total_engines: total,
        score: Number(vtResult.score || 0),
        verdict: vtApplied.vtVerdict || vtResult.verdict,
        source: 'VirusTotal',
      },
    }, {
      tenantId: alert.tenantId,
      companyId: alert.companyId,
      departmentId: alert.departmentId,
      endpointId: alert.endpointId || alert.systemId,
      filePath: alert.filePath || alert.processExe,
      fileName: alert.fileName,
      observedAt: alert.createdAt || new Date(),
    });
    const update = {
      vtScore: Number(vtResult.score || 0),
      vtDetections: detections,
      vtTotal: total,
      vtEngines: vtResult.engines || [],
      vtDetectionRatio: vtResult.detection_ratio || `${detections}/${total}`,
      vtVerdict: vtApplied.vtVerdict || vtResult.verdict,
      vtScannedAt: vtResult.scannedAt || new Date(),
      eventCategory: vtApplied.eventCategory,
      underObservation: vtApplied.underObservation,
      ...hashTelemetry,
    };
    update.riskScore = Math.max(Number(alert.riskScore || 0), Number(hashTelemetry.hashSignatureRiskScore || 0));
    update.severity = higherSeverity(
      vtApplied.severity,
      hashTelemetry.hashSignatureAlertEligible ? hashTelemetry.hashSignatureSeverity : alert.severity,
    );
    if (vtApplied.description) update.description = vtApplied.description;
    const refreshed = await Alert.findByIdAndUpdate(alert._id, { $set: update }, { new: true });
    if (refreshed && io) {
      io.to(`company:${alert.companyId}`).emit('hash:alert', refreshed);
      io.to(`company:${alert.companyId}`).emit('alert:updated', {
        _id: alert._id,
        capabilityId: 25,
      });
    }
  } catch (error) {
    console.error('[hash threat intel]', error.message);
  }
}

async function enrichScriptThreatIntel(alert, io) {
  if (!alert || !hasCapability(alert, 21) || !alert.fileHash || alert.vtScore != null || !vt.isEnabled()) return;
  try {
    const result = await vt.scanHash(alert.fileHash);
    if (!result) return; // An unknown script hash is not malware by itself.
    const detections = Number(result.detections || 0);
    const total = Number(result.total || 0);
    const malicious = detections > 5;
    const suspicious = !malicious && detections > 0;
    const currentRisk = Number(alert.riskScore || 0);
    const riskScore = Math.min(100, Math.max(currentRisk, malicious ? 90 : suspicious ? 60 : Math.max(0, currentRisk - 10)));
    const severity = malicious ? 'critical' : suspicious ? higherSeverity(alert.severity, 'high') : alert.severity;
    const refreshed = await Alert.findByIdAndUpdate(alert._id, { $set: {
      vtScore: Number(result.score || 0), vtDetections: detections, vtTotal: total,
      vtEngines: result.engines || [], vtDetectionRatio: result.detection_ratio || `${detections}/${total}`,
      vtVerdict: result.verdict || (malicious ? 'malicious' : suspicious ? 'suspicious' : 'clean'),
      vtScannedAt: result.scannedAt || new Date(), threatIntelMatch: malicious || suspicious,
      threatIntelSource: 'VirusTotal', reputation: malicious ? 'malicious' : suspicious ? 'suspicious' : 'known-good',
      riskScore, severity,
    } }, { new: true });
    if (refreshed && io) {
      io.to(`company:${alert.companyId}`).emit('script:event', refreshed);
      io.to(`company:${alert.companyId}`).emit('alert:updated', { _id: alert._id, capabilityId: 21 });
    }
  } catch (error) {
    console.error('[script threat intel]', error.message);
  }
}

function pickFirst(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return undefined;
}

function normalizeUebaTelemetry(body = {}, system = null) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const riskFactors = pickFirst(
    body.uebaRiskFactors, body.ueba_risk_factors,
    raw.uebaRiskFactors, raw.ueba_risk_factors,
  );
  return {
    behaviorCategory: pickFirst(body.behaviorCategory, body.behavior_category, raw.behaviorCategory, raw.behavior_category),
    entityType: pickFirst(body.entityType, body.entity_type, raw.entityType, raw.entity_type),
    entityId: pickFirst(
      body.entityId, body.entity_id, raw.entityId, raw.entity_id,
      body.username, body.user, body.system_name, system?.hostname, system?.name,
    ),
    behaviorScore: numberOrUndefined(body.behaviorScore, body.behavior_score, raw.behaviorScore, raw.behavior_score),
    baselineScore: numberOrUndefined(body.baselineScore, body.baseline_score, raw.baselineScore, raw.baseline_score),
    peerDeviationScore: numberOrUndefined(body.peerDeviationScore, body.peer_deviation_score, raw.peerDeviationScore, raw.peer_deviation_score),
    uebaConfidence: numberOrUndefined(body.uebaConfidence, body.ueba_confidence, raw.uebaConfidence, raw.ueba_confidence),
    uebaRiskFactors: Array.isArray(riskFactors) ? riskFactors.map(String).filter(Boolean).slice(0, 50) : [],
    baselineWindowDays: numberOrUndefined(body.baselineWindowDays, body.baseline_window_days, raw.baselineWindowDays, raw.baseline_window_days),
    inputMonitoringAvailable: pickFirst(body.inputMonitoringAvailable, body.input_monitoring_available, raw.inputMonitoringAvailable, raw.input_monitoring_available),
    inputPrivacyMode: pickFirst(body.inputPrivacyMode, body.input_privacy_mode, raw.inputPrivacyMode, raw.input_privacy_mode),
    inputKeyboardEvents: numberOrUndefined(body.inputKeyboardEvents, body.input_keyboard_events, raw.inputKeyboardEvents, raw.input_keyboard_events),
    inputMouseEvents: numberOrUndefined(body.inputMouseEvents, body.input_mouse_events, raw.inputMouseEvents, raw.input_mouse_events),
    inputClickCount: numberOrUndefined(body.inputClickCount, body.input_click_count, raw.inputClickCount, raw.input_click_count),
    inputScrollCount: numberOrUndefined(body.inputScrollCount, body.input_scroll_count, raw.inputScrollCount, raw.input_scroll_count),
    inputKeyboardRate: numberOrUndefined(body.inputKeyboardRate, body.input_keyboard_rate, raw.inputKeyboardRate, raw.input_keyboard_rate),
    inputMouseRate: numberOrUndefined(body.inputMouseRate, body.input_mouse_rate, raw.inputMouseRate, raw.input_mouse_rate),
    inputActivityPercent: numberOrUndefined(body.inputActivityPercent, body.input_activity_percent, raw.inputActivityPercent, raw.input_activity_percent),
    inputProfileStatus: pickFirst(body.inputProfileStatus, body.input_profile_status, raw.inputProfileStatus, raw.input_profile_status),
    inputBaselineDays: numberOrUndefined(body.inputBaselineDays, body.input_baseline_days, raw.inputBaselineDays, raw.input_baseline_days),
    inputIdentityConfidence: numberOrUndefined(body.inputIdentityConfidence, body.input_identity_confidence, raw.inputIdentityConfidence, raw.input_identity_confidence),
    inputProfileMismatch: pickFirst(body.inputProfileMismatch, body.input_profile_mismatch, raw.inputProfileMismatch, raw.input_profile_mismatch),
    inputProfileMismatchFeatures: (() => {
      const features = pickFirst(body.inputProfileMismatchFeatures, body.input_profile_mismatch_features, raw.inputProfileMismatchFeatures, raw.input_profile_mismatch_features);
      return Array.isArray(features) ? features.map(String).filter(Boolean).slice(0, 8) : [];
    })(),
    inputProfileDeviation: (() => {
      const deviation = pickFirst(body.inputProfileDeviation, body.input_profile_deviation, raw.inputProfileDeviation, raw.input_profile_deviation);
      if (!deviation || typeof deviation !== 'object' || Array.isArray(deviation)) return {};
      return Object.fromEntries(Object.entries(deviation).slice(0, 8).map(([key, value]) => [String(key).slice(0, 64), Number(value) || 0]));
    })(),
    inputUserSource: pickFirst(body.inputUserSource, body.input_user_source, raw.inputUserSource, raw.input_user_source),
    inputUserVerified: pickFirst(body.inputUserVerified, body.input_user_verified, raw.inputUserVerified, raw.input_user_verified),
    inputSessionCount: numberOrUndefined(body.inputSessionCount, body.input_session_count, raw.inputSessionCount, raw.input_session_count),
  };
}

function normalizeEmailTelemetry(body = {}) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const auth = pickFirst(body.emailAuth, body.email_auth, raw.emailAuth, raw.email_auth) || {};
  const direction = String(pickFirst(body.emailDirection, body.email_direction, raw.emailDirection, raw.email_direction, 'unknown')).toLowerCase();
  return {
    emailSender: pickFirst(body.emailSender, body.email_sender, body.sender, body.from, raw.emailSender, raw.email_sender, raw.sender),
    emailRecipient: pickFirst(body.emailRecipient, body.email_recipient, body.recipient, body.to, raw.emailRecipient, raw.email_recipient, raw.recipient),
    emailSubject: pickFirst(body.emailSubject, body.email_subject, body.subject, raw.emailSubject, raw.email_subject, raw.subject),
    emailDirection: ['incoming', 'outgoing', 'internal', 'unknown'].includes(direction) ? direction : 'unknown',
    emailMessageId: pickFirst(body.emailMessageId, body.email_message_id, body.messageId, body.message_id, raw.emailMessageId, raw.message_id),
    emailAuth: {
      spf: pickFirst(auth.spf, body.spf, raw.spf),
      dkim: pickFirst(auth.dkim, body.dkim, raw.dkim),
      dmarc: pickFirst(auth.dmarc, body.dmarc, raw.dmarc),
    },
    mailboxEventType: pickFirst(body.mailboxEventType, body.mailbox_event_type, raw.mailboxEventType, raw.mailbox_event_type),
    attachmentMimeType: pickFirst(body.attachmentMimeType, body.attachment_mime_type, body.mimeType, body.mime_type, raw.attachmentMimeType, raw.mime_type),
    attachmentSize: numberOrUndefined(body.attachmentSize, body.attachment_size, raw.attachmentSize, raw.attachment_size),
  };
}

function normalizeLateralTelemetry(body = {}) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const related = pickFirst(body.relatedEventIds, body.related_event_ids, raw.relatedEventIds, raw.related_event_ids);
  return {
    lateralVector: pickFirst(body.lateralVector, body.lateral_vector, body.vector, raw.lateralVector, raw.lateral_vector, raw.vector),
    sourceHost: pickFirst(body.sourceHost, body.source_host, body.srcHost, body.src_host, raw.sourceHost, raw.source_host, raw.src_host),
    destinationHost: pickFirst(body.destinationHost, body.destination_host, body.dstHost, body.dst_host, raw.destinationHost, raw.destination_host, raw.dst_host),
    authProtocol: pickFirst(body.authProtocol, body.auth_protocol, body.authMethod, body.auth_method, raw.authProtocol, raw.auth_protocol, raw.auth_method),
    shareName: pickFirst(body.shareName, body.share_name, body.share, raw.shareName, raw.share_name, raw.share),
    sessionState: pickFirst(body.sessionState, body.session_state, raw.sessionState, raw.session_state),
    windowsEventId: numberOrUndefined(body.windowsEventId, body.windows_event_id, raw.windowsEventId, raw.windows_event_id),
    attackPathId: pickFirst(body.attackPathId, body.attack_path_id, raw.attackPathId, raw.attack_path_id),
    relatedEventIds: Array.isArray(related) ? related.map(String).slice(0, 100) : [],
  };
}

function normalizeCredentialTelemetry(body = {}) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  return {
    credentialEventType: pickFirst(body.credentialEventType, body.credential_event_type, body.authAction, body.auth_action, raw.credentialEventType, raw.credential_event_type, raw.auth_action),
    authResult: pickFirst(body.authResult, body.auth_result, body.result, raw.authResult, raw.auth_result, raw.result),
    failureReason: pickFirst(body.failureReason, body.failure_reason, raw.failureReason, raw.failure_reason),
    sessionId: pickFirst(body.sessionId, body.session_id, raw.sessionId, raw.session_id),
    deviceId: pickFirst(body.deviceId, body.device_id, raw.deviceId, raw.device_id),
    mfaStatus: pickFirst(body.mfaStatus, body.mfa_status, raw.mfaStatus, raw.mfa_status),
    identityProvider: pickFirst(body.identityProvider, body.identity_provider, body.provider, raw.identityProvider, raw.identity_provider, raw.provider),
    privilegeLevel: pickFirst(body.privilegeLevel, body.privilege_level, raw.privilegeLevel, raw.privilege_level),
    logonType: pickFirst(body.logonType, body.logon_type, raw.logonType, raw.logon_type),
    groupName: pickFirst(body.groupName, body.group_name, body.group, raw.groupName, raw.group_name, raw.group),
    targetUser: pickFirst(body.targetUser, body.target_user, raw.targetUser, raw.target_user),
    endpointType: pickFirst(body.endpointType, body.endpoint_type, body.hostType, body.host_type, raw.endpointType, raw.endpoint_type, raw.host_type),
    credentialTarget: pickFirst(body.credentialTarget, body.credential_target, raw.credentialTarget, raw.credential_target),
    tokenType: pickFirst(body.tokenType, body.token_type, raw.tokenType, raw.token_type),
  };
}

function normalizeDataSecurityTelemetry(body = {}) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const explicitCapabilityIds = [
    body.capabilityId, body.capability_id,
    ...(Array.isArray(body.capabilityIds) ? body.capabilityIds : []),
    ...(Array.isArray(body.capability_ids) ? body.capability_ids : []),
    raw.capabilityId, raw.capability_id,
  ].map(Number);
  const source = String(pickFirst(body.source, body.log_source, raw.source, '')).toLowerCase();
  const subCategory = String(pickFirst(body.subCategory, body.sub_category, raw.subCategory, raw.sub_category, '')).toLowerCase();
  const hasExplicitDataFields = [
    body.dataEventType, body.data_event_type, body.dataClassification, body.data_classification,
    body.dlpPattern, body.dlp_pattern, body.transferChannel, body.transfer_channel,
    raw.dataEventType, raw.data_event_type, raw.dataClassification, raw.data_classification,
    raw.dlpPattern, raw.dlp_pattern, raw.transferChannel, raw.transfer_channel,
  ].some(value => value !== undefined && value !== null && value !== '');
  const isDataSecurityEvent = explicitCapabilityIds.includes(12)
    || source === 'data_security'
    || /data[-_ ]security|\bdlp\b/.test(subCategory)
    || hasExplicitDataFields;
  let classification = String(pickFirst(
    body.dataClassification, body.data_classification, body.classification,
    raw.dataClassification, raw.data_classification, raw.classification, '',
  ));
  const allowedClassifications = new Set(['Public', 'Internal', 'Confidential', 'Restricted', 'Secret', 'Unknown']);
  if (classification) classification = `${classification.charAt(0).toUpperCase()}${classification.slice(1).toLowerCase()}`;
  const sensitivity = String(pickFirst(body.sensitivityType, body.sensitivity_type, raw.sensitivity_type, '')).toLowerCase();
  if (!allowedClassifications.has(classification)) {
    if (/credential|secret|key/.test(sensitivity)) classification = 'Secret';
    else if (/source|identity|database|backup/.test(sensitivity)) classification = 'Restricted';
    else if (/business|confidential|sensitive/.test(sensitivity)) classification = 'Confidential';
    else classification = 'Unknown';
  }
  const rule = String(pickFirst(body.ruleId, body.rule_id, '')).toLowerCase();
  const inferredChannel = /usb/.test(rule) ? 'usb' : /cloud/.test(rule) ? 'cloud' : /exfil|transfer/.test(rule) ? 'network' : undefined;
  return {
    dataEventType: pickFirst(
      body.dataEventType, body.data_event_type, raw.dataEventType, raw.data_event_type,
      ...(isDataSecurityEvent ? [body.eventType, body.event_type, body.fileAction, body.file_action, body.ruleId, body.rule_id] : []),
    ),
    dataClassification: classification || (isDataSecurityEvent ? 'Unknown' : undefined),
    dlpPattern: pickFirst(body.dlpPattern, body.dlp_pattern, raw.dlpPattern, raw.dlp_pattern),
    dlpMatchCount: numberOrUndefined(body.dlpMatchCount, body.dlp_match_count, raw.dlpMatchCount, raw.dlp_match_count),
    transferChannel: pickFirst(body.transferChannel, body.transfer_channel, raw.transferChannel, raw.transfer_channel, inferredChannel),
    destinationDomain: pickFirst(body.destinationDomain, body.destination_domain, raw.destinationDomain, raw.destination_domain, body.domain, raw.domain),
    transferProtocol: pickFirst(body.transferProtocol, body.transfer_protocol, raw.transferProtocol, raw.transfer_protocol, body.protocol, raw.protocol),
  };
}

function normalizeSystemChangeTelemetry(body = {}, capabilityIds = []) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const ids = [body.capabilityId, body.capability_id, ...capabilityIds,
    ...(Array.isArray(body.capabilityIds) ? body.capabilityIds : []),
    ...(Array.isArray(body.capability_ids) ? body.capability_ids : [])].map(Number);
  const evidence = `${body.ruleId || body.rule_id || ''} ${body.eventType || body.event_type || ''} ${body.description || ''} ${body.category || ''} ${body.inventoryType || body.inventory_type || ''} ${body.filePath || body.file_path || ''} ${body.keyPath || body.key_path || ''}`.toLowerCase();
  if (!ids.includes(7) && !/system.?change/.test(evidence)) return {};

  let category = pickFirst(body.systemChangeCategory, body.system_change_category, raw.systemChangeCategory, raw.system_change_category);
  if (!category) {
    if (/user|account|group|sudoers|administrator|privilege/.test(evidence)) category = 'users_groups';
    else if (/service|systemd|daemon|\bsmf\b/.test(evidence)) category = 'services';
    else if (/scheduled.task|schtasks|\bcron\b|crontab|\bat job\b/.test(evidence)) category = 'scheduled_tasks';
    else if (/registry|hklm|hkcu|runonce|winlogon|group.policy|\bgpo\b/.test(evidence)) category = 'registry_configuration';
    else if (/firewall|defender|antivirus|security.policy|audit/.test(evidence)) category = 'security_configuration';
    else if (/dns|hosts.file|resolv.conf|gateway|proxy|route|network.adapter|vpn/.test(evidence)) category = 'network_configuration';
    else if (/software|package|patch|installer|driver/.test(evidence)) category = 'software_patch';
    else if (/kernel|boot|grub|secure.boot|\bbcd\b/.test(evidence)) category = 'boot_kernel';
    else if (/certificate|trusted.root|\btls\b/.test(evidence)) category = 'certificates';
    else if (/docker|container|kubernetes|\bk8s\b|pod/.test(evidence)) category = 'container_virtualization';
    else if (/permission|ownership|\bacl\b|suid|sgid|chmod|chown/.test(evidence)) category = 'permissions';
    else category = 'critical_system_files';
  }
  const changeType = pickFirst(body.systemChangeType, body.system_change_type, raw.systemChangeType, raw.system_change_type,
    body.changeType, body.change_type, body.fileAction, body.file_action, body.eventType, body.event_type, body.user_action, body.ruleId, body.rule_id);
  const target = pickFirst(body.systemChangeTarget, body.system_change_target, raw.systemChangeTarget, raw.system_change_target,
    body.target, body.targetFile, body.filePath, body.file_path, body.keyPath, body.key_path, body.registryKey, body.registry_key,
    body.inventoryName, body.inventory_name, body.serviceName, body.service_name);
  const previousState = pickFirst(body.previousState, body.previous_state, raw.previousState, raw.previous_state,
    body.oldInventoryItem, body.old_inventory_item, body.oldValue, body.old_value, body.oldHash, body.old_hash, body.previous_status);
  const newState = pickFirst(body.newState, body.new_state, raw.newState, raw.new_state,
    body.inventoryItem, body.inventory_item, body.newValue, body.new_value, body.newHash, body.new_hash, body.current_status);
  const indicators = [];
  let calculatedRisk = 35;
  if (/log.cleared|audit.*disabled|tamper|defender.*disabled|firewall.*disabled|security.*stopped/.test(evidence)) { calculatedRisk = 88; indicators.push('defense_impairment'); }
  if (/administrator|domain.admin|root|sudoers|authorized.keys|secure.boot|bootloader|kernel.module/.test(evidence)) { calculatedRisk = Math.max(calculatedRisk, 75); indicators.push('privileged_or_boot_change'); }
  if (/service.*(?:created|installed)|scheduled.task.*created|registry.*(?:run|winlogon)|exclusion.*added/.test(evidence)) { calculatedRisk = Math.max(calculatedRisk, 68); indicators.push('persistence_or_security_change'); }
  if (/system32|syswow64|\/etc\/(?:shadow|passwd|sudoers|ssh|pam\.d|security|audit)/.test(evidence)) { calculatedRisk = Math.max(calculatedRisk, 62); indicators.push('critical_target'); }
  if (/unsigned|untrusted|temp|appdata|downloads|powershell.*encoded/.test(evidence)) { calculatedRisk += 15; indicators.push('suspicious_actor'); }
  const maintenanceApproved = body.maintenanceApproved === true || body.maintenance_approved === true || raw.maintenance_approved === true;
  if (maintenanceApproved && !indicators.includes('defense_impairment')) calculatedRisk -= 25;
  calculatedRisk = Math.max(0, Math.min(100, calculatedRisk));
  const reportedRisk = numberOrUndefined(body.riskScore, body.risk_score, raw.riskScore, raw.risk_score);
  const normalizedRisk = maintenanceApproved && !indicators.includes('defense_impairment')
    ? Math.min(reportedRisk ?? calculatedRisk, calculatedRisk)
    : Math.max(reportedRisk ?? 0, calculatedRisk);

  const inferredMitre = category === 'scheduled_tasks' ? 'T1053'
    : category === 'services' ? 'T1543'
      : category === 'registry_configuration' ? 'T1112'
        : category === 'audit_tampering' ? 'T1070.001'
          : category === 'boot_kernel' ? 'T1547.006'
            : category === 'users_groups' ? 'T1098'
              : category === 'security_configuration' ? 'T1562.001' : undefined;
  return {
    systemChangeCategory: category,
    systemChangeType: changeType,
    systemChangeTarget: target,
    previousState,
    newState,
    baselineStatus: pickFirst(body.baselineStatus, body.baseline_status, raw.baselineStatus, raw.baseline_status, 'unexpected'),
    changeSource: pickFirst(body.changeSource, body.change_source, raw.changeSource, raw.change_source, body.source, body.log_source),
    changeTicket: pickFirst(body.changeTicket, body.change_ticket, raw.changeTicket, raw.change_ticket),
    maintenanceApproved,
    systemChangeIndicators: [...new Set([...(Array.isArray(body.systemChangeIndicators) ? body.systemChangeIndicators : []), ...indicators])],
    riskScore: normalizedRisk,
    mitreId: pickFirst(body.mitreId, body.mitre_id, raw.mitreId, raw.mitre_id, inferredMitre),
  };
}

function normalizeRegistryConfigurationTelemetry(body = {}, capabilityIds = []) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const ids = [body.capabilityId, body.capability_id, ...capabilityIds,
    ...(Array.isArray(body.capabilityIds) ? body.capabilityIds : []),
    ...(Array.isArray(body.capability_ids) ? body.capability_ids : [])].map(Number);
  if (!ids.includes(6)) return {};
  const target = pickFirst(
    body.configurationObject, body.configuration_object, raw.configurationObject, raw.configuration_object,
    body.keyPath, body.key_path, body.registryKey, body.registry_key, body.filePath, body.file_path,
    body.sourcePath, body.source_path, body.target,
  );
  const evidence = `${body.ruleId || body.rule_id || ''} ${body.eventType || body.event_type || ''} ${body.description || ''} ${target || ''} ${body.newValue || body.new_value || ''}`.toLowerCase();
  const platformText = String(pickFirst(body.configurationPlatform, body.configuration_platform, body.osType, body.os_type, body.os, body.platform, raw.platform, '')).toLowerCase();
  const configurationPlatform = /sunos|solaris/.test(platformText) ? 'solaris'
    : /linux|ubuntu|debian|rhel|centos/.test(platformText) ? 'linux'
      : /win/.test(platformText) || /hklm|hkcu|hkey/.test(evidence) ? 'windows' : (platformText || 'unknown');
  let configurationCategory = pickFirst(body.configurationCategory, body.configuration_category, raw.configurationCategory, raw.configuration_category);
  if (!configurationCategory) {
    if (/runonce|run.key|winlogon|userinit|appinit|image.file.execution|\\clsid|cron|systemd|init\.d|ld.so.preload|startup/.test(evidence)) configurationCategory = 'persistence';
    else if (/defender|antivirus|firewall|uac|security.center|audit|eventlog|sysmon|selinux|apparmor|pam|credential.guard|bitlocker|smartscreen|applocker|exploit/.test(evidence)) configurationCategory = 'security_configuration';
    else if (/passwd|shadow|group|sudoers|user.attr|account|administrator|password.policy|lsa|authentication|credential.provider/.test(evidence)) configurationCategory = 'user_authentication';
    else if (/dns|resolv.conf|hosts.file|\\hosts|proxy|network|adapter|route|vpn|smb|tcpip/.test(evidence)) configurationCategory = 'network_configuration';
    else if (/software|package|apt|dpkg|yum|dnf|rpm|zypper|msi|file.association|powershell.policy/.test(evidence)) configurationCategory = 'software_configuration';
    else if (/service|currentcontrolset\\services|smf|svcadm|svc:\//.test(evidence)) configurationCategory = 'service_configuration';
    else if (/permission|owner|acl|suid|sgid/.test(evidence)) configurationCategory = 'permissions';
    else configurationCategory = configurationPlatform === 'windows' ? 'registry_integrity' : 'configuration_integrity';
  }
  const configurationOperation = String(pickFirst(
    body.configurationOperation, body.configuration_operation, raw.configurationOperation, raw.configuration_operation,
    body.operation, body.changeType, body.change_type, body.fileAction, body.file_action, body.eventType, body.event_type,
  ) || 'observed').toLowerCase();
  const riskFactors = [];
  const severityRisk = { low: 20, medium: 45, high: 70, critical: 90 }[String(body.severity || '').toLowerCase()] || 30;
  let calculatedRisk = severityRisk;
  if (/defender.*(?:disable|off)|security.log.*(?:disable|clear)|edr.*(?:stop|tamper)|audit.*disable/.test(evidence)) { calculatedRisk = 94; riskFactors.push('security_control_impairment'); }
  else if (/runonce|run.key|winlogon|image.file.execution|authentication.package|\\lsa|unauthorized.*admin/.test(evidence)) { calculatedRisk = 86; riskFactors.push('critical_persistence_or_authentication_change'); }
  else if (/firewall.*disable|rdp.*enable|sudoers|cron|systemd|sshd.config|permitrootlogin/.test(evidence)) { calculatedRisk = 76; riskFactors.push('high_risk_configuration_change'); }
  else if (/permission|owner|acl|dns|proxy|software|package/.test(evidence)) { calculatedRisk = Math.max(calculatedRisk, 52); riskFactors.push('configuration_deviation'); }
  if (/powershell|cmd\.exe|wscript|mshta|\\temp\\|\\appdata\\|\/tmp\//.test(evidence)) { calculatedRisk += 12; riskFactors.push('suspicious_process_or_path'); }
  const reportedRisk = numberOrUndefined(body.riskScore, body.risk_score, raw.riskScore, raw.risk_score);
  const riskScore = Math.min(100, Math.max(calculatedRisk, reportedRisk || 0));
  let mitreId;
  let technique;
  let mitreTactic;
  if (/runonce|run.key|winlogon|startup/.test(evidence)) { mitreId = 'T1547.001'; technique = 'Registry Run Keys / Startup Folder'; mitreTactic = 'Persistence'; }
  else if (/service|smf/.test(evidence)) { mitreId = 'T1543'; technique = 'Create or Modify System Process'; mitreTactic = 'Persistence'; }
  else if (/scheduled.task|cron/.test(evidence)) { mitreId = 'T1053'; technique = 'Scheduled Task/Job'; mitreTactic = 'Persistence'; }
  else if (/user|account|administrator|sudoers|rbac/.test(evidence)) { mitreId = 'T1098'; technique = 'Account Manipulation'; mitreTactic = 'Persistence'; }
  else if (/defender|firewall|audit|eventlog|sysmon|edr.*(?:stop|disable)/.test(evidence)) { mitreId = 'T1562.001'; technique = 'Impair Defenses'; mitreTactic = 'Defense Evasion'; }
  else if (/lsa|authentication.package|credential.provider/.test(evidence)) { mitreId = 'T1556'; technique = 'Modify Authentication Process'; mitreTactic = 'Credential Access'; }
  else if (configurationPlatform === 'windows' && /registry|hklm|hkcu|hkey/.test(evidence)) { mitreId = 'T1112'; technique = 'Modify Registry'; mitreTactic = 'Defense Evasion'; }
  return {
    configurationCategory,
    configurationOperation,
    configurationObject: target,
    configurationPlatform,
    configurationBaselineStatus: pickFirst(body.configurationBaselineStatus, body.configuration_baseline_status, raw.configurationBaselineStatus, raw.configuration_baseline_status, body.baselineStatus, body.baseline_status, 'unexpected'),
    configurationPolicyViolation: pickFirst(body.configurationPolicyViolation, body.configuration_policy_violation, raw.configurationPolicyViolation, raw.configuration_policy_violation, riskScore >= 60) === true,
    configurationRiskFactors: [...new Set([...(Array.isArray(body.configurationRiskFactors) ? body.configurationRiskFactors : []), ...(Array.isArray(body.configuration_risk_factors) ? body.configuration_risk_factors : []), ...riskFactors])].slice(0, 30),
    registryHive: pickFirst(body.registryHive, body.registry_hive, raw.registryHive, raw.registry_hive, /^HK(?:LM|CU|CR|U|CC)/i.exec(String(target || ''))?.[0]),
    registryValueName: pickFirst(body.registryValueName, body.registry_value_name, raw.registryValueName, raw.registry_value_name, body.valueName, body.value_name),
    registryValueType: pickFirst(body.registryValueType, body.registry_value_type, raw.registryValueType, raw.registry_value_type, body.valueType, body.value_type),
    processAttribution: pickFirst(body.processAttribution, body.process_attribution, raw.processAttribution, raw.process_attribution),
    riskScore,
    ...(mitreId ? { mitreId, technique, mitreTactic } : {}),
  };
}

function normalizeCapabilityTelemetry(body = {}, system = null) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const ruleText = `${body.rule_id || body.ruleId || ''} ${body.category || ''} ${body.subCategory || body.sub_category || ''} ${body.eventType || body.event_type || ''} ${body.description || ''}`.toLowerCase();
  let capabilityId = numberOrUndefined(body.capabilityId, body.capability_id, raw.capabilityId, raw.capability_id);
  if (!capabilityId) {
    const isFileTelemetry = Boolean(body.file_path || body.filePath || body.file_action || body.fileAction)
      || String(body.source || body.log_source || '').toLowerCase() === 'file_watch'
      || /^file[_ -]/.test(ruleText);
    const category = String(body.category || raw.category || '').toLowerCase();
    const source = String(body.source || body.log_source || raw.source || '').toLowerCase();
    const isProcessTelemetry = Boolean(body.process_name || body.processName || body.pid || body.process_count)
      || /^proc[_ -]/.test(ruleText) || /process (?:started|terminated|inventory)/.test(ruleText);
    const isNetworkTelemetry = category === 'network' || source === 'network'
      || Boolean(body.dst_ip || body.destip || body.dst_port || body.destPort)
      || /^net[_ -]/.test(ruleText);
    if (isProcessTelemetry) capabilityId = 1;
    else if (isFileTelemetry) capabilityId = 2;
    else if (isNetworkTelemetry) capabilityId = 3;
    else if (isAuthCapabilityTelemetry(body, raw)) capabilityId = 4;
    else if (/memory|ram|lsass|shellcode|dll injection|process injection|fileless|heap|rwx/.test(ruleText)) capabilityId = 5;
    else if (/registry|hklm|hkcu|run key|linux config|solaris|compliance|file integrity|fim|permission/.test(ruleText)) capabilityId = 6;
    else if (/system change|service|driver|install|uninstall|update|boot|scheduled task|user activity/.test(ruleText)) capabilityId = 7;
    else if (/persistence|startup|wmi|com hijack|dll hijack|cron|systemd|authorized_keys|kernel module|cloud persistence/.test(ruleText)) capabilityId = 8;
  }
  const categoryByCapability = {
    2: 'file',
    4: 'edr',
    5: 'memory',
    6: 'registry',
    7: 'systemchanges',
    8: 'persistence',
    15: 'edr',
    29: 'memory',
    36: 'memory',
    37: 'network',
    38: 'network',
  };
  const category = pickFirst(body.category, raw.category, categoryByCapability[capabilityId]);
  const subCategory = pickFirst(body.subCategory, body.sub_category, raw.subCategory, raw.sub_category);
  const eventType = pickFirst(body.eventType, body.event_type, raw.eventType, raw.event_type, body.user_action, body.file_action);
  const sourcePath = pickFirst(body.sourcePath, body.source_path, body.file_path, body.filePath, raw.sourcePath, raw.source_path, raw.file_path);
  const keyPath = pickFirst(body.keyPath, body.key_path, body.registryKey, body.registry_key, body.path, raw.keyPath, raw.key_path, raw.registry_key, raw.path, sourcePath);
  const oldHash = pickFirst(body.oldHash, body.old_hash, body.previousHash, body.previous_hash, raw.oldHash, raw.old_hash, raw.previousHash, raw.previous_hash);
  const newHash = pickFirst(body.newHash, body.new_hash, body.file_hash, body.fileHash, body.sha256, raw.newHash, raw.new_hash, raw.file_hash, raw.fileHash, raw.sha256);
  const hashAlgorithm = pickFirst(body.hashAlgorithm, body.hash_algorithm, raw.hashAlgorithm, raw.hash_algorithm, oldHash || newHash ? 'sha256' : undefined);
  const oldValue = pickFirst(body.oldValue, body.old_value, raw.oldValue, raw.old_value, oldHash);
  const newValue = pickFirst(body.newValue, body.new_value, raw.newValue, raw.new_value, newHash);
  const riskScore = numberOrUndefined(body.riskScore, body.risk_score, raw.riskScore, raw.risk_score);
  const insiderSignalType = pickFirst(
    body.insiderSignalType,
    body.insider_signal_type,
    raw.insiderSignalType,
    raw.insider_signal_type,
  );
  const rawStatus = String(pickFirst(body.status, raw.status, '') || '').toLowerCase().replace(/\s+/g, '_');
  const status = ['open', 'investigating', 'resolved', 'false_positive', 'under_observation'].includes(rawStatus)
    ? rawStatus
    : undefined;
  const rawFimModule = String(pickFirst(body.fimModule, body.fim_module, body.moduleType, body.module_type, raw.fimModule, raw.fim_module, raw.moduleType, raw.module_type) || '').toLowerCase().replace(/_/g, '-');
  const fimModule = ({
    general: 'integrity', hash: 'integrity', 'integrity-monitoring': 'integrity', integrity: 'integrity',
    permissions: 'permission', permission: 'permission', ownership: 'ownership',
    ransomware: 'ransomware', 'ransomware-detection': 'ransomware',
    sensitive: 'sensitive', 'sensitive-files': 'sensitive',
  })[rawFimModule] || (capabilityId === 2 ? 'integrity' : undefined);
  const kernelRules = ['SYS_MODULE_LOAD', 'SYS_KERNEL_ERR', 'PROC_LINUX_KERNEL_INJECTION'];
  const isKernelRule = kernelRules.includes(body.ruleId || raw.ruleId || body.rule_id || raw.rule_id || body.ruleName || raw.ruleName);
  const resolvedCapId = isKernelRule ? 19 : capabilityId;
  const normalizedCapabilityIds = [...new Set([
    ...(Array.isArray(body.capabilityIds) ? body.capabilityIds : []),
    ...(Array.isArray(body.capability_ids) ? body.capability_ids : []),
    ...(Array.isArray(raw.capabilityIds) ? raw.capabilityIds : []),
    ...(Array.isArray(raw.capability_ids) ? raw.capability_ids : []),
    resolvedCapId,
  ].map(Number).filter(Number.isFinite))];
  const systemChangeTelemetry = normalizeSystemChangeTelemetry(body, normalizedCapabilityIds);
  const registryConfigurationTelemetry = normalizeRegistryConfigurationTelemetry(body, normalizedCapabilityIds);

  return {
    capabilityId: resolvedCapId,
    capabilityIds: normalizedCapabilityIds,
    fimModule,
    category,
    subCategory,
    eventType,
    riskScore: registryConfigurationTelemetry.riskScore ?? systemChangeTelemetry.riskScore ?? riskScore,
    ...systemChangeTelemetry,
    ...registryConfigurationTelemetry,
    insiderSignalType,
    endpointId: pickFirst(body.endpointId, body.endpoint_id, body.system_id, system?._id),
    hostname: pickFirst(body.hostname, body.host, body.system_name, system?.hostname, system?.name),
    osType: pickFirst(body.osType, body.os_type, body.os, body.platform, raw.osType, raw.os_type, raw.os, raw.platform, system?.osType, system?.os),
    agentVersion: pickFirst(body.agentVersion, body.agent_version, system?.agentVersion),
    sourcePath,
    keyPath,
    registryKey: pickFirst(
      body.registryKey,
      body.registry_key,
      capabilityId === 6 || category === 'registry' ? keyPath : undefined
    ),
    oldValue,
    newValue,
    oldHash,
    newHash,
    hashAlgorithm,
    hash: pickFirst(body.hash, body.sha256, body.file_hash, body.fileHash, body.new_hash, body.newHash, raw.hash, raw.sha256, raw.file_hash, raw.new_hash),
    telemetryProvider: pickFirst(body.telemetryProvider, body.telemetry_provider, raw.telemetryProvider, raw.telemetry_provider),
    providerChannel: pickFirst(body.providerChannel, body.provider_channel, raw.providerChannel, raw.provider_channel),
    providerEventId: numberOrUndefined(body.providerEventId, body.provider_event_id, raw.providerEventId, raw.provider_event_id),
    providerRecordId: numberOrUndefined(body.providerRecordId, body.provider_record_id, raw.providerRecordId, raw.provider_record_id),
    evidenceType: pickFirst(body.evidenceType, body.evidence_type, raw.evidenceType, raw.evidence_type),
    coverageStatus: pickFirst(body.coverageStatus, body.coverage_status, raw.coverageStatus, raw.coverage_status),
    sensorStatus: pickFirst(body.sensorStatus, body.sensor_status, raw.sensorStatus, raw.sensor_status),
    sourceProcessName: pickFirst(body.sourceProcessName, body.source_process_name, raw.sourceProcessName, raw.source_process_name),
    sourcePid: numberOrUndefined(body.sourcePid, body.source_pid, raw.sourcePid, raw.source_pid),
    targetProcessName: pickFirst(body.targetProcessName, body.target_process_name, raw.targetProcessName, raw.target_process_name),
    targetPid: numberOrUndefined(body.targetPid, body.target_pid, raw.targetPid, raw.target_pid),
    imageLoaded: pickFirst(body.imageLoaded, body.image_loaded, raw.imageLoaded, raw.image_loaded),
    grantedAccess: pickFirst(body.grantedAccess, body.granted_access, raw.grantedAccess, raw.granted_access),
    callTrace: pickFirst(body.callTrace, body.call_trace, raw.callTrace, raw.call_trace),
    attributionConfidence: pickFirst(body.attributionConfidence, body.attribution_confidence, raw.attributionConfidence, raw.attribution_confidence),
    inventoryType: pickFirst(body.inventoryType, body.inventory_type, raw.inventoryType, raw.inventory_type),
    inventoryName: pickFirst(body.inventoryName, body.inventory_name, raw.inventoryName, raw.inventory_name),
    inventoryCount: numberOrUndefined(body.inventoryCount, body.inventory_count, raw.inventoryCount, raw.inventory_count),
    inventorySnapshotId: pickFirst(body.inventorySnapshotId, body.inventory_snapshot_id, raw.inventorySnapshotId, raw.inventory_snapshot_id),
    inventoryBatchIndex: numberOrUndefined(body.inventoryBatchIndex, body.inventory_batch_index, raw.inventoryBatchIndex, raw.inventory_batch_index),
    inventoryBatchCount: numberOrUndefined(body.inventoryBatchCount, body.inventory_batch_count, raw.inventoryBatchCount, raw.inventory_batch_count),
    inventoryItems: pickFirst(body.inventoryItems, body.inventory_items, raw.inventoryItems, raw.inventory_items),
    inventoryItem: pickFirst(body.inventoryItem, body.inventory_item, raw.inventoryItem, raw.inventory_item),
    oldInventoryItem: pickFirst(body.oldInventoryItem, body.old_inventory_item, raw.oldInventoryItem, raw.old_inventory_item),
    changeType: pickFirst(body.changeType, body.change_type, raw.changeType, raw.change_type),
    persistenceType: pickFirst(body.persistenceType, body.persistence_type, raw.persistenceType, raw.persistence_type, body.inventory_type),
    persistenceLocation: pickFirst(body.persistenceLocation, body.persistence_location, raw.persistenceLocation, raw.persistence_location, body.location, raw.location),
    persistenceKey: pickFirst(body.persistenceKey, body.persistence_key, raw.persistenceKey, raw.persistence_key),
    persistenceValue: pickFirst(body.persistenceValue, body.persistence_value, raw.persistenceValue, raw.persistence_value),
    persistenceTrigger: pickFirst(body.persistenceTrigger, body.persistence_trigger, raw.persistenceTrigger, raw.persistence_trigger),
    persistenceAction: pickFirst(body.persistenceAction, body.persistence_action, raw.persistenceAction, raw.persistence_action),
    serviceName: pickFirst(body.serviceName, body.service_name, raw.serviceName, raw.service_name, body.inventory_type === 'service' ? body.inventory_name : undefined),
    serviceDisplayName: pickFirst(body.serviceDisplayName, body.service_display_name, raw.serviceDisplayName, raw.service_display_name),
    serviceEventType: pickFirst(body.serviceEventType, body.service_event_type, raw.serviceEventType, raw.service_event_type, /^SERVICE_/i.test(String(body.eventType || body.event_type || '')) ? body.eventType || body.event_type : undefined),
    servicePreviousStatus: pickFirst(body.servicePreviousStatus, body.previous_status, raw.servicePreviousStatus, raw.previous_status),
    serviceCurrentStatus: pickFirst(body.serviceCurrentStatus, body.current_status, raw.serviceCurrentStatus, raw.current_status),
    serviceStartupType: pickFirst(body.serviceStartupType, body.startup_type, raw.serviceStartupType, raw.startup_type),
    serviceAccount: pickFirst(body.serviceAccount, body.service_account, raw.serviceAccount, raw.service_account),
    serviceBinaryPath: pickFirst(body.serviceBinaryPath, body.service_binary_path, raw.serviceBinaryPath, raw.service_binary_path),
    serviceBinarySha256: pickFirst(body.serviceBinarySha256, body.service_binary_sha256, raw.serviceBinarySha256, raw.service_binary_sha256),
    serviceBinarySha1: pickFirst(body.serviceBinarySha1, body.service_binary_sha1, raw.serviceBinarySha1, raw.service_binary_sha1),
    serviceBinaryMd5: pickFirst(body.serviceBinaryMd5, body.service_binary_md5, raw.serviceBinaryMd5, raw.service_binary_md5),
    serviceSignatureStatus: pickFirst(body.serviceSignatureStatus, body.service_signature_status, raw.serviceSignatureStatus, raw.service_signature_status),
    servicePublisher: pickFirst(body.servicePublisher, body.service_publisher, raw.servicePublisher, raw.service_publisher),
    servicePackageOwner: pickFirst(body.servicePackageOwner, body.service_package_owner, raw.servicePackageOwner, raw.service_package_owner),
    servicePackageVerificationStatus: pickFirst(body.servicePackageVerificationStatus, body.service_package_verification_status, raw.servicePackageVerificationStatus, raw.service_package_verification_status),
    serviceDependencies: pickFirst(body.serviceDependencies, body.service_dependencies, raw.serviceDependencies, raw.service_dependencies),
    servicePid: numberOrUndefined(body.servicePid, body.service_pid, raw.servicePid, raw.service_pid),
    serviceRestartCount: numberOrUndefined(body.serviceRestartCount, body.service_restart_count, raw.serviceRestartCount, raw.service_restart_count),
    serviceUnitPath: pickFirst(body.serviceUnitPath, body.service_unit_path, raw.serviceUnitPath, raw.service_unit_path),
    serviceSecurityCritical: body.serviceSecurityCritical === true || body.security_service === true || raw.serviceSecurityCritical === true || raw.security_service === true,
    suspiciousServicePath: body.suspiciousServicePath === true || body.suspicious_service_path === true || raw.suspiciousServicePath === true || raw.suspicious_service_path === true,
    kernelEventType: pickFirst(body.kernelEventType, body.kernel_event_type, raw.kernelEventType, raw.kernel_event_type, body.eventType, body.event_type),
    kernelCategory: pickFirst(body.kernelCategory, body.kernel_category, raw.kernelCategory, raw.kernel_category),
    kernelVersion: pickFirst(body.kernelVersion, body.kernel_version, raw.kernelVersion, raw.kernel_version),
    driverName: pickFirst(body.driverName, body.driver_name, raw.driverName, raw.driver_name, body.moduleName, body.module_name),
    driverPath: pickFirst(body.driverPath, body.driver_path, raw.driverPath, raw.driver_path, body.modulePath, body.module_path),
    driverVersion: pickFirst(body.driverVersion, body.driver_version, raw.driverVersion, raw.driver_version),
    driverState: pickFirst(body.driverState, body.driver_state, raw.driverState, raw.driver_state),
    driverStartMode: pickFirst(body.driverStartMode, body.driver_start_mode, raw.driverStartMode, raw.driver_start_mode),
    moduleName: pickFirst(body.moduleName, body.module_name, raw.moduleName, raw.module_name, body.driverName, body.driver_name),
    modulePath: pickFirst(body.modulePath, body.module_path, raw.modulePath, raw.module_path, body.driverPath, body.driver_path),
    moduleSignature: pickFirst(body.moduleSignature, body.module_signature, raw.moduleSignature, raw.module_signature, body.signatureStatus, body.signature_status),
    moduleTaint: pickFirst(body.moduleTaint, body.module_taint, raw.moduleTaint, raw.module_taint),
    vulnerableDriver: body.vulnerableDriver === true || body.vulnerable_driver === true || raw.vulnerableDriver === true || raw.vulnerable_driver === true,
    syscallName: pickFirst(body.syscallName, body.syscall_name, raw.syscallName, raw.syscall_name),
    syscallCount: numberOrUndefined(body.syscallCount, body.syscall_count, raw.syscallCount, raw.syscall_count),
    callbackType: pickFirst(body.callbackType, body.callback_type, raw.callbackType, raw.callback_type),
    memoryProtection: pickFirst(body.memoryProtection, body.memory_protection, raw.memoryProtection, raw.memory_protection),
    secureBootStatus: pickFirst(body.secureBootStatus, body.secure_boot_status, raw.secureBootStatus, raw.secure_boot_status),
    codeIntegrityStatus: pickFirst(body.codeIntegrityStatus, body.code_integrity_status, raw.codeIntegrityStatus, raw.code_integrity_status),
    patchGuardStatus: pickFirst(body.patchGuardStatus, body.patch_guard_status, raw.patchGuardStatus, raw.patch_guard_status),
    kernelPosture: pickFirst(body.kernelPosture, body.kernel_posture, raw.kernelPosture, raw.kernel_posture),
    workloadType: pickFirst(body.workloadType, body.workload_type, raw.workloadType, raw.workload_type),
    workloadCounts: pickFirst(body.workloadCounts, body.workload_counts, raw.workloadCounts, raw.workload_counts),
    listenerPorts: pickFirst(body.listenerPorts, body.listener_ports, raw.listenerPorts, raw.listener_ports),
    runtimeType: pickFirst(body.runtimeType, body.runtime_type, raw.runtimeType, raw.runtime_type),
    containerId: pickFirst(body.containerId, body.container_id, raw.containerId, raw.container_id),
    podName: pickFirst(body.podName, body.pod_name, raw.podName, raw.pod_name),
    namespace: pickFirst(body.namespace, raw.namespace),
    containerRisks: pickFirst(body.containerRisks, body.container_risks, raw.containerRisks, raw.container_risks),
    recommendedAction: pickFirst(body.recommendedAction, body.recommended_action, raw.recommendedAction, raw.recommended_action),
    mitreId: pickFirst(body.mitreId, body.mitre_id, body.attackId, body.attack_id, raw.mitreId, raw.mitre_id),
    technique: pickFirst(body.technique, body.persistenceTechnique, body.persistence_technique, raw.technique),
    mitreTechnique: pickFirst(body.mitreTechnique, body.mitre_technique, body.technique, raw.mitreTechnique, raw.mitre_technique, raw.technique),
    mitreTactic: pickFirst(body.mitreTactic, body.mitre_tactic, raw.mitreTactic, raw.mitre_tactic),
    mitreTechniques: pickFirst(body.mitreTechniques, body.mitre_techniques, raw.mitreTechniques, raw.mitre_techniques),
    domain: pickFirst(body.domain, body.query, body.dnsQuery, body.dns_query, raw.domain, raw.query, raw.dnsQuery, raw.dns_query),
    destinationIps: Array.isArray(body.destinationIps || body.destination_ips || raw.destinationIps || raw.destination_ips || raw.answer_ips)
      ? (body.destinationIps || body.destination_ips || raw.destinationIps || raw.destination_ips || raw.answer_ips).filter(Boolean).slice(0, 100)
      : [],
    queryType: pickFirst(body.queryType, body.query_type, raw.queryType, raw.query_type, raw.record_type),
    responseCode: pickFirst(body.responseCode, body.response_code, raw.responseCode, raw.response_code),
    responseType: pickFirst(body.responseType, body.response_type, raw.responseType, raw.response_type),
    responseIp: pickFirst(body.responseIp, body.response_ip, body.answerIp, body.answer_ip, raw.responseIp, raw.response_ip, raw.answerIp, raw.answer_ip),
    expectedIp: pickFirst(body.expectedIp, body.expected_ip, body.knownGoodIp, body.known_good_ip, raw.expectedIp, raw.expected_ip, raw.knownGoodIp, raw.known_good_ip),
    detectionType: pickFirst(body.detectionType, body.detection_type, body.eventType, body.event_type, raw.detectionType, raw.detection_type),
    detectionEvidence: pickFirst(body.detectionEvidence, body.detection_evidence, body.evidence, raw.detectionEvidence, raw.detection_evidence, raw.evidence),
    detectionReason: pickFirst(body.detectionReason, body.detection_reason, body.reason, raw.detectionReason, raw.detection_reason, raw.reason),
    detectionRuleId: pickFirst(body.detectionRuleId, body.detection_rule_id, raw.detectionRuleId, raw.detection_rule_id),
    sinkholeIp: pickFirst(body.sinkholeIp, body.sinkhole_ip, raw.sinkholeIp, raw.sinkhole_ip, raw.ip),
    threatCategory: pickFirst(body.threatCategory, body.threat_category, raw.threatCategory, raw.threat_category, raw.reason),
    iocMatched: body.iocMatched === true || body.ioc_matched === true || raw.iocMatched === true || raw.ioc_matched === true,
    reputationScore: numberOrUndefined(body.reputationScore, body.reputation_score, raw.reputationScore, raw.reputation_score),
    confidenceScore: numberOrUndefined(body.confidenceScore, body.confidence_score, raw.confidenceScore, raw.confidence_score),
    ttl: numberOrUndefined(body.ttl, body.newTtl, body.new_ttl, raw.ttl, raw.newTtl, raw.new_ttl),
    previousTtl: numberOrUndefined(body.previousTtl, body.previous_ttl, body.oldTtl, body.old_ttl, raw.previousTtl, raw.previous_ttl, raw.oldTtl, raw.old_ttl),
    connectionCount: numberOrUndefined(body.connectionCount, body.connection_count, raw.connectionCount, raw.connection_count),
    retryCount: numberOrUndefined(body.retryCount, body.retry_count, raw.retryCount, raw.retry_count),
    averageInterval: numberOrUndefined(body.averageInterval, body.average_interval, raw.averageInterval, raw.average_interval),
    medianInterval: numberOrUndefined(body.medianInterval, body.median_interval, raw.medianInterval, raw.median_interval),
    jitterSeconds: numberOrUndefined(body.jitterSeconds, body.jitter_seconds, raw.jitterSeconds, raw.jitter_seconds),
    intervalConsistency: numberOrUndefined(body.intervalConsistency, body.interval_consistency, raw.intervalConsistency, raw.interval_consistency),
    periodicityScore: numberOrUndefined(body.periodicityScore, body.periodicity_score, raw.periodicityScore, raw.periodicity_score),
    observationSeconds: numberOrUndefined(body.observationSeconds, body.observation_seconds, raw.observationSeconds, raw.observation_seconds),
    bytesSent: numberOrUndefined(body.bytesSent, body.bytes_sent, raw.bytesSent, raw.bytes_sent),
    bytesReceived: numberOrUndefined(body.bytesReceived, body.bytes_received, raw.bytesReceived, raw.bytes_received),
    entropy: numberOrUndefined(body.entropy, raw.entropy),
    affectedFiles: numberOrUndefined(body.affectedFiles, body.affected_files, raw.affectedFiles, raw.affected_files),
    affectedDirectory: pickFirst(body.affectedDirectory, body.affected_directory, raw.affectedDirectory, raw.affected_directory),
    extension: pickFirst(body.extension, raw.extension),
    encryptionSpeed: numberOrUndefined(body.encryptionSpeed, body.encryption_speed, raw.encryptionSpeed, raw.encryption_speed),
    modifiedFilesPerSecond: numberOrUndefined(body.modifiedFilesPerSecond, body.modified_files_per_second, raw.modifiedFilesPerSecond, raw.modified_files_per_second),
    deletedFilesPerSecond: numberOrUndefined(body.deletedFilesPerSecond, body.deleted_files_per_second, raw.deletedFilesPerSecond, raw.deleted_files_per_second),
    renamedFilesPerSecond: numberOrUndefined(body.renamedFilesPerSecond, body.renamed_files_per_second, raw.renamedFilesPerSecond, raw.renamed_files_per_second),
    memoryMetricType: pickFirst(body.memoryMetricType, body.memory_metric_type, raw.memoryMetricType, raw.memory_metric_type),
    memoryTotalBytes: numberOrUndefined(body.memoryTotalBytes, body.memory_total_bytes, raw.memoryTotalBytes, raw.memory_total_bytes),
    memoryUsedBytes: numberOrUndefined(body.memoryUsedBytes, body.memory_used_bytes, raw.memoryUsedBytes, raw.memory_used_bytes),
    memoryAvailableBytes: numberOrUndefined(body.memoryAvailableBytes, body.memory_available_bytes, raw.memoryAvailableBytes, raw.memory_available_bytes),
    commitChargeBytes: numberOrUndefined(body.commitChargeBytes, body.commit_charge_bytes, raw.commitChargeBytes, raw.commit_charge_bytes),
    memoryPressure: numberOrUndefined(body.memoryPressure, body.memory_pressure, raw.memoryPressure, raw.memory_pressure),
    swapTotalBytes: numberOrUndefined(body.swapTotalBytes, body.swap_total_bytes, raw.swapTotalBytes, raw.swap_total_bytes),
    swapUsedBytes: numberOrUndefined(body.swapUsedBytes, body.swap_used_bytes, raw.swapUsedBytes, raw.swap_used_bytes),
    swapPercent: numberOrUndefined(body.swapPercent, body.swap_percent, raw.swapPercent, raw.swap_percent),
    pageFaults: numberOrUndefined(body.pageFaults, body.page_faults, raw.pageFaults, raw.page_faults),
    majorPageFaults: numberOrUndefined(body.majorPageFaults, body.major_page_faults, raw.majorPageFaults, raw.major_page_faults),
    pagingRate: numberOrUndefined(body.pagingRate, body.paging_rate, raw.pagingRate, raw.paging_rate),
    oomEvents: numberOrUndefined(body.oomEvents, body.oom_events, raw.oomEvents, raw.oom_events),
    containerMemoryBytes: numberOrUndefined(body.containerMemoryBytes, body.container_memory_bytes, raw.containerMemoryBytes, raw.container_memory_bytes),
    containerMemoryLimitBytes: numberOrUndefined(body.containerMemoryLimitBytes, body.container_memory_limit_bytes, raw.containerMemoryLimitBytes, raw.container_memory_limit_bytes),
    containerOomEvents: numberOrUndefined(body.containerOomEvents, body.container_oom_events, raw.containerOomEvents, raw.container_oom_events),
    processRssBytes: numberOrUndefined(body.processRssBytes, body.process_rss_bytes, raw.processRssBytes, raw.process_rss_bytes),
    virtualMemoryBytes: numberOrUndefined(body.virtualMemoryBytes, body.virtual_memory_bytes, raw.virtualMemoryBytes, raw.virtual_memory_bytes),
    privateWorkingSetBytes: numberOrUndefined(body.privateWorkingSetBytes, body.private_working_set_bytes, raw.privateWorkingSetBytes, raw.private_working_set_bytes),
    sharedMemoryBytes: numberOrUndefined(body.sharedMemoryBytes, body.shared_memory_bytes, raw.sharedMemoryBytes, raw.shared_memory_bytes),
    peakMemoryBytes: numberOrUndefined(body.peakMemoryBytes, body.peak_memory_bytes, raw.peakMemoryBytes, raw.peak_memory_bytes),
    memoryGrowthBytes: numberOrUndefined(body.memoryGrowthBytes, body.memory_growth_bytes, raw.memoryGrowthBytes, raw.memory_growth_bytes),
    memoryGrowthPercent: numberOrUndefined(body.memoryGrowthPercent, body.memory_growth_percent, raw.memoryGrowthPercent, raw.memory_growth_percent),
    memoryAllocationRate: numberOrUndefined(body.memoryAllocationRate, body.memory_allocation_rate, raw.memoryAllocationRate, raw.memory_allocation_rate),
    threadCount: numberOrUndefined(body.threadCount, body.thread_count, raw.threadCount, raw.thread_count),
    handleCount: numberOrUndefined(body.handleCount, body.handle_count, raw.handleCount, raw.handle_count),
    crashCount: numberOrUndefined(body.crashCount, body.crash_count, raw.crashCount, raw.crash_count),
    restartCount: numberOrUndefined(body.restartCount, body.restart_count, raw.restartCount, raw.restart_count),
    executableRegionCount: numberOrUndefined(body.executableRegionCount, body.executable_region_count, raw.executableRegionCount, raw.executable_region_count),
    rwxRegionCount: numberOrUndefined(body.rwxRegionCount, body.rwx_region_count, raw.rwxRegionCount, raw.rwx_region_count),
    actionable: body.actionable === true || raw.actionable === true,
    isSimulated: body.isSimulated === true || body.is_simulated === true || raw.isSimulated === true || raw.is_simulated === true,
    ...(status && { status }),
  };
}

function isFimEvent({ ruleId = '', source = '', eventCategory = '', filePath = '', body = {} } = {}) {
  return eventCategory === 'file'
    || /^FILE_/i.test(ruleId)
    || String(source || '').toLowerCase() === 'file_watch'
    || Boolean(filePath)
    || Boolean(body.file_path || body.filePath || body.file_action || body.fileAction);
}

function isPreInstallFimEvent(system, eventCategory, ruleId, source, filePath, body, createdAt) {
  const baseline = system?.fimStartAt || system?.installDate || system?.createdAt || new Date();
  if (!baseline) return false;
  if (!isFimEvent({ ruleId, source, eventCategory, filePath, body })) return false;
  return createdAt < new Date(baseline);
}

// ── Category mapper ───────────────────────────────────────────────────────────
function toCategory(ruleId, source, description) {
  const r = (ruleId  || '').toLowerCase();
  const s = (source  || '').toLowerCase();
  const d = (description || '').toLowerCase();

  if (s === 'registry_monitor' || /(?:^|_)registry_(?:new|modified|change|persistence)/.test(r)
      || /\b(?:windows\s+registry|registry\s+(?:key|value|change|modified|persistence)|regedit|hklm|hkcu|hkcr|hku|runonce?\s+key)\b/.test(d)) return 'registry';

  if (r.includes('memory') || r.includes('persistence') ||
      r.includes('system_change') || r.includes('sys_change') || r.includes('config') ||
      r.includes('scheduled_task') || r.includes('service') || r.includes('driver')) return 'system';

  if (r.includes('yara') || r.includes('malware') || r.includes('ransomware') ||
      r.includes('miner') || r.includes('trojan') || r.includes('backdoor') ||
      s === 'yara' || d.includes('yara match') || d.includes('malware')) return 'malware';

  if (r.includes('net') || r.includes('port_scan') || r.includes('ddos') ||
      r.includes('connection') || s === 'network' ||
      d.includes('suspicious outbound') || d.includes('malicious ip')) return 'network';

  if (r.includes('file') || s === 'file_watch') return 'file';

  if (r.includes('auth') || r.includes('brute') || r.includes('login') ||
      r.includes('edr') || r.includes('priv_esc') || r.includes('new_user') ||
      s === 'edr' || d.includes('authentication') || d.includes('privilege')) return 'edr';

  if (r.includes('usb') || s === 'usb' || d.includes('usb device')) return 'usb';

  if (r.includes('isolat') || r.includes('quarant')) return 'isolation';

  if (r.includes('proc') || r.includes('system') || r.includes('service') ||
      r.includes('anomaly') || s === 'syslog' || s === 'windows_event_log' ||
      s === 'macos_unified_log') return 'system';

  return 'other';
}

/**
 * SOC-grade numeric rule level → severity mapper
 *
 * Level 0–6   → low      (informational, routine events)
 * Level 7–11  → medium   (suspicious, needs investigation)
 * Level 12–14 → high     (active threat, confirmed attack pattern)
 * Level 15+   → critical (active exploitation, confirmed breach)
 */
function mapSeverity(level) {
  const lvl = Number(level) || 0;
  if (lvl >= 15) return 'critical'; // Active exploitation / confirmed breach
  if (lvl >= 12) return 'high';     // Confirmed attack pattern
  if (lvl >= 7)  return 'medium';   // Suspicious / needs investigation
  return 'low';                      // Informational / routine
}

async function autoIsolateGeoFence(req, systemId, reason) {
  if (!systemId) return;
  const system = await System.findByIdAndUpdate(
    systemId,
    {
      isIsolated: true,
      isolatedAt: new Date(),
      isolationReason: reason,
      geoFenceLastViolationAt: new Date(),
      status: 'active',
    },
    { new: true }
  );
  if (!system) return;
  const io = req.app?.get?.('io');
  if (io) {
    io.to(`system_${system._id}`).emit('agent:command', {
      command: 'isolate',
      systemId: String(system._id),
      reason,
    });
    io.to(`company:${system.companyId}`).emit('system:isolated', {
      systemId: system._id,
      systemName: system.name,
      isIsolated: true,
      isolatedAt: system.isolatedAt,
      reason,
    });
  }
}

/**
 * MASTER VT RULESET (Rules 1–3, 7)
 * Returns { severity, eventCategory, vtVerdict, underObservation, description }
 * VT=0/N        → clean,       severity=low,    not malware
 * VT=1–5/N      → suspicious,  severity=medium, not malware (yet)
 * VT>5/N        → malicious,   severity=high+,  malware confirmed
 * VT missing    → under_observation, tag = "Threat Intel Missing"
 * VT not_found  → unknown,     severity unchanged, tag = "Threat Intel Missing"
 */
function applyVtRules(vtRaw, currentCategory, currentSeverity, currentDescription) {
  const sevOrder = { low: 0, medium: 1, high: 2, critical: 3 };

  // No VT data at all — Rule 2 / Rule 9
  if (!vtRaw || typeof vtRaw !== 'object') {
    const isFileMalware = (currentCategory === 'malware');
    return {
      severity:         currentSeverity,
      eventCategory:    currentCategory,
      vtVerdict:        null,
      underObservation: isFileMalware,   // Rule 9: low confidence → Under Observation
      description:      isFileMalware
        ? (currentDescription || '') + ' [UNDER OBSERVATION — Threat Intel Missing]'
        : currentDescription,
      vtIntelMissing:   isFileMalware,
    };
  }

  const detections   = (vtRaw.malicious  || 0) + (vtRaw.suspicious || 0);
  const total        = vtRaw.total        || vtRaw.total_engines   || 0;
  const score        = vtRaw.score        || 0;

  // VT not in database (0 engines responded) — Rule 2
  if (total === 0) {
    return {
      severity:         currentSeverity,
      eventCategory:    currentCategory,
      vtVerdict:        'not_found',
      underObservation: currentCategory === 'malware',
      description:      (currentDescription || '') + ' [UNDER OBSERVATION — Threat Intel Missing]',
      vtIntelMissing:   true,
    };
  }

  // VT = 0/N → CLEAN — Rule 1
  if (detections === 0) {
    return {
      severity:         'low',
      eventCategory:    currentCategory === 'malware' ? 'file' : currentCategory,  // Rule 3
      vtVerdict:        'clean',
      underObservation: false,
      description:      currentDescription,
      vtIntelMissing:   false,
    };
  }

  // VT 1–5 engines → SUSPICIOUS / Medium — Rule 1
  if (detections <= 5) {
    const newSev = (sevOrder[currentSeverity] || 0) < sevOrder.medium ? 'medium' : currentSeverity;
    return {
      severity:         newSev,
      eventCategory:    currentCategory,
      vtVerdict:        'suspicious',
      underObservation: false,
      description:      currentDescription,
      vtIntelMissing:   false,
    };
  }

  // VT > 5 engines → MALWARE — Rule 1
  const newSev = score >= 70 ? 'critical' : score >= 40 ? 'high' : 'high';
  const finalSev = (sevOrder[newSev] || 0) > (sevOrder[currentSeverity] || 0) ? newSev : currentSeverity;
  return {
    severity:         finalSev,
    eventCategory:    'malware',
    vtVerdict:        'malicious',
    underObservation: false,
    description:      currentDescription,
    vtIntelMissing:   false,
  };
}


async function autoAssignNewAlert(alert) {
  try {
    const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
    const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
    const SocShift = require('../models/SocShift.model');
    const User = require('../models/User.model');

    const companyId = alert.companyId;
    if (!companyId) return;

    // 1. Get all active SOC assignments for this company
    const candidates = await SocCompanyAssignment.find({ companyId, active: true }).distinct('userId');
    if (!candidates || candidates.length === 0) return;

    // 2. Restrict assignment to the analysts who are currently on duty.
    // Companies without shift configuration keep the legacy workload fallback.
    const configuredShifts = await SocShift.find({ companyId, active: true })
      .select('timezone startTime endTime weekdays analystIds').lean();
    const onShiftIds = new Set(configuredShifts
      .filter(shift => isShiftActiveAt(shift))
      .flatMap(shift => shift.analystIds || []).map(String));
    if (configuredShifts.length && !onShiftIds.size) return;
    const eligibleCandidates = configuredShifts.length
      ? candidates.filter(id => onShiftIds.has(String(id)))
      : candidates;

    const requiredRole = alert.severity === 'critical'
      ? 'l3_analyst'
      : alert.severity === 'high'
        ? 'l2_analyst'
        : 'l1_analyst';
    let analysts = await User.find({
      _id: { $in: eligibleCandidates },
      role: requiredRole,
      isActive: true,
      accountStatus: 'active',
    }).select('_id departmentId departmentIds').lean();

    // A department alert must stay with an analyst assigned to that department.
    if (alert.departmentId) {
      const departmentAssignments = new Set((await SocDepartmentAssignment.find({
        companyId, departmentId: alert.departmentId, active: true,
      }).distinct('userId')).map(String));
      analysts = analysts.filter(user => departmentAssignments.has(String(user._id))
        || String(user.departmentId || '') === String(alert.departmentId)
        || (user.departmentIds || []).some(id => String(id) === String(alert.departmentId)));
    }

    if (!analysts || analysts.length === 0) return;

    const ids = analysts.map(u => u._id);

    // 3. Find workload for each analyst (open or investigating alerts)
    const loads = await require('../models/Alert.model').aggregate([
      { $match: { assignedTo: { $in: ids }, status: { $in: ['open', 'investigating'] } } },
      { $group: { _id: '$assignedTo', count: { $sum: 1 } } }
    ]);

    const workloadMap = {};
    for (const id of ids) {
      workloadMap[String(id)] = 0;
    }
    for (const load of loads) {
      workloadMap[String(load._id)] = load.count;
    }

    // 4. Sort analyst IDs by workload (ascending)
    const sortedAnalysts = ids.sort((a, b) => workloadMap[String(a)] - workloadMap[String(b)]);
    const assignedAnalystId = sortedAnalysts[0];

    if (assignedAnalystId) {
      alert.assignedTo = assignedAnalystId;
      if (alert.status === 'open') {
        alert.status = 'investigating';
      }
      await alert.save();
      console.log(`[Auto-Assignment] ${alert.severity} alert ${alert._id} auto-assigned to ${requiredRole} ${assignedAnalystId}`);
    }
  } catch (err) {
    console.error('[autoAssignNewAlert error]', err.message);
  }
}


// ── POST /api/alerts — from SOC Agent (no JWT) ────────────────────────────────
router.post('/', async (req, res) => {
  const secret   = req.headers['x-integration-secret'];
  const agentKey = req.body.agent_key || req.body.agentKey;

  const signedAuth = await verifySignedAgentRequest(req, { agentKey });
  let system = signedAuth.ok ? signedAuth.system : null;
  if (!system && agentKey) system = await System.findOne({ agentKey });
  const hasLegacySecret = Boolean(
    system && secret && secret === process.env.INTEGRATION_SECRET
  );
  const authorized = signedAuth.ok || hasLegacySecret;
  if (!authorized) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const body = req.body;

    const scope = await resolveScope({
      system,
      companyId: body.company_id || body.companyId,
      body,
      requireSystem: Boolean(agentKey),
    });

    const companyId    = scope.companyId;
    const tenantId     = scope.tenantId;
    const partnerId    = scope.partnerId;
    const departmentId = scope.departmentId;
    const systemId     = scope.systemId;
    const eventId      = body.event_id || body.eventId || req.headers['idempotency-key'];

    if (!companyId) return res.status(400).json({ message: 'company_id required' });
    if (eventId) {
      const duplicate = await Alert.findOne({ companyId, eventId }).select('_id').lean();
      if (duplicate) {
        return res.status(200).json({ ok: true, duplicate: true, alertId: duplicate._id });
      }
    }
    const ingestionStatus = await getCompanyIngestionStatus(companyId);
    if (!ingestionStatus.allowed) return sendIngestionBlocked(res, ingestionStatus);

    // Map agent field names → model field names
    // BUG FIX: ruleId must be the string rule name (e.g. 'YARA_MATCH'), NOT the numeric level
    const ruleId      = body.rule_id    || body.ruleId    || body.type || '';
    const description = body.description;
    const source      = body.log_source || body.source    || '';
    const severity    = body.severity   || mapSeverity(body.ruleLevel || body.rule_level || 0);

    // Use body.category directly if provided by agent (exact category), else derive from ruleId
    const eventCategory = normalizeEventCategory(body.category, toCategory(ruleId, source, description));

    // File fields — agent sends snake_case
    const filePath    = body.file_path || body.filePath || body.script_path || body.scriptPath;
    enrichFimPermissionFields(body, ruleId);
    const fimHashes   = enrichFimHashFields(body);
    const fileHash    = body.script_hash || body.scriptHash || fimHashes.fileHash;
    const fileHashMd5 = body.script_md5 || body.scriptMd5 || fimHashes.fileHashMd5;
    const fileName    = body.file_name || body.fileName || body.script_name || body.scriptName
                        || (filePath ? filePath.split(/[\\/]/).pop() : undefined);
    const createdAt   = eventDateFromBody(body);
    if (isPreInstallFimEvent(system, eventCategory, ruleId, source, filePath, body, createdAt)) {
      return res.status(202).json({
        ok: true,
        ignored: true,
        reason: 'pre_install_fim_event',
        installDate: system.installDate,
      });
    }

    // Network fields
    const srcip    = body.src_ip    || body.srcip;
    const destip   = body.dst_ip    || body.dest_ip  || body.destip   || body.destIp   || undefined;
    const destPort = body.dst_port  || body.destPort || body.port;

    // Domain field — explicit or parsed from description ("domain:youtube.com" pattern)
    let domain = body.domain || body.tiDomain || undefined;
    if (!domain) {
      const descRaw = body.description || body.raw_log || '';
      const domMatch = descRaw.match(/\bdomain[:\s]+([a-z0-9._\-]+\.[a-z]{2,})/i);
      if (domMatch) domain = domMatch[1];
    }

    // DNS / Web fields
    const queryType = body.query_type || body.queryType || body.record_type || undefined;

    // USB device identifier
    const device = body.device || body.device_name;

    // YARA rules array
    const yaraRules = body.yara_rules || body.yaraRules;

    // Malware type — prefer explicit, then infer from rule_id
    let malwareType = body.malwareType || body.malware_type;
    if (!malwareType && eventCategory === 'malware') {
      const rid = ruleId.toLowerCase();
      if      (rid.includes('ransomware') || rid.includes('ransom') || rid.includes('shadow')) malwareType = 'Ransomware';
      else if (rid.includes('trojan'))                                                          malwareType = 'Trojan';
      else if (rid.includes('miner')  || rid.includes('coin'))                                 malwareType = 'Miner';
      else if (rid.includes('worm'))                                                            malwareType = 'Worm';
      else if (rid.includes('backdoor') || rid.includes('shell'))                              malwareType = 'Backdoor';
      else if (rid.includes('mimikatz') || rid.includes('credential'))                        malwareType = 'Credential Dumper';
      else if (rid.includes('lolbin'))                                                          malwareType = 'LolBin';
      else                                                                                      malwareType = 'Generic';
    }

    // ── Extract pre-enriched VT data from agent ────────────────────────────────
    // Agent may send any of these field names depending on version:
    //   virustotal.score, .detections, .malicious, .total, .total_engines,
    //   .verdict, .detection_ratio, .engines, .engines_triggered
    let vtScore = undefined, vtDetections = undefined, vtTotal = undefined;
    let vtDetectionRatio = undefined, vtVerdict = undefined, vtEngines = undefined;
    const vtRaw = body.virustotal || body.vt;
    if (vtRaw && typeof vtRaw === 'object') {
      vtScore      = vtRaw.score          != null ? Number(vtRaw.score)     : undefined;
      vtDetections = (vtRaw.detections    != null ? Number(vtRaw.detections)
                    : vtRaw.malicious     != null ? Number(vtRaw.malicious)
                    : undefined);
      vtTotal      = (vtRaw.total         != null ? Number(vtRaw.total)
                    : vtRaw.total_engines != null ? Number(vtRaw.total_engines)
                    : undefined);
      vtDetectionRatio = vtRaw.detection_ratio || vtRaw.ratio || undefined;
      vtEngines        = vtRaw.engines_triggered || vtRaw.engines || undefined;

      // Correct verdict derivation (Rule 1)
      if (vtRaw.verdict) {
        vtVerdict = vtRaw.verdict;
      } else if (vtTotal === 0 || vtTotal == null) {
        vtVerdict = 'not_found';
      } else if ((vtDetections || 0) === 0) {
        vtVerdict = 'clean';
      } else if ((vtScore || 0) >= 40) {
        vtVerdict = 'malicious';
      } else {
        vtVerdict = 'suspicious';
      }

      if (!vtDetectionRatio && vtDetections != null && vtTotal != null) {
        vtDetectionRatio = `${vtDetections}/${vtTotal}`;
      }
    }
    if (vtScore == null && body.vt_score    != null) vtScore          = Number(body.vt_score);
    if (!vtVerdict      && body.vt_verdict)           vtVerdict        = body.vt_verdict;
    if (!vtDetectionRatio && body.vt_detections)      vtDetectionRatio = String(body.vt_detections);

    // ── Apply Master VT Ruleset (Rules 1-3, 7, 9) ─────────────────────────────
    const vtApplied = applyVtRules(vtRaw, eventCategory, severity, description);
    const finalCategory    = vtApplied.eventCategory;
    const finalSeverity    = vtApplied.severity;
    const finalDescription = vtApplied.description;
    const underObservation = vtApplied.underObservation;
    if (vtApplied.vtVerdict && !vtVerdict) vtVerdict = vtApplied.vtVerdict;
    // Override saved vtVerdict if VT data forces clean
    if (vtApplied.vtVerdict === 'clean') vtVerdict = 'clean';

    if (/^GEO_/i.test(ruleId) && !(await hasActiveGeoPolicy(companyId))) {
      return res.status(202).json({ ok: true, suppressed: true, reason: 'No active geolocation policy' });
    }
    if (['GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS'].includes(ruleId)) {
      const accuracyLimit = await activeGpsPolicyAccuracyLimit(companyId, systemId);
      if (accuracyLimit === null) {
        return res.status(202).json({ ok: true, suppressed: true, reason: 'No active GPS policy for this system' });
      }
      const reportedAccuracy = numberOrUndefined(body.gpsAccuracyMeters, body.gps_accuracy_meters);
      if (ruleId === 'GPS_LOCATION_TELEMETRY'
        && (!Number.isFinite(reportedAccuracy) || reportedAccuracy < 0 || reportedAccuracy > accuracyLimit)) {
        return res.status(202).json({ ok: true, suppressed: true, reason: `GPS accuracy must be within ${accuracyLimit} metres` });
      }
    }
    const normalizedTelemetry = normalizeCapabilityTelemetry(body, system);
    const uebaTelemetry = normalizeUebaTelemetry(body, system);
    const emailTelemetry = normalizeEmailTelemetry(body);
    const lateralTelemetry = normalizeLateralTelemetry(body);
    const credentialTelemetry = normalizeCredentialTelemetry(body);
    const dataSecurityTelemetry = normalizeDataSecurityTelemetry(body);
    const hashSignatureTelemetry = await enrichHashSignatureEvent({
      ...body,
      filePath,
      fileHash,
      fileHashMd5,
      vtVerdict,
    }, {
      tenantId,
      companyId,
      departmentId,
      endpointId: normalizedTelemetry.endpointId,
      filePath: filePath || normalizedTelemetry.processExe,
      fileName,
      observedAt: createdAt,
    });
    const hashSeverity = hashSignatureTelemetry.hashSignatureAlertEligible
      ? hashSignatureTelemetry.hashSignatureSeverity
      : finalSeverity;
    const inferredModule = inferSecurityModule(body, finalCategory);
    const normalizedSecurity = normalizeSecurityEvent({ ...body, module: body.module || inferredModule });
    const idsIpsTelemetry = {
      module: body.module || inferredModule,
      source_type: body.source_type,
      event_category: body.event_category,
      attackType: body.attackType || body.attack_type,
      signatureName: body.signatureName || body.signature_name,
      packetCount: numberOrUndefined(body.packetCount, body.packet_count),
    };

    const alertData = {
      tenantId, partnerId, companyId, departmentId, systemId, eventId,
      agentId:   (body.agent_key || '').slice(0, 8) || body.agentId,
      agentName: body.system_name || system?.name || body.agentName,
      ...normalizedTelemetry,
      ...uebaTelemetry,
      ...emailTelemetry,
      ...lateralTelemetry,
      ...credentialTelemetry,
      ...dataSecurityTelemetry,
      ...normalizedSecurity,
      ...hashSignatureTelemetry,
      ruleId:    ruleId,
      ruleLevel: body.ruleLevel || body.rule_level,
      description: finalDescription,
      full_log:  body.raw_log  || body.full_log,
      source,
      type:      ruleId,
      eventCategory: finalCategory,
      subCategory: body.subCategory || body.sub_category || (body.category && body.category !== eventCategory ? body.category : undefined),
      severity:      higherSeverity(higherSeverity(finalSeverity, hashSeverity), (normalizedTelemetry.systemChangeCategory || normalizedTelemetry.configurationCategory) ? severityFromRisk(normalizedTelemetry.riskScore) : 'low'),
      // Rule 8: standard logging fields
      srcip,
      sourcePort: numberOrUndefined(body.sourcePort, body.srcPort, body.src_port),
      srcPort: numberOrUndefined(body.srcPort, body.src_port, body.sourcePort),
      destip,
      destPort,
      port:      destPort,
      domain,
      normalizedDomain: domain ? String(domain).trim().toLowerCase().replace(/\.$/, '') : undefined,
      url: pickFirst(body.url, body.targetUrl, body.target_url, body.raw?.url),
      httpMethod: pickFirst(body.httpMethod, body.http_method, body.requestMethod, body.request_method, body.raw?.http_method),
      requestPath: pickFirst(body.requestPath, body.request_path, body.path, body.raw?.requestPath, body.raw?.request_path),
      statusCode: numberOrUndefined(body.statusCode, body.status_code, body.httpStatusCode, body.responseStatus, body.raw?.status_code),
      apiVersion: pickFirst(body.apiVersion, body.api_version, body.raw?.api_version),
      responseTime: numberOrUndefined(body.responseTime, body.response_time, body.raw?.response_time),
      requestSize: numberOrUndefined(body.requestSize, body.request_size, body.raw?.request_size),
      responseSize: numberOrUndefined(body.responseSize, body.response_size, body.raw?.response_size),
      authType: pickFirst(body.authType, body.auth_type, body.authMethod, body.auth_method, body.raw?.auth_type, body.raw?.auth_method),
      wafProvider: pickFirst(body.wafProvider, body.waf_provider, body.provider, body.raw?.waf_provider),
      wafRuleId: pickFirst(body.wafRuleId, body.waf_rule_id, body.raw?.waf_rule_id, body.rule_id),
      wafRuleName: pickFirst(body.wafRuleName, body.waf_rule_name, body.raw?.waf_rule_name),
      matchedSignature: pickFirst(body.matchedSignature, body.matched_signature, body.matched, body.raw?.matched),
      backendService: pickFirst(body.backendService, body.backend_service, body.raw?.backend_service),
      backendError: pickFirst(body.backendError, body.backend_error, body.raw?.backend_error),
      browser: pickFirst(body.browser, body.raw?.browser),
      userAgent: pickFirst(body.userAgent, body.user_agent, body.raw?.user_agent),
      referrer: pickFirst(body.referrer, body.referer, body.raw?.referrer, body.raw?.referer),
      tlsVersion: pickFirst(body.tlsVersion, body.tls_version, body.raw?.tls_version),
      certificateInfo: pickFirst(body.certificateInfo, body.certificate_info, body.raw?.certificate_info),
      resolver: pickFirst(body.resolver, body.dnsServer, body.dns_server, body.raw?.resolver, body.raw?.dns_server),
      queryTime: numberOrUndefined(body.queryTime, body.query_time, body.raw?.query_time),
      queryType,
      protocol:  body.protocol,
      connectionId: body.connectionId || body.connection_id,
      connectionState: body.connectionState || body.connection_state || body.state,
      connectionStartTime: body.connectionStartTime || body.connection_start_time,
      connectionEndTime: body.connectionEndTime || body.connection_end_time,
      connectionDuration: numberOrUndefined(body.connectionDuration, body.connection_duration, body.duration),
      networkInterface: body.networkInterface || body.network_interface || body.interface,
      networkAdapter: body.networkAdapter || body.network_adapter,
      ipVersion: numberOrUndefined(body.ipVersion, body.ip_version),
      bytesSent: numberOrUndefined(body.bytesSent, body.bytes_sent),
      bytesReceived: numberOrUndefined(body.bytesReceived, body.bytes_received),
      direction: body.inbound !== undefined ? (body.inbound ? 'inbound' : 'outbound') : undefined,
      inbound:   body.inbound,
      blocked:   body.blocked   || false,
      geoCountry: body.geoCountry || body.geo_country,
      geoCountryCode: body.geoCountryCode || body.geo_country_code || body.geoCountry || body.geo_country,
      geoCity:    body.geoCity    || body.geo_city,
      geoRegion:  body.geoRegion  || body.geo_region,
      geoTimezone: body.geoTimezone || body.geo_timezone,
      geoISP:     body.geoISP     || body.geo_isp,
      geoLat:     body.geoLat     || body.geo_lat,
      geoLon:     body.geoLon     || body.geo_lon,
      gpsLat:     numberOrUndefined(body.gpsLat, body.gps_lat),
      gpsLon:     numberOrUndefined(body.gpsLon, body.gps_lon),
      gpsAccuracyMeters: numberOrUndefined(body.gpsAccuracyMeters, body.gps_accuracy_meters),
      gpsAltitudeMeters: numberOrUndefined(body.gpsAltitudeMeters, body.gps_altitude_meters),
      gpsProvider: pickFirst(body.gpsProvider, body.gps_provider),
      gpsStatus: pickFirst(body.gpsStatus, body.gps_status),
      gpsReason: pickFirst(body.gpsReason, body.gps_reason),
      gpsObservedAt: processCreateDate(pickFirst(body.gpsObservedAt, body.gps_observed_at)),
      geoProxy:   body.geoProxy   || body.geo_proxy || false,
      geoHosting: body.geoHosting || body.geo_hosting || false,
      geoVpn:     body.geoVpn     || body.vpnDetected || body.geo_vpn || false,
      geoTor:     body.geoTor     || body.torDetected || body.geo_tor || false,
      geoRelay:   body.geoRelay   || body.geo_relay || false,
      asn:        body.asn || body.geoAsn || body.geo_asn,
      asnOrg:     body.asnOrg || body.asn_org,
      highRiskCountry: body.highRiskCountry || body.high_risk_country || false,
      filePath,
      fileName,
      fileHash: fileHash || hashSignatureTelemetry.sha256,
      fileHashMd5: fileHashMd5 || hashSignatureTelemetry.md5,
      fileAction: body.fileAction || body.file_action,
      fileUser:   body.fileUser   || body.file_user,
      malwareType,
      quarantined: body.quarantined || false,
      yaraRules,
      device,
      deviceVendor: body.deviceVendor || body.vendor,
      serialNumber: body.serialNumber || body.serial_number,
      usbVendorId: body.usbVendorId || body.vid || body.vendor_id,
      usbProductId: body.usbProductId || body.product_id,
      deviceType: body.deviceType || body.device_type,
      mountPath: body.mountPath || body.mount_path,
      fileSize: numberOrUndefined(body.fileSize, body.file_size),
      bytesTransferred: numberOrUndefined(body.bytesTransferred, body.bytes_transferred),
      policyName: body.policyName || body.policy_name,
      usbPolicyId: body.usbPolicyId || body.policy_id,
      usbPolicyRuleType: body.usbPolicyRuleType || body.policy_rule_type,
      usbDriver: body.usbDriver || body.driver_name,
      sensitivityType: body.sensitivityType || body.sensitivity_type,
      usbEnforcementStatus: body.usbEnforcementStatus || body.enforcement_status,
      usbEnforcementError: body.usbEnforcementError || body.enforcement_error,
      username:    body.username || body.mount_user || body.user || body.raw?.username || body.raw?.user || body.raw?.process_user || undefined,
      processName: body.processName || body.process_name || body.process || body.raw?.processName || body.raw?.process_name || body.raw?.process || undefined,
      pid:         numberOrUndefined(body.pid, body.processId, body.process_id, body.raw?.pid, body.raw?.processId, body.raw?.process_id),
      parentPid:   numberOrUndefined(body.parentPid, body.parent_pid, body.raw?.parentPid, body.raw?.parent_pid),
      parentProcessName: body.parentProcessName || body.parent_process_name || body.raw?.parentProcessName || body.raw?.parent_process_name,
      parentCommandLine: body.parentCommandLine || body.parent_cmdline || body.parent_command_line || body.raw?.parentCommandLine || body.raw?.parent_cmdline || body.raw?.parent_command_line,
      parentUsername: body.parentUsername || body.parent_username || body.raw?.parentUsername || body.raw?.parent_username,
      userDomain: body.userDomain || body.user_domain || body.endpoint_domain,
      processCmdline: body.processCmdline || body.cmdline || body.command_line || body.raw?.processCmdline || body.raw?.process_cmdline || body.raw?.command_line || body.raw?.cmdline,
      processExe:  body.processExe || body.exe || body.raw?.processExe || body.raw?.process_exe || body.raw?.exe,
      processStatus: body.processStatus || body.process_status,
      processCpuPercent: numberOrUndefined(body.processCpuPercent, body.cpu_percent, body.raw?.cpu_percent),
      processMemoryPercent: numberOrUndefined(body.processMemoryPercent, body.memory_percent, body.raw?.memory_percent),
      processMemoryMb: numberOrUndefined(body.processMemoryMb, body.memory_mb, body.currentMb, body.current_mb, body.raw?.memory_mb, body.raw?.currentMb, body.raw?.current_mb),
      processDiskReadBytes: numberOrUndefined(body.processDiskReadBytes, body.disk_read_bytes, body.raw?.disk_read_bytes),
      processDiskWriteBytes: numberOrUndefined(body.processDiskWriteBytes, body.disk_write_bytes, body.raw?.disk_write_bytes),
      processDiskReadBytesPerSecond: numberOrUndefined(body.processDiskReadBytesPerSecond, body.disk_read_bytes_per_second, body.raw?.disk_read_bytes_per_second),
      processDiskWriteBytesPerSecond: numberOrUndefined(body.processDiskWriteBytesPerSecond, body.disk_write_bytes_per_second, body.raw?.disk_write_bytes_per_second),
      processNetworkConnectionCount: numberOrUndefined(body.processNetworkConnectionCount, body.network_connection_count, body.raw?.network_connection_count),
      processExternalConnectionCount: numberOrUndefined(body.processExternalConnectionCount, body.external_connection_count, body.raw?.external_connection_count),
      processRemoteAddresses: body.processRemoteAddresses || body.remote_addresses || body.raw?.remote_addresses || [],
      processUniqueRemoteIpCount: numberOrUndefined(body.processUniqueRemoteIpCount, body.unique_remote_ip_count, body.raw?.unique_remote_ip_count),
      processUniqueRemotePortCount: numberOrUndefined(body.processUniqueRemotePortCount, body.unique_remote_port_count, body.raw?.unique_remote_port_count),
      processPrivateRemoteIpCount: numberOrUndefined(body.processPrivateRemoteIpCount, body.private_remote_ip_count, body.raw?.private_remote_ip_count),
      processClassifications: body.processClassifications || body.process_classifications || body.raw?.classifications || [],
      processExecutableSha256: body.processExecutableSha256 || body.executable_sha256,
      processSignatureStatus: body.processSignatureStatus || body.signature_status,
      processTrustStatus: body.processTrustStatus || body.trust_status,
      processPublisher: body.processPublisher || body.publisher,
      processPackageOwner: body.processPackageOwner || body.package_owner,
      processPackageVerificationStatus: body.processPackageVerificationStatus || body.package_verification_status,
      processCreateTime: processCreateDate(body.processCreateTime || body.process_create_time),
      processEndTime: processCreateDate(body.processEndTime || body.process_end_time || body.end_time),
      processExitCode: numberOrUndefined(body.processExitCode, body.process_exit_code, body.exit_code),
      processIntegrityLevel: body.processIntegrityLevel || body.integrity_level,
      processFileCompany: body.processFileCompany || body.company,
      processFileVersion: body.processFileVersion || body.version,
      processExecutableMd5: body.processExecutableMd5 || body.executable_md5 || body.file_hash_md5,
      processCount: numberOrUndefined(body.processCount, body.process_count),
      // Script Execution Monitoring telemetry is normalized here so the
      // tenant API and UI never need to interpret arbitrary raw payloads.
      scriptName: pickFirst(body.scriptName, body.script_name, body.raw?.scriptName, body.raw?.script_name),
      scriptPath: pickFirst(body.scriptPath, body.script_path, body.raw?.scriptPath, body.raw?.script_path),
      scriptHash: pickFirst(body.scriptHash, body.script_hash, body.raw?.scriptHash, body.raw?.script_hash),
      scriptSha1: pickFirst(body.scriptSha1, body.script_sha1, body.raw?.script_sha1),
      scriptMd5: pickFirst(body.scriptMd5, body.script_md5, body.raw?.script_md5),
      interpreter: pickFirst(body.interpreter, body.raw?.interpreter),
      commandLine: pickFirst(body.commandLine, body.command_line, body.cmdline, body.raw?.commandLine, body.raw?.command_line, body.raw?.cmdline),
      executionSource: pickFirst(body.executionSource, body.execution_source, body.raw?.execution_source),
      obfuscationScore: numberOrUndefined(body.obfuscationScore, body.obfuscation_score, body.raw?.obfuscation_score),
      detectionReasons: body.detectionReasons || body.detection_reasons || body.raw?.detection_reasons || [],
      processTree: body.processTree || body.process_tree || body.raw?.process_tree || [],
      childProcesses: body.childProcesses || body.child_processes || body.raw?.child_processes || [],
      networkConnections: body.networkConnections || body.network_connections || body.raw?.network_connections || [],
      filesCreated: body.filesCreated || body.files_created || body.raw?.files_created || [],
      filesModified: body.filesModified || body.files_modified || body.raw?.files_modified || [],
      filesDeleted: body.filesDeleted || body.files_deleted || body.raw?.files_deleted || [],
      userAction:  body.userAction  || body.user_action,
      policyId: body.policyId || body.policy_id,
      policyName: body.policyName || body.policy_name,
      policyCategory: body.policyCategory || body.policy_category,
      policyAction: body.policyAction || body.policy_action,
      policyTriggered: body.policyTriggered === true || body.policy_triggered === true,
      policyActionStatus: body.policyActionStatus || body.policy_action_status,
      // LOLBins / Ransomware detection fields
      riskScore:       normalizedTelemetry.riskScore ?? numberOrUndefined(body.riskScore, body.risk_score, body.raw?.riskScore, body.raw?.risk_score),
      matchedPatterns: body.matchedPatterns || body.matched_patterns,
      isNetwork:       body.isNetwork    || body.is_network,
      isPersistence:   body.isPersistence || body.is_persistence,
      // Source tag from agent (lolbins / ransomware / auto_response)
      source:          body.source || body.source_tag || body.log_source || '',
      // ── Malware enrichment fields ──────────────────────────────────────────
      actionTaken:       normalizeActionTaken(body.actionTaken || body.action_taken || body.action),
      containmentStatus: body.containmentStatus || body.containment_status || 'none',
      detectionSource:   body.detectionSource   || body.detection_source   || body.source || null,
      firstSeen:         body.firstSeen         || body.first_seen         || null,
      lastSeen:          body.lastSeen          || body.last_seen          || null,
      // Rule 9: Under Observation flag
      underObservation,
      // Pre-enriched VT
      ...(vtScore          != null && { vtScore }),
      ...(vtDetections     != null && { vtDetections }),
      ...(vtTotal          != null && { vtTotal }),
      ...(vtDetectionRatio          && { vtDetectionRatio }),
      ...(vtVerdict                 && { vtVerdict }),
      ...(vtEngines                 && { vtEngines }),
      rawEvent: body,
      ...idsIpsTelemetry,
      actionable: body.actionable === true
        || hashSignatureTelemetry.hashSignatureAlertEligible === true
        || (normalizedTelemetry.capabilityId === 29 && !normalizedTelemetry.memoryMetricType),
      isSimulated: normalizedTelemetry.isSimulated,
      expiresAt: memoryMetricExpiry(body),
      createdAt,
    };
    alertData.riskScore = Math.max(
      Number(alertData.riskScore ?? calculateSecurityRisk(alertData)) || 0,
      Number(hashSignatureTelemetry.hashSignatureRiskScore || 0),
    );
    await applyRegistryConfigurationPolicies(alertData);
    await applySystemChangeControls(alertData);

    if (brokerEnabled()) {
      if (!eventId) return res.status(400).json({ message: 'event_id is required in broker mode' });
      await getEventBroker().publishAlerts([alertData]);
      ingestionEvents.inc({ kind: 'alert', mode: 'broker', outcome: 'accepted' });
      return res.status(202).json({ ok: true, accepted: 1, eventId, mode: 'broker' });
    }
    if (ALERT_CONSOLE_LOGS) {
      console.log(`[ALERT] ${new Date().toISOString()} | evt=${ruleId} | sev=${finalSeverity} | cat=${finalCategory} | vt=${vtVerdict||'N/A'}(${vtDetectionRatio||'?'}) | file=${filePath||''} | ip=${srcip||''} | host=${body.system_name||''} | ua=${underObservation}`);
    }


    const alert = await Alert.create(alertData);
    await persistCurrentGpsState(alert);
    ingestionEvents.inc({ kind: 'alert', mode: 'direct', outcome: 'inserted' });
    if (alert.ruleId === 'UEBA_INPUT_PROFILE_MISMATCH' && alert.inputProfileMismatch === true) {
      setImmediate(() => require('../services/uebaProfileLock.service')
        .processProfileMismatchAlert(alert, req.app.get('io'))
        .catch(error => console.error('[ueba profile mismatch]', error.message)));
    }
    if (/^GEO_/i.test(String(alert.ruleId || ''))
      && (alert.rawEvent?.systemLogoutRequested || alert.rawEvent?.sessionRevokeRequested
        || alert.rawEvent?.geoFenceLockRequested || alert.rawEvent?.lockRecommended)) {
      setImmediate(() => require('../services/uebaProfileLock.service')
        .processGeolocationProtectionAlert(alert, req.app.get('io'))
        .catch(error => console.error('[geolocation protection log]', error.message)));
    }
    const isMemoryMetric = alert.memoryMetricType || alert.eventType === 'memory.metric';
    const routineTelemetry = isRoutineSecurityTelemetry(alert);
    if (!isMemoryMetric && !routineTelemetry) await autoAssignNewAlert(alert);
    // AI enriches normalized, high-risk EDR/IDS/IPS events asynchronously.
    // Ingestion and deterministic dashboard visibility never wait for the model.
    if (!isMemoryMetric && !routineTelemetry) {
      setImmediate(() => require('../services/azureAi.service')
        .enqueueSecurityEventAnalysis(alert, { io: req.app.get('io') })
        .catch(err => console.error('[AI event investigation]', err.message)));
    }

    if ((body.geoFenceLockRequested || body.lockRecommended) && ruleId === 'GEO_FENCE_RADIUS_VIOLATION') {
      autoIsolateGeoFence(req, systemId, finalDescription || 'Geo-fence radius violation').catch(err => {
        console.warn('[geo-fence] auto isolate failed:', err.message);
      });
    }

    // ── VirusTotal async enrichment (backend-side, only if agent didn't pre-scan) ─
    if (vt.isEnabled() && vtScore == null && !hasCapability(alert, 25) && !routineTelemetry) {
      setImmediate(async () => {
        try {
          let vtResult = null;

          if (alert.fileHash && finalCategory === 'malware') {
            vtResult = await vt.scanHash(alert.fileHash);
          } else if (alert.srcip && finalCategory === 'network') {
            vtResult = await vt.scanIp(alert.srcip);
          }

          if (vtResult) {
            const detections   = vtResult.detections || 0;
            const totalEngines = vtResult.total || 0;

            // Apply Master VT Ruleset to backend-side scan (Rules 1-3, 7)
            const vtAppliedAsync = applyVtRules(
              { malicious: detections, total: totalEngines, score: vtResult.score || 0, verdict: vtResult.verdict },
              alert.eventCategory,
              alert.severity,
              alert.description,
            );

            const update = {
              vtScore:          vtResult.score || 0,
              vtDetections:     detections,
              vtTotal:          totalEngines,
              vtEngines:        vtResult.engines || [],
              vtDetectionRatio: vtResult.detection_ratio || `${detections}/${totalEngines}`,
              vtVerdict:        vtAppliedAsync.vtVerdict || vtResult.verdict,
              vtScannedAt:      vtResult.scannedAt || new Date(),
              severity:         vtAppliedAsync.severity,
              eventCategory:    vtAppliedAsync.eventCategory,
              underObservation: vtAppliedAsync.underObservation,
            };

            if (vtAppliedAsync.underObservation) {
              update.description = vtAppliedAsync.description;
            }

            // Auto-resolve confirmed-clean network alerts (Rule 1)
            if (vtAppliedAsync.vtVerdict === 'clean' && alert.eventCategory === 'network') {
              update.status = 'false_positive';
              console.log(`[VT] Auto-resolved clean network alert ${alert._id} — 0/${totalEngines} engines`);
            }

            console.log(`[VT] ${alert.ruleId} → ${detections}/${totalEngines} (${vtAppliedAsync.vtVerdict}) → sev=${vtAppliedAsync.severity} cat=${vtAppliedAsync.eventCategory}`);
            await Alert.findByIdAndUpdate(alert._id, update);
          } else {
            // VT lookup failed — Rule 2: mark Under Observation, schedule retry
            if (alert.eventCategory === 'malware') {
              await Alert.findByIdAndUpdate(alert._id, {
                underObservation: true,
                vtVerdict: 'not_found',
                description: (alert.description || '') + ' [UNDER OBSERVATION — Threat Intel Missing]',
              });
              console.log(`[VT] Retry scheduled for ${alert._id} (${alert.fileHash || alert.srcip})`);
              // Simple 60-second retry
              setTimeout(async () => {
                try {
                  const retryResult = alert.fileHash
                    ? await vt.scanHash(alert.fileHash)
                    : alert.srcip ? await vt.scanIp(alert.srcip) : null;
                  if (retryResult) {
                    const rd = retryResult.detections || 0;
                    const rt = retryResult.total || 0;
                    const retryApplied = applyVtRules(
                      { malicious: rd, total: rt, score: retryResult.score || 0 },
                      alert.eventCategory, alert.severity, alert.description,
                    );
                    await Alert.findByIdAndUpdate(alert._id, {
                      vtScore: retryResult.score || 0,
                      vtDetections: rd, vtTotal: rt,
                      vtDetectionRatio: `${rd}/${rt}`,
                      vtVerdict: retryApplied.vtVerdict,
                      severity: retryApplied.severity,
                      eventCategory: retryApplied.eventCategory,
                      underObservation: retryApplied.underObservation,
                    });
                    console.log(`[VT] Retry OK for ${alert._id}: ${rd}/${rt}`);
                  }
                } catch (e) { console.error('[VT retry]', e.message); }
              }, 60_000);
            }
          }
        } catch (e) { console.error('[VT async]', e.message); }
      });
    }

    // ── Emit via Socket.IO ────────────────────────────────────────────────────
    const io = req.app.get('io');
    if (alert.ruleId === 'NET_CONNECTION_SUMMARY') {
      setImmediate(() => ingestNetworkTelemetry(alert, io)
        .catch(error => console.error('[network telemetry]', error.message)));
    }
    if (!routineTelemetry) scheduleGeolocationEnrichment(alert, io);
    if (!isMemoryMetric && !routineTelemetry) {
      io.to(`company:${alert.companyId}`).emit('alert:new', alert);
      if (alert.departmentId) io.to(`dept:${alert.departmentId}`).emit('alert:new', alert);
      io.to('superadmin').emit('alert:new', alert);
    }
    if (hasCapability(alert, 5) || hasCapability(alert, 29)) {
      io.to(`company:${alert.companyId}`).emit(alert.memoryMetricType ? 'memory:metric' : 'memory:alert', alert);
    }
    if (hasCapability(alert, 4)) {
      io.to(`company:${alert.companyId}`).emit('auth:event', alert);
      io.to(`company:${alert.companyId}`).emit('authentication_event', alert);
      if (['medium', 'high', 'critical'].includes(String(alert.severity || '').toLowerCase())) {
        io.to(`company:${alert.companyId}`).emit('authentication_alert', alert);
      }
    }
    if (hasCapability(alert, 20)) {
      io.to(`company:${alert.companyId}`).emit('api:event', alert);
    }
    if (hasCapability(alert, 19)) {
      io.to(`company:${alert.companyId}`).emit('kernel:event', alert);
    }
    if (hasCapability(alert, 17)) {
      io.to(`company:${alert.companyId}`).emit('patch:event', alert);
    }
    if (hasCapability(alert, 16)) {
      io.to(`company:${alert.companyId}`).emit('insider:event', alert);
    }
    if (hasCapability(alert, 15)) {
      io.to(`company:${alert.companyId}`).emit('email:event', alert);
    }
    if (hasCapability(alert, 14)) {
      io.to(`company:${alert.companyId}`).emit('lateral:event', alert);
    }
    if (hasCapability(alert, 13)) {
      io.to(`company:${alert.companyId}`).emit('credential:event', alert);
    }
    if (hasCapability(alert, 12)) {
      io.to(`company:${alert.companyId}`).emit('data-security:event', alert);
    }
    if (hasCapability(alert, 11)) {
      io.to(`company:${alert.companyId}`).emit('ueba:event', alert);
    }
    if (hasCapability(alert, 10)) {
      io.to(`company:${alert.companyId}`).emit('usb:event', alert);
    }
    if (hasCapability(alert, 9)) {
      io.to(`company:${alert.companyId}`).emit('webdns:event', alert);
    }
    if (hasCapability(alert, 8)) {
      io.to(`company:${alert.companyId}`).emit('persistence:event', alert);
    }
    if (hasCapability(alert, 7)) {
      io.to(`company:${alert.companyId}`).emit('system-change:event', alert);
    }
    if (hasCapability(alert, 6)) {
      io.to(`company:${alert.companyId}`).emit('registry:event', alert);
    }
    if (hasCapability(alert, 28)) {
      io.to(`company:${alert.companyId}`).emit('lolbins:event', alert);
    }
    if (hasCapability(alert, 25)) {
      io.to(`company:${alert.companyId}`).emit('hash:alert', alert);
      setImmediate(() => enrichHashAlertThreatIntel(alert, io));
    }
    if (hasCapability(alert, 24)) {
      io.to(`company:${alert.companyId}`).emit('service:alert', alert);
    }
    if (hasCapability(alert, 23)) {
      io.to(`company:${alert.companyId}`).emit('geo:event', alert);
      io.to(`company:${alert.companyId}`).emit('geo:anomaly', alert);
    }
    if (hasCapability(alert, 22)) {
      io.to(`company:${alert.companyId}`).emit('time:anomaly', alert);
    }
    if (hasCapability(alert, 21)) {
      io.to(`company:${alert.companyId}`).emit('script:event', alert);
      setImmediate(() => enrichScriptThreatIntel(alert, io));
    }
    if (hasCapability(alert, 26)) {
      io.to(`company:${alert.companyId}`).emit('beaconing:event', alert);
    }
    if (hasCapability(alert, 27) || String(alert.source || '').toLowerCase() === 'ransomware') {
      io.to(`company:${alert.companyId}`).emit('ransomware:event', alert);
    }
    if (isMemoryMetric) {
      return res.status(201).json({ ok: true, alertId: alert._id, metric: true });
    }

    // Also emit as log:new so SIEM Live Feed gets real-time updates
    if (!routineTelemetry) io.to(`company:${alert.companyId}`).emit('log:new', {
      _id: alert._id,
      tenantId: alert.tenantId,
      partnerId: alert.partnerId,
      companyId: alert.companyId,
      source: alert.source || 'agent',
      agentName: alert.agentName,
      hostname: alert.agentName,
      logType: alert.eventCategory || 'system',
      level: alert.severity || 'info',
      message: `[${(alert.severity || 'info').toUpperCase()}] ${alert.ruleId || ''}: ${alert.description || ''}`,
      receivedAt: alert.createdAt || new Date(),
      format: 'alert',
      tags: [alert.eventCategory, alert.severity, 'alert'],
    });

    // ── SOAR ─────────────────────────────────────────────────────────────────
    if (!isMemoryMetric && !routineTelemetry) setImmediate(() => runSoarForAlert(alert).catch(e => console.error('[SOAR]', e.message)));

    // Response playbooks run after the alert is persisted. Response-result alerts
    // are deliberately excluded so an action result cannot trigger another action.
    if (!isMemoryMetric && !routineTelemetry && alert.source !== 'auto_response') {
      setImmediate(() => evaluatePlaybooksForAlert(alert, io)
        .catch(e => console.error('[automated response]', e.message)));
    }

    // ── SOC AI Agent Correlation Engine ───────────────────────────────────────
    if (!isMemoryMetric && !routineTelemetry) setImmediate(async () => {
      try {
        const { correlateAlerts } = require('../services/soc-agent-edr.service');
        await correlateAlerts(alert, req.app.get('io'));
      } catch (e) { console.error('[SOC-AI correlation]', e.message); }
    });
    // Keep the existing CorrelationEvent engine real-time as well. Bursts are
    // debounced per company so ingestion throughput is not blocked.
    if (!routineTelemetry) {
      require('../services/correlation.service')
        .scheduleCompanyCorrelation(alert.companyId, req.app.get('io'));
    }

    // ── IPS Auto-Block ────────────────────────────────────────────────────────
    if (!routineTelemetry) setImmediate(async () => {
      try {
        const { autoBlockFromAlert } = require('../services/ips.service');
        await autoBlockFromAlert(alert, alert.companyId);
      } catch (e) { console.error('[IPS auto-block]', e.message); }
    });

    // ── Threat Intel Enrichment (IP + Domain) ─────────────────────────────────
    if (!routineTelemetry) setImmediate(async () => {
      try {
        const isDnsAlert = DNS_RULE_PATTERNS.test(alert.ruleId || '') ||
                           (alert.userAction || '').includes('dns');

        // 1. DNS alert — enrich domain via OTX AlienVault
        if (isDnsAlert) {
          // Extract domain from description or rawEvent
          const raw     = alert.rawEvent || {};
          const domain  = raw.domain || raw.query || raw.dns_query ||
                          (alert.description || '').match(/\b([a-z0-9][a-z0-9\-]{1,61}\.[a-z]{2,})\b/i)?.[1];
          if (domain && !domain.includes('localhost')) {
            const intel = await threatIntel.enrichDomain(domain);
            if (intel) {
              await Alert.findByIdAndUpdate(alert._id, {
                // Domain enrichment is evidence for Web & DNS Monitoring.
                // Never tag it as Memory Overflow (29).
                $addToSet: { capabilityIds: 9 },
                $set: {
                tiEnriched:   true,
                tiDomain:     domain,
                tiDomainMalicious: intel.isMalicious,
                tiSummary:    intel.summary,
                tiFeeds:      { otxPulses: intel.pulseCount, malwareFamilies: intel.malwareFamilies },
                },
              });
              if (intel.isMalicious) {
                console.log(`[ThreatIntel] 🚨 Malicious domain: ${domain} — ${intel.pulseCount} OTX pulses`);
                // Emit real-time socket alert
                io.to(`company:${alert.companyId}`).emit('ti:domain:malicious', {
                  alertId: alert._id, domain, summary: intel.summary,
                  malwareFamilies: intel.malwareFamilies,
                });
              }
            }
          }
        }

        // 2. Network/IP alert — inspect the remote destination. The endpoint's
        // local source address is not the C2 reputation target.
        const reputationIp = alert.destip || srcip;
        if (reputationIp && (finalCategory === 'network' || isDnsAlert)) {
          await threatIntel.enrichAndMaybeBlock(reputationIp, alert.companyId, alert._id, io);
        }
      } catch (e) { console.error('[ThreatIntel enrichment]', e.message); }
    });

    res.status(201).json({ ok: true, alertId: alert._id });
  } catch (err) {
    if (err?.code === 11000 && (req.body.event_id || req.body.eventId || req.headers['idempotency-key'])) {
      return res.status(200).json({ ok: true, duplicate: true });
    }
    console.error('[alert] POST error:', err.message);
    res.status(400).json({ message: err.message });
  }
});

// ── POST /api/alerts/batch — agent batch send (no JWT) ───────────────────────
// Accepts { alerts: [...] } and inserts all in one DB call (insertMany).
// Dramatically reduces sender latency when many alerts are queued.
router.post('/batch', async (req, res) => {
  const secret   = req.headers['x-integration-secret'];
  const alerts   = req.body?.alerts;

  if (!Array.isArray(alerts) || alerts.length === 0)
    return res.status(400).json({ message: 'alerts array required' });
  const batchCheck = enforceBatchLimit(alerts, 50, 'alerts');
  if (!batchCheck.ok) return res.status(batchCheck.status).json({ message: batchCheck.message });

  // Auth: use first alert's agent_key (all from same agent)
  const agentKey = alerts[0]?.agent_key || alerts[0]?.agentKey;
  const mixedAgentBatch = alerts.some((item) => {
    const itemAgentKey = item.agent_key || item.agentKey || agentKey;
    return itemAgentKey !== agentKey;
  });
  if (mixedAgentBatch) {
    return res.status(400).json({ message: 'All alerts in a batch must belong to one agent' });
  }
  const signedAuth = await verifySignedAgentRequest(req, { agentKey });
  let system = signedAuth.ok ? signedAuth.system : null;
  if (!system && agentKey) system = await System.findOne({ agentKey });
  const hasLegacySecret = Boolean(
    system && secret && secret === process.env.INTEGRATION_SECRET
  );
  const authorized = signedAuth.ok || hasLegacySecret;
  if (!authorized) return res.status(401).json({ message: 'Unauthorized' });

  try {
    const firstScope = await resolveScope({
      system,
      companyId: alerts[0]?.company_id || alerts[0]?.companyId,
      body: alerts[0],
      requireSystem: Boolean(agentKey),
    });
    const ingestionStatus = await getCompanyIngestionStatus(firstScope.companyId);
    if (!ingestionStatus.allowed) return sendIngestionBlocked(res, ingestionStatus);

    // Map each raw alert body to an Alert document (same logic as single POST)
    const docs = (await Promise.all(alerts.map(async body => {
      const itemAgentKey = body.agent_key || body.agentKey || agentKey;
      const itemSystem = itemAgentKey === agentKey
        ? system
        : await System.findOne({ agentKey: itemAgentKey });
      const scope = await resolveScope({
        system: itemSystem,
        companyId: body.company_id || body.companyId,
        body,
        requireSystem: Boolean(itemAgentKey),
      });
      const companyId    = scope.companyId;
      const tenantId     = scope.tenantId;
      const partnerId    = scope.partnerId;
      const departmentId = scope.departmentId;
      const systemId     = scope.systemId;
      const eventId      = body.event_id || body.eventId;
      const ruleId       = body.rule_id    || body.ruleId    || body.type || '';
      const source       = body.log_source || body.source    || '';
      const description  = body.description;
      const severity     = body.severity   || mapSeverity(body.ruleLevel || body.rule_level || 0);
      const eventCategory = normalizeEventCategory(body.category, toCategory(ruleId, source, description));
      const filePath     = body.file_path || body.filePath || body.script_path || body.scriptPath;
      enrichFimPermissionFields(body, ruleId);
      const fimHashes    = enrichFimHashFields(body);
      const fileHash     = body.script_hash || body.scriptHash || fimHashes.fileHash;
      const fileHashMd5  = body.script_md5 || body.scriptMd5 || fimHashes.fileHashMd5;
      const fileName     = body.file_name || body.fileName || body.script_name || body.scriptName || (filePath ? filePath.split(/[/\\]/).pop() : undefined);
      const createdAt    = eventDateFromBody(body);
      const srcip        = body.src_ip    || body.srcip;
      const destip       = body.dst_ip    || body.dest_ip || body.destip || body.destIp;
      const destPort     = body.dst_port  || body.destPort || body.port;
      const yaraRules    = body.yara_rules || body.yaraRules;
      if (/^GEO_/i.test(ruleId) && !(await hasActiveGeoPolicy(companyId))) return null;
      if (['GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS'].includes(ruleId)) {
        const accuracyLimit = await activeGpsPolicyAccuracyLimit(companyId, systemId);
        if (accuracyLimit === null) return null;
        const reportedAccuracy = numberOrUndefined(body.gpsAccuracyMeters, body.gps_accuracy_meters);
        if (ruleId === 'GPS_LOCATION_TELEMETRY'
          && (!Number.isFinite(reportedAccuracy) || reportedAccuracy < 0 || reportedAccuracy > accuracyLimit)) return null;
      }
      const normalizedTelemetry = normalizeCapabilityTelemetry(body, itemSystem);
      const uebaTelemetry = normalizeUebaTelemetry(body, itemSystem);
      const emailTelemetry = normalizeEmailTelemetry(body);
      const lateralTelemetry = normalizeLateralTelemetry(body);
      const credentialTelemetry = normalizeCredentialTelemetry(body);
      const dataSecurityTelemetry = normalizeDataSecurityTelemetry(body);
      const inferredModule = inferSecurityModule(body, eventCategory);
      const normalizedSecurity = normalizeSecurityEvent({ ...body, module: body.module || inferredModule });
      if (isPreInstallFimEvent(itemSystem, eventCategory, ruleId, source, filePath, body, createdAt)) {
        return null;
      }

      let malwareType = body.malwareType || body.malware_type;
      if (!malwareType && eventCategory === 'malware') {
        const rid = ruleId.toLowerCase();
        if      (rid.includes('ransomware') || rid.includes('shadow')) malwareType = 'Ransomware';
        else if (rid.includes('trojan'))    malwareType = 'Trojan';
        else if (rid.includes('miner'))     malwareType = 'Miner';
        else if (rid.includes('worm'))      malwareType = 'Worm';
        else if (rid.includes('backdoor') || rid.includes('shell')) malwareType = 'Backdoor';
        else if (rid.includes('mimikatz')) malwareType = 'Credential Dumper';
        else                               malwareType = 'Generic';
      }

      // Pre-enriched VT from agent
      let vtScore, vtDetections, vtTotal, vtDetectionRatio, vtVerdict, vtEngines;
      const vtRaw = body.virustotal;
      if (vtRaw && typeof vtRaw === 'object') {
        vtScore          = vtRaw.score       != null ? Number(vtRaw.score)      : undefined;
        vtDetections     = vtRaw.malicious   != null ? Number(vtRaw.malicious)  : undefined;
        vtTotal          = vtRaw.total_engines != null ? Number(vtRaw.total_engines) : undefined;
        vtDetectionRatio = vtRaw.detection_ratio || undefined;
        vtVerdict        = vtRaw.verdict         || undefined;
        vtEngines        = vtRaw.engines_triggered || undefined;
      }

      const hashSignatureTelemetry = await enrichHashSignatureEvent({
        ...body,
        filePath,
        fileHash,
        fileHashMd5,
        vtVerdict,
      }, {
        tenantId,
        companyId,
        departmentId,
        endpointId: normalizedTelemetry.endpointId,
        filePath: filePath || normalizedTelemetry.processExe,
        fileName,
        observedAt: createdAt,
      });
      const hashSeverity = hashSignatureTelemetry.hashSignatureAlertEligible
        ? hashSignatureTelemetry.hashSignatureSeverity
        : severity;

      return {
        tenantId, partnerId, companyId, departmentId, systemId, eventId,
        agentId:    (itemAgentKey || '').slice(0, 8) || body.agentId,
        agentName:  body.system_name || itemSystem?.name,
        ...normalizedTelemetry,
        ...uebaTelemetry,
        ...emailTelemetry,
        ...lateralTelemetry,
        ...credentialTelemetry,
        ...dataSecurityTelemetry,
        ...normalizedSecurity,
        ...hashSignatureTelemetry,
        ruleId, ruleLevel: body.ruleLevel || body.rule_level,
        description, full_log: body.raw_log || body.full_log,
        source, type: ruleId,
        eventCategory, subCategory: body.subCategory || body.sub_category || (body.category && body.category !== eventCategory ? body.category : undefined), severity: higherSeverity(higherSeverity(severity, hashSeverity), (normalizedTelemetry.systemChangeCategory || normalizedTelemetry.configurationCategory) ? severityFromRisk(normalizedTelemetry.riskScore) : 'low'),
        srcip,
        sourcePort: numberOrUndefined(body.sourcePort, body.srcPort, body.src_port),
        srcPort: numberOrUndefined(body.srcPort, body.src_port, body.sourcePort),
        destip, destPort, port: destPort, protocol: body.protocol,
        connectionId: body.connectionId || body.connection_id,
        connectionState: body.connectionState || body.connection_state || body.state,
        connectionStartTime: body.connectionStartTime || body.connection_start_time,
        connectionEndTime: body.connectionEndTime || body.connection_end_time,
        connectionDuration: numberOrUndefined(body.connectionDuration, body.connection_duration, body.duration),
        networkInterface: body.networkInterface || body.network_interface || body.interface,
        networkAdapter: body.networkAdapter || body.network_adapter,
        ipVersion: numberOrUndefined(body.ipVersion, body.ip_version),
        bytesSent: numberOrUndefined(body.bytesSent, body.bytes_sent),
        bytesReceived: numberOrUndefined(body.bytesReceived, body.bytes_received),
        domain: body.domain || body.query || body.dnsQuery || body.dns_query,
        normalizedDomain: (body.domain || body.query || body.dnsQuery || body.dns_query)
          ? String(body.domain || body.query || body.dnsQuery || body.dns_query).trim().toLowerCase().replace(/\.$/, '')
          : undefined,
        url: pickFirst(body.url, body.targetUrl, body.target_url, body.raw?.url),
        httpMethod: pickFirst(body.httpMethod, body.http_method, body.requestMethod, body.request_method, body.raw?.http_method),
        requestPath: pickFirst(body.requestPath, body.request_path, body.path, body.raw?.requestPath, body.raw?.request_path),
        statusCode: numberOrUndefined(body.statusCode, body.status_code, body.httpStatusCode, body.responseStatus, body.raw?.status_code),
        apiVersion: pickFirst(body.apiVersion, body.api_version, body.raw?.api_version),
        responseTime: numberOrUndefined(body.responseTime, body.response_time, body.raw?.response_time),
        requestSize: numberOrUndefined(body.requestSize, body.request_size, body.raw?.request_size),
        responseSize: numberOrUndefined(body.responseSize, body.response_size, body.raw?.response_size),
        authType: pickFirst(body.authType, body.auth_type, body.authMethod, body.auth_method, body.raw?.auth_type, body.raw?.auth_method),
        wafProvider: pickFirst(body.wafProvider, body.waf_provider, body.provider, body.raw?.waf_provider),
        wafRuleId: pickFirst(body.wafRuleId, body.waf_rule_id, body.raw?.waf_rule_id, body.rule_id),
        wafRuleName: pickFirst(body.wafRuleName, body.waf_rule_name, body.raw?.waf_rule_name),
        matchedSignature: pickFirst(body.matchedSignature, body.matched_signature, body.matched, body.raw?.matched),
        backendService: pickFirst(body.backendService, body.backend_service, body.raw?.backend_service),
        backendError: pickFirst(body.backendError, body.backend_error, body.raw?.backend_error),
        browser: pickFirst(body.browser, body.raw?.browser),
        userAgent: pickFirst(body.userAgent, body.user_agent, body.raw?.user_agent),
        referrer: pickFirst(body.referrer, body.referer, body.raw?.referrer, body.raw?.referer),
        tlsVersion: pickFirst(body.tlsVersion, body.tls_version, body.raw?.tls_version),
        certificateInfo: pickFirst(body.certificateInfo, body.certificate_info, body.raw?.certificate_info),
        resolver: pickFirst(body.resolver, body.dnsServer, body.dns_server, body.raw?.resolver, body.raw?.dns_server),
        queryTime: numberOrUndefined(body.queryTime, body.query_time, body.raw?.query_time),
        queryType: body.queryType || body.query_type,
        direction: body.inbound !== undefined ? (body.inbound ? 'inbound' : 'outbound') : undefined,
        inbound: body.inbound, blocked: body.blocked || false,
        geoCountry: body.geoCountry || body.geo_country,
        geoCountryCode: body.geoCountryCode || body.geo_country_code || body.geoCountry || body.geo_country,
        geoCity:    body.geoCity    || body.geo_city,
        geoRegion:  body.geoRegion  || body.geo_region,
        geoTimezone: body.geoTimezone || body.geo_timezone,
        geoISP:     body.geoISP     || body.geo_isp,
        geoLat:     body.geoLat     || body.geo_lat,
        geoLon:     body.geoLon     || body.geo_lon,
        gpsLat:     numberOrUndefined(body.gpsLat, body.gps_lat),
        gpsLon:     numberOrUndefined(body.gpsLon, body.gps_lon),
        gpsAccuracyMeters: numberOrUndefined(body.gpsAccuracyMeters, body.gps_accuracy_meters),
        gpsAltitudeMeters: numberOrUndefined(body.gpsAltitudeMeters, body.gps_altitude_meters),
        gpsProvider: pickFirst(body.gpsProvider, body.gps_provider),
        gpsStatus: pickFirst(body.gpsStatus, body.gps_status),
        gpsReason: pickFirst(body.gpsReason, body.gps_reason),
        gpsObservedAt: processCreateDate(pickFirst(body.gpsObservedAt, body.gps_observed_at)),
        geoProxy:   body.geoProxy   || body.geo_proxy || false,
        geoHosting: body.geoHosting || body.geo_hosting || false,
        geoVpn:     body.geoVpn     || body.vpnDetected || body.geo_vpn || false,
        geoTor:     body.geoTor     || body.torDetected || body.geo_tor || false,
        geoRelay:   body.geoRelay   || body.geo_relay || false,
        asn:        body.asn || body.geoAsn || body.geo_asn,
        asnOrg:     body.asnOrg || body.asn_org,
        highRiskCountry: body.highRiskCountry || body.high_risk_country || false,
        filePath, fileName,
        fileHash: fileHash || hashSignatureTelemetry.sha256,
        fileHashMd5: fileHashMd5 || hashSignatureTelemetry.md5,
        fileAction: body.fileAction || body.file_action,
        fileUser:   body.fileUser   || body.file_user,
        malwareType, quarantined: body.quarantined || false, yaraRules,
        device: body.device || body.device_name,
        deviceVendor: body.deviceVendor || body.vendor,
        serialNumber: body.serialNumber || body.serial_number,
        usbVendorId: body.usbVendorId || body.vid || body.vendor_id,
        usbProductId: body.usbProductId || body.product_id,
        deviceType: body.deviceType || body.device_type,
        mountPath: body.mountPath || body.mount_path,
        fileSize: numberOrUndefined(body.fileSize, body.file_size),
        bytesTransferred: numberOrUndefined(body.bytesTransferred, body.bytes_transferred),
        policyName: body.policyName || body.policy_name,
        policyId: body.policyId || body.policy_id,
        policyCategory: body.policyCategory || body.policy_category,
        policyAction: body.policyAction || body.policy_action,
        policyTriggered: body.policyTriggered === true || body.policy_triggered === true,
        policyActionStatus: body.policyActionStatus || body.policy_action_status,
        usbPolicyId: body.usbPolicyId || body.policy_id,
        usbPolicyRuleType: body.usbPolicyRuleType || body.policy_rule_type,
        usbDriver: body.usbDriver || body.driver_name,
        usbEnforcementStatus: body.usbEnforcementStatus || body.enforcement_status,
        usbEnforcementError: body.usbEnforcementError || body.enforcement_error,
        sensitivityType: body.sensitivityType || body.sensitivity_type,
        processName: body.processName || body.process_name || body.process || body.raw?.processName || body.raw?.process_name || body.raw?.process,
        pid: numberOrUndefined(body.pid, body.processId, body.process_id, body.raw?.pid, body.raw?.processId, body.raw?.process_id),
        parentPid: numberOrUndefined(body.parentPid, body.parent_pid, body.raw?.parentPid, body.raw?.parent_pid),
        parentProcessName: body.parentProcessName || body.parent_process_name || body.raw?.parentProcessName || body.raw?.parent_process_name,
        parentCommandLine: body.parentCommandLine || body.parent_cmdline || body.parent_command_line || body.raw?.parentCommandLine || body.raw?.parent_cmdline || body.raw?.parent_command_line,
        parentUsername: body.parentUsername || body.parent_username || body.raw?.parentUsername || body.raw?.parent_username,
        userDomain: body.userDomain || body.user_domain || body.endpoint_domain,
        processCmdline: body.processCmdline || body.cmdline || body.command_line || body.raw?.processCmdline || body.raw?.process_cmdline || body.raw?.command_line || body.raw?.cmdline,
        processExe: body.processExe || body.exe || body.raw?.processExe || body.raw?.process_exe || body.raw?.exe,
        processStatus: body.processStatus || body.process_status,
        processCpuPercent: numberOrUndefined(body.processCpuPercent, body.cpu_percent, body.raw?.cpu_percent),
        processMemoryPercent: numberOrUndefined(body.processMemoryPercent, body.memory_percent, body.raw?.memory_percent),
        processMemoryMb: numberOrUndefined(body.processMemoryMb, body.memory_mb, body.currentMb, body.current_mb, body.raw?.memory_mb, body.raw?.currentMb, body.raw?.current_mb),
        processDiskReadBytes: numberOrUndefined(body.processDiskReadBytes, body.disk_read_bytes, body.raw?.disk_read_bytes),
        processDiskWriteBytes: numberOrUndefined(body.processDiskWriteBytes, body.disk_write_bytes, body.raw?.disk_write_bytes),
        processDiskReadBytesPerSecond: numberOrUndefined(body.processDiskReadBytesPerSecond, body.disk_read_bytes_per_second, body.raw?.disk_read_bytes_per_second),
        processDiskWriteBytesPerSecond: numberOrUndefined(body.processDiskWriteBytesPerSecond, body.disk_write_bytes_per_second, body.raw?.disk_write_bytes_per_second),
        processNetworkConnectionCount: numberOrUndefined(body.processNetworkConnectionCount, body.network_connection_count, body.raw?.network_connection_count),
        processExternalConnectionCount: numberOrUndefined(body.processExternalConnectionCount, body.external_connection_count, body.raw?.external_connection_count),
        processRemoteAddresses: body.processRemoteAddresses || body.remote_addresses || body.raw?.remote_addresses || [],
        processUniqueRemoteIpCount: numberOrUndefined(body.processUniqueRemoteIpCount, body.unique_remote_ip_count, body.raw?.unique_remote_ip_count),
        processUniqueRemotePortCount: numberOrUndefined(body.processUniqueRemotePortCount, body.unique_remote_port_count, body.raw?.unique_remote_port_count),
        processPrivateRemoteIpCount: numberOrUndefined(body.processPrivateRemoteIpCount, body.private_remote_ip_count, body.raw?.private_remote_ip_count),
        processClassifications: body.processClassifications || body.process_classifications || body.raw?.classifications || [],
        processExecutableSha256: body.processExecutableSha256 || body.executable_sha256,
        processSignatureStatus: body.processSignatureStatus || body.signature_status,
        processTrustStatus: body.processTrustStatus || body.trust_status,
        processPublisher: body.processPublisher || body.publisher,
        processPackageOwner: body.processPackageOwner || body.package_owner,
        processPackageVerificationStatus: body.processPackageVerificationStatus || body.package_verification_status,
        processCreateTime: processCreateDate(body.processCreateTime || body.process_create_time),
        processEndTime: processCreateDate(body.processEndTime || body.process_end_time || body.end_time),
        processExitCode: numberOrUndefined(body.processExitCode, body.process_exit_code, body.exit_code),
        processIntegrityLevel: body.processIntegrityLevel || body.integrity_level,
        processFileCompany: body.processFileCompany || body.company,
        processFileVersion: body.processFileVersion || body.version,
        processExecutableMd5: body.processExecutableMd5 || body.executable_md5 || body.file_hash_md5,
        processCount: numberOrUndefined(body.processCount, body.process_count),
        scriptName: pickFirst(body.scriptName, body.script_name, body.raw?.scriptName, body.raw?.script_name),
        scriptPath: pickFirst(body.scriptPath, body.script_path, body.raw?.scriptPath, body.raw?.script_path),
        scriptHash: pickFirst(body.scriptHash, body.script_hash, body.raw?.scriptHash, body.raw?.script_hash),
        scriptSha1: pickFirst(body.scriptSha1, body.script_sha1, body.raw?.script_sha1),
        scriptMd5: pickFirst(body.scriptMd5, body.script_md5, body.raw?.script_md5),
        interpreter: pickFirst(body.interpreter, body.raw?.interpreter),
        commandLine: pickFirst(body.commandLine, body.command_line, body.cmdline, body.raw?.commandLine, body.raw?.command_line, body.raw?.cmdline),
        executionSource: pickFirst(body.executionSource, body.execution_source, body.raw?.execution_source),
        obfuscationScore: numberOrUndefined(body.obfuscationScore, body.obfuscation_score, body.raw?.obfuscation_score),
        detectionReasons: body.detectionReasons || body.detection_reasons || body.raw?.detection_reasons || [],
        processTree: body.processTree || body.process_tree || body.raw?.process_tree || [],
        childProcesses: body.childProcesses || body.child_processes || body.raw?.child_processes || [],
        networkConnections: body.networkConnections || body.network_connections || body.raw?.network_connections || [],
        filesCreated: body.filesCreated || body.files_created || body.raw?.files_created || [],
        filesModified: body.filesModified || body.files_modified || body.raw?.files_modified || [],
        filesDeleted: body.filesDeleted || body.files_deleted || body.raw?.files_deleted || [],
        username: body.username || body.user || body.raw?.username || body.raw?.user || body.raw?.process_user,
        userAction:  body.userAction  || body.user_action,
        actionTaken: normalizeActionTaken(body.actionTaken || body.action_taken || body.action),
        containmentStatus: body.containmentStatus || body.containment_status || 'none',
        // LOLBins / Ransomware detection fields
        riskScore:       numberOrUndefined(body.riskScore, body.risk_score, body.raw?.riskScore, body.raw?.risk_score),
        matchedPatterns: body.matchedPatterns || body.matched_patterns,
        isNetwork:       body.isNetwork    || body.is_network,
        isPersistence:   body.isPersistence || body.is_persistence,
        source:          body.source || body.source_tag || body.log_source || '',
        module: body.module || inferredModule,
        source_type: body.source_type,
        event_category: body.event_category,
        attackType: body.attackType || body.attack_type,
        signatureName: body.signatureName || body.signature_name,
        packetCount: numberOrUndefined(body.packetCount, body.packet_count),
        ...(vtScore         != null && { vtScore }),
        ...(vtDetections    != null && { vtDetections }),
        ...(vtTotal         != null && { vtTotal }),
        ...(vtDetectionRatio       && { vtDetectionRatio }),
        ...(vtVerdict              && { vtVerdict }),
        ...(vtEngines              && { vtEngines }),
        rawEvent: body,
        actionable: body.actionable === true
          || hashSignatureTelemetry.hashSignatureAlertEligible === true
          || (normalizedTelemetry.capabilityId === 29 && !normalizedTelemetry.memoryMetricType),
        isSimulated: normalizedTelemetry.isSimulated,
        expiresAt: memoryMetricExpiry(body),
        createdAt,
        riskScore: Math.max(
          Number(normalizedTelemetry.riskScore ?? calculateSecurityRisk({ ...body, ...normalizedTelemetry })) || 0,
          Number(hashSignatureTelemetry.hashSignatureRiskScore || 0),
        ),
      };
    }))).filter(d => d && d.companyId);   // drop pre-install FIM events and any without a companyId

    await Promise.all(docs.map(async doc => {
      await applyRegistryConfigurationPolicies(doc);
      await applySystemChangeControls(doc);
    }));

    if (docs.length === 0) {
      return res.json({ ok: true, inserted: 0, ignored: alerts.length, reason: 'pre_install_fim_events' });
    }

    const eventIds = docs.map(doc => doc.eventId).filter(Boolean);
    let duplicateCount = 0;
    let insertableDocs = docs;
    if (eventIds.length) {
      const existing = await Alert.find({
        companyId: firstScope.companyId,
        eventId: { $in: eventIds },
      }).select('eventId').lean();
      const existingIds = new Set(existing.map(item => item.eventId));
      duplicateCount = docs.filter(doc => doc.eventId && existingIds.has(doc.eventId)).length;
      insertableDocs = docs.filter(doc => !doc.eventId || !existingIds.has(doc.eventId));
    }
    if (!insertableDocs.length) {
      return res.status(200).json({
        ok: true,
        inserted: 0,
        duplicates: duplicateCount,
        total: docs.length,
      });
    }

    if (brokerEnabled()) {
      if (insertableDocs.some(doc => !doc.eventId)) {
        return res.status(400).json({ message: 'event_id is required for every alert in broker mode' });
      }
      const published = await getEventBroker().publishAlerts(insertableDocs);
      ingestionEvents.inc({ kind: 'alert', mode: 'broker', outcome: 'accepted' }, published.published);
      return res.status(202).json({
        ok: true,
        accepted: published.published,
        duplicates: duplicateCount,
        total: docs.length,
        mode: 'broker',
      });
    }
    const inserted = await Alert.insertMany(insertableDocs, { ordered: false });
    await Promise.all(inserted.map(alert => persistCurrentGpsState(alert)));
    ingestionEvents.inc({ kind: 'alert', mode: 'direct', outcome: 'inserted' }, inserted.length);

    for (const a of inserted) {
      if (!a.memoryMetricType && a.eventType !== 'memory.metric' && !isRoutineSecurityTelemetry(a)) await autoAssignNewAlert(a);
    }

    inserted
      .filter(doc => doc.ruleId === 'GEO_FENCE_RADIUS_VIOLATION' && (doc.rawEvent?.geoFenceLockRequested || doc.rawEvent?.lockRecommended))
      .forEach(doc => {
        autoIsolateGeoFence(req, doc.systemId, doc.description || 'Geo-fence radius violation').catch(err => {
          console.warn('[geo-fence] auto isolate failed:', err.message);
        });
      });

    // Emit Socket.IO events async (don't block response)
    setImmediate(() => {
      const io = req.app.get('io');
      for (const a of inserted) {
        const routineTelemetry = isRoutineSecurityTelemetry(a);
        if (!routineTelemetry) scheduleGeolocationEnrichment(a, io);
        if (a.ruleId === 'NET_CONNECTION_SUMMARY') {
          ingestNetworkTelemetry(a, io)
            .catch(error => console.error('[network telemetry batch]', error.message));
        }
        const isMemoryMetric = a.memoryMetricType || a.eventType === 'memory.metric';
        if (!isMemoryMetric && !routineTelemetry) {
          io.to(`company:${a.companyId}`).emit('alert:new', a);
          if (a.departmentId) io.to(`dept:${a.departmentId}`).emit('alert:new', a);
        }
        if (hasCapability(a, 5) || hasCapability(a, 29)) {
          io.to(`company:${a.companyId}`).emit(a.memoryMetricType ? 'memory:metric' : 'memory:alert', a);
        }
        if (hasCapability(a, 4)) {
          io.to(`company:${a.companyId}`).emit('auth:event', a);
          io.to(`company:${a.companyId}`).emit('authentication_event', a);
          if (['medium', 'high', 'critical'].includes(String(a.severity || '').toLowerCase())) {
            io.to(`company:${a.companyId}`).emit('authentication_alert', a);
          }
        }
        if (hasCapability(a, 20)) {
          io.to(`company:${a.companyId}`).emit('api:event', a);
        }
        if (hasCapability(a, 19)) {
          io.to(`company:${a.companyId}`).emit('kernel:event', a);
        }
        if (hasCapability(a, 17)) {
          io.to(`company:${a.companyId}`).emit('patch:event', a);
        }
        if (hasCapability(a, 16)) {
          io.to(`company:${a.companyId}`).emit('insider:event', a);
        }
        if (hasCapability(a, 15)) {
          io.to(`company:${a.companyId}`).emit('email:event', a);
        }
        if (hasCapability(a, 14)) {
          io.to(`company:${a.companyId}`).emit('lateral:event', a);
        }
        if (hasCapability(a, 13)) {
          io.to(`company:${a.companyId}`).emit('credential:event', a);
        }
        if (hasCapability(a, 12)) {
          io.to(`company:${a.companyId}`).emit('data-security:event', a);
        }
        if (hasCapability(a, 11)) {
          io.to(`company:${a.companyId}`).emit('ueba:event', a);
        }
        if (hasCapability(a, 10)) {
          io.to(`company:${a.companyId}`).emit('usb:event', a);
        }
        if (hasCapability(a, 9)) {
          io.to(`company:${a.companyId}`).emit('webdns:event', a);
        }
        if (hasCapability(a, 8)) {
          io.to(`company:${a.companyId}`).emit('persistence:event', a);
        }
        if (hasCapability(a, 7)) {
          io.to(`company:${a.companyId}`).emit('system-change:event', a);
        }
        if (hasCapability(a, 6)) {
          io.to(`company:${a.companyId}`).emit('registry:event', a);
        }
        if (hasCapability(a, 28)) {
          io.to(`company:${a.companyId}`).emit('lolbins:event', a);
        }
        if (hasCapability(a, 25)) {
          io.to(`company:${a.companyId}`).emit('hash:alert', a);
          enrichHashAlertThreatIntel(a, io);
        }
        if (hasCapability(a, 24)) {
          io.to(`company:${a.companyId}`).emit('service:alert', a);
        }
        if (hasCapability(a, 23)) {
          io.to(`company:${a.companyId}`).emit('geo:event', a);
          io.to(`company:${a.companyId}`).emit('geo:anomaly', a);
        }
        if (hasCapability(a, 22)) {
          io.to(`company:${a.companyId}`).emit('time:anomaly', a);
        }
        if (hasCapability(a, 21)) {
          io.to(`company:${a.companyId}`).emit('script:event', a);
          enrichScriptThreatIntel(a, io);
        }
        if (hasCapability(a, 26)) {
          io.to(`company:${a.companyId}`).emit('beaconing:event', a);
          if (a.destip) {
            threatIntel.enrichAndMaybeBlock(a.destip, a.companyId, a._id, io)
              .then(() => io.to(`company:${a.companyId}`).emit('alert:updated', { _id: a._id, capabilityId: 26 }))
              .catch(error => console.error('[beacon threat intel batch]', error.message));
          } else if (a.domain) {
            threatIntel.enrichDomain(a.domain)
              .then(intel => intel && Alert.findByIdAndUpdate(a._id, {
                $set: {
                  tiEnriched: true, tiDomain: a.domain,
                  tiDomainMalicious: intel.isMalicious, tiSummary: intel.summary,
                  iocMatched: Boolean(intel.isMalicious),
                },
              }))
              .then(() => io.to(`company:${a.companyId}`).emit('alert:updated', { _id: a._id, capabilityId: 26 }))
              .catch(error => console.error('[beacon domain intel batch]', error.message));
          }
        }
        if (hasCapability(a, 27) || String(a.source || '').toLowerCase() === 'ransomware') {
          io.to(`company:${a.companyId}`).emit('ransomware:event', a);
        }

        // Metrics update widgets through memory:metric; they are not SIEM alerts.
        if (!isMemoryMetric && !routineTelemetry) io.to(`company:${a.companyId}`).emit('log:new', {
          _id: a._id,
          tenantId: a.tenantId,
          partnerId: a.partnerId,
          companyId: a.companyId,
          source: a.source || 'agent',
          agentName: a.agentName,
          hostname: a.agentName,
          logType: a.eventCategory || 'system',
          level: a.severity || 'info',
          message: `[${(a.severity || 'info').toUpperCase()}] ${a.ruleId || ''}: ${a.description || ''}`,
          receivedAt: a.createdAt || new Date(),
          format: 'alert',
          tags: [a.eventCategory, a.severity, 'alert'],
        });
      }
      io.to('superadmin').emit('alert:batch', { count: inserted.length });
    });

    // Run SOAR for critical/high alerts async
    setImmediate(() => {
      for (const a of inserted) {
        const isMemoryMetric = a.memoryMetricType || a.eventType === 'memory.metric';
        const routineTelemetry = isRoutineSecurityTelemetry(a);
        if (!isMemoryMetric && !routineTelemetry && (a.severity === 'critical' || a.severity === 'high')) {
          runSoarForAlert(a).catch(e => console.error('[SOAR batch]', e.message));
        }
        if (!isMemoryMetric && !routineTelemetry && a.source !== 'auto_response') {
          evaluatePlaybooksForAlert(a, req.app.get('io'))
            .catch(e => console.error('[automated response batch]', e.message));
        }
        if (a.ruleId === 'UEBA_INPUT_PROFILE_MISMATCH' && a.inputProfileMismatch === true) {
          require('../services/uebaProfileLock.service')
            .processProfileMismatchAlert(a, req.app.get('io'))
            .catch(error => console.error('[ueba profile mismatch batch]', error.message));
        }
        if (/^GEO_/i.test(String(a.ruleId || ''))
          && (a.rawEvent?.systemLogoutRequested || a.rawEvent?.sessionRevokeRequested
            || a.rawEvent?.geoFenceLockRequested || a.rawEvent?.lockRecommended)) {
          require('../services/uebaProfileLock.service')
            .processGeolocationProtectionAlert(a, req.app.get('io'))
            .catch(error => console.error('[geolocation protection log batch]', error.message));
        }
      }
    });

    // Batch ingestion must drive the same real-time correlation path as a
    // single alert. Debouncing keeps one scan per affected company/burst.
    const correlationService = require('../services/correlation.service');
    for (const companyId of new Set(inserted
      .filter(item => !item.memoryMetricType && item.eventType !== 'memory.metric' && !isRoutineSecurityTelemetry(item))
      .map(item => String(item.companyId)))) {
      correlationService.scheduleCompanyCorrelation(companyId, req.app.get('io'));
    }

    if (ALERT_CONSOLE_LOGS) {
      console.log(`[alert/batch] inserted ${inserted.length}/${docs.length} alerts`);
    }
    res.status(201).json({
      ok: true,
      inserted: inserted.length,
      duplicates: duplicateCount,
      total: docs.length,
    });
  } catch (err) {
    // insertMany with ordered:false returns partial success even on dups
    if (err.name === 'BulkWriteError') {
      const inserted = err.result?.nInserted || 0;
      const duplicateErrors = (err.writeErrors || []).filter(item => item.code === 11000).length;
      if (duplicateErrors === (err.writeErrors || []).length) {
        return res.status(200).json({
          ok: true,
          inserted,
          duplicates: duplicateErrors,
          total: alerts.length,
        });
      }
      console.warn(`[alert/batch] partial: ${inserted} inserted, ${err.writeErrors?.length} errors`);
      return res.status(207).json({ ok: true, inserted, errors: err.writeErrors?.length });
    }
    console.error('[alert/batch] error:', err.message);
    res.status(400).json({ message: err.message });
  }
});

router.use(authenticate);

// GET /api/alerts
router.get('/', requireAnalyst, async (req, res) => {
  const { severity, status, from, to, departmentId, category, sourceType, action, iocMatch, threatIntel, username, hostname, sourceIp, destinationIp, mitreTechnique, search } = req.query;
  const page = boundedInteger(req.query.page, { defaultValue: 1, max: 100000 });
  const limit = boundedInteger(req.query.limit, { defaultValue: 50, max: 200 });
  const filter = (await getUserDataFilter(req.user, { personal: false })).filter;

  // Investigation consumes security signals, while Log Monitor intentionally
  // retains the complete telemetry stream from the same event store.
  if (req.query.mode === 'investigation') {
    Object.assign(filter, socWorkItemFilter());
    // Threat Investigation is source-bounded. Endpoint/EDR detections stay in
    // the EDR and correlation workflows unless they arrive through one of the
    // explicitly supported intelligence/security-log sources.
    filter.$and = [
      ...(filter.$and || []),
      { $or: [
        { sourceType: { $in: ['IAM', 'IDS', 'IPS', 'ZEEK', 'THREAT_FEED'] } },
        { module: { $in: ['IDS', 'IPS'] } },
        { source: { $regex: /^(iam|auth|ids|ips|zeek|suricata|snort|threat[_ -]?feed|threat[_ -]?intel)$/i } },
        { detectionSource: { $regex: /^(iam|ids|ips|zeek|suricata|snort|threat intelligence)$/i } },
      ] },
      // Zeek emits raw dns/conn/http telemetry at a very high rate. Keep that
      // complete stream in Log Monitor, but require explicit threat evidence
      // before a Zeek event becomes an Investigation work item.
      { $or: [
        { $nor: [
          { sourceType: 'ZEEK' },
          { source: { $regex: /^zeek$/i } },
          { detectionSource: { $regex: /^zeek$/i } },
          { module: { $regex: /^zeek$/i } },
        ] },
        { iocMatched: true },
        { correlationIds: { $exists: true, $ne: [] } },
        { actionable: true },
        { blocked: true },
        { quarantined: true },
        { action: { $in: ['blocked', 'dropped', 'rejected', 'quarantined'] } },
        { vtVerdict: { $in: ['malicious', 'suspicious'] } },
        { tiEnriched: true, tiConfidence: { $gte: 50 } },
        { ruleId: { $regex: /malicious|suspicious|exploit|scan|c2|ioc.?match|dns.?tunnel|dga|tor|onion|spoof|cache.?poison/i } },
        { normalizedEventType: { $regex: /malicious|suspicious|exploit|scan|c2|ioc.?match|dns.?tunnel|dga|tor|onion|spoof|cache.?poison/i } },
        { eventName: { $regex: /malicious|suspicious|exploit|scan|c2|ioc.?match|dns.?tunnel|dga|tor|onion|spoof|cache.?poison/i } },
      ] },
    ];
  }

  if (req.query.companyId) {
    await assertCompanyScope(req.user, [req.query.companyId]);
    filter.companyId = req.query.companyId;
  }
  if (req.query.systemId) filter.systemId = req.query.systemId;
  if (req.user.role !== 'department_admin' && departmentId) filter.departmentId = departmentId;

  if (severity) filter.severity = severity;
  if (status)   filter.status   = status;
  if (category) filter.eventCategory = category;
  if (sourceType) filter.sourceType = String(sourceType).toUpperCase();
  if (action) filter.action = action;
  if (iocMatch === 'true') filter.iocMatched = true;
  if (iocMatch === 'false') filter.iocMatched = false;
  if (threatIntel === 'true') {
    filter.$or = [
      { iocMatched: true }, { sourceType: 'THREAT_FEED' }, { capabilityIds: 29 },
      { vtVerdict: { $in: ['malicious', 'suspicious'] } },
      { tiEnriched: true, tiConfidence: { $gte: 50 } },
    ];
  }
  if (username) filter.username = new RegExp(String(username).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
  if (hostname) filter.$or = [{ hostname: new RegExp(String(hostname).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') }, { agentName: new RegExp(String(hostname).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') }];
  if (sourceIp) filter.srcip = sourceIp;
  if (destinationIp) filter.destip = destinationIp;
  if (mitreTechnique) filter.mitreTechnique = mitreTechnique;
  if (search) {
    const rx = new RegExp(String(search).slice(0, 200).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    filter.$or = [{ description: rx }, { eventName: rx }, { ruleId: rx }, { srcip: rx }, { destip: rx }, { username: rx }, { hostname: rx }];
  }
  if (from || to) {
    filter.createdAt = {};
    if (from) filter.createdAt.$gte = new Date(from);
    if (to)   filter.createdAt.$lte = new Date(to);
  }

  try {
    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .populate('assignedTo', 'name email')
        .populate('departmentId', 'name')
        .populate('systemId', 'name hostname'),
      Alert.countDocuments(filter),
    ]);
    res.json({ alerts, total, page, limit });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/metadata/filters', requireAnalyst, async (req, res) => {
  try {
    const filter = (await getUserDataFilter(req.user, { personal: false })).filter;
    const [sources, categories, vendors] = await Promise.all([
      Alert.distinct('sourceType', filter), Alert.distinct('eventCategory', filter), Alert.distinct('sourceVendor', filter),
    ]);
    res.json({ sources: sources.filter(Boolean), categories: categories.filter(Boolean), vendors: vendors.filter(Boolean) });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/alerts/:id
router.get('/:id', requireAnalyst, async (req, res) => {
  try {
    const socRoles = ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'analyst'];
    const accessFilter = socRoles.includes(req.user.role)
      ? (await getUserDataFilter(req.user, { personal: false })).filter
      : scopeForUser(req.user, { departmentScoped: true });
    const alert = await Alert.findOne({ _id: req.params.id, ...accessFilter })
      .populate('assignedTo', 'name email')
      .populate('departmentId', 'name')
      .populate('systemId', 'name hostname')
      .populate('notes.user', 'name email');
    if (!alert) return res.status(404).json({ message: 'Alert not found' });
    res.json(alert);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/alerts/:id
router.patch('/:id', requireManager, async (req, res) => {
  try {
    const update = { ...req.body };
    if (update.status === 'resolved' && !update.resolvedAt) update.resolvedAt = new Date();
    const alert = await Alert.findOneAndUpdate(
      { _id: req.params.id, ...scopeForUser(req.user, { departmentScoped: true }) },
      update, { new: true }
    );
    if (!alert) return res.status(404).json({ message: 'Alert not found' });
    const io = req.app.get('io');
    io.to(`company:${alert.companyId}`).emit('alert:updated', alert);
    if (alert.departmentId) io.to(`dept:${alert.departmentId}`).emit('alert:updated', alert);
    io.to('superadmin').emit('alert:updated', alert);
    res.json(alert);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/alerts/:id/notes
router.post('/:id/notes', requireAnalyst, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
  const text = String(req.body.text || '').trim();
  if (!text) return res.status(400).json({ message: 'text is required' });
  if (text.length > 4000) return res.status(400).json({ message: 'text exceeds 4000 characters' });
  try {
    const alert = await Alert.findOneAndUpdate(
      { _id: req.params.id, ...scopeForUser(req.user, { departmentScoped: true }) },
      { $push: {
        notes: { user: req.user.id, text, at: new Date() },
        auditHistory: { action: 'note_added', actorId: req.user.id, at: new Date(), metadata: {} },
      } },
      { new: true }
    ).populate('notes.user', 'name');
    if (!alert) return res.status(404).json({ message: 'Alert not found' });
    req.app.get('io')?.to(`company:${alert.companyId}`).emit('alert:updated', alert);
    res.json(alert);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
