const crypto = require('crypto');

const SOURCE_TYPES = new Set(['IAM', 'IDS', 'IPS', 'ZEEK', 'THREAT_FEED']);
const ACTIONS = new Set(['detected', 'allowed', 'blocked', 'dropped', 'rejected', 'quarantined']);
const EVENT_CATEGORIES = new Set(['malware', 'network', 'file', 'system', 'registry', 'memory', 'systemchanges', 'persistence', 'edr', 'usb', 'isolation', 'other']);
const SECURITY_MODULES = new Set(['EDR', 'IDS', 'IPS', 'FIREWALL', 'WAF']);

function text(value) { return value == null ? '' : String(value).trim(); }
function number(value) { const parsed = Number(value); return Number.isFinite(parsed) ? parsed : undefined; }

function inferSecurityModule(body = {}, eventCategory = '') {
  const explicit = text(body.module).toUpperCase();
  if (SECURITY_MODULES.has(explicit)) return explicit;

  const sourceType = text(body.sourceType || body.source_type).toUpperCase();
  if (['IDS', 'IPS'].includes(sourceType)) return sourceType;

  const rule = text(body.rule_id || body.ruleId || body.type || body.event_type || body.eventType).toUpperCase();
  const source = text(body.log_source || body.source || body.sensor).toUpperCase();
  const action = text(body.action || body.actionTaken || body.action_taken).toLowerCase();
  const category = text(eventCategory || body.category || body.eventCategory).toLowerCase();

  if (/^FIREWALL_|HOST_FIREWALL|WINDOWS_DEFENDER_FIREWALL/.test(rule)
      || /^(FIREWALL|HOST-FIREWALL)$/.test(source)) return 'FIREWALL';
  if (/^WAF_|\bWAF\b/.test(`${rule} ${source}`)) return 'WAF';
  if (/^IPS_|ANDROID_IPS|INTRUSION_PREVENTION/.test(rule)
      || /\bIPS\b/.test(source)
      || body.blocked === true
      || ['blocked', 'dropped', 'rejected'].includes(action)) return 'IPS';
  if (/^IDS_|^NET_|^ANDROID_NETWORK|INTRUSION_DETECTION/.test(rule)
      || /\bIDS\b|SURICATA|SNORT|ZEEK/.test(source)
      || category === 'network') return 'IDS';
  if (['edr', 'file', 'system', 'registry', 'memory', 'systemchanges', 'persistence', 'usb', 'isolation', 'malware'].includes(category)
      || /^(PROC_|FILE_|AUTH_|SYS_|MEM_|REGISTRY_|USB_|YARA_|ANDROID_APP)/.test(rule)) return 'EDR';
  return undefined;
}

function inferSourceType(body = {}) {
  const module = inferSecurityModule(body);
  const haystack = `${body.sourceType || ''} ${body.source_type || ''} ${body.module || module || ''} ${body.log_source || ''} ${body.source || ''} ${body.sensor || ''}`.toUpperCase();
  if (/\bIAM\b|AUTH|LOGIN|IDENTITY/.test(haystack) || /login|mfa|password|role|permission|session|token/i.test(body.eventType || body.event_type || body.userAction || body.user_action || '')) return 'IAM';
  if (/\bZEEK\b/.test(haystack)) return 'ZEEK';
  if (/THREAT.?FEED|\bIOC\b/.test(haystack)) return 'THREAT_FEED';
  if (/\bIPS\b/.test(haystack) || body.blocked === true || ['blocked', 'dropped', 'rejected'].includes(text(body.action).toLowerCase())) return 'IPS';
  if (/\bIDS\b|SURICATA|SNORT/.test(haystack)) return 'IDS';
  return null;
}

function normalizeAction(body = {}, sourceType) {
  const raw = text(body.action || body.actionTaken || body.action_taken).toLowerCase();
  const aliases = { block: 'blocked', drop: 'dropped', reject: 'rejected', quarantine: 'quarantined', detect: 'detected', alert: 'detected', pass: 'allowed' };
  const mapped = aliases[raw] || raw;
  if (ACTIONS.has(mapped)) return mapped;
  if (body.quarantined === true) return 'quarantined';
  if (body.blocked === true) return 'blocked';
  // IDS is detection-only unless the vendor explicitly confirms prevention.
  return sourceType === 'IPS' && body.success === false ? 'allowed' : 'detected';
}

function normalizeSecurityEvent(body = {}) {
  const module = inferSecurityModule(body);
  const sourceType = inferSourceType(body);
  const sourceIp = text(body.sourceIp || body.src_ip || body.srcip) || undefined;
  const destinationIp = text(body.destinationIp || body.dst_ip || body.dest_ip || body.destip || body.destIp) || undefined;
  const eventType = text(body.eventType || body.event_type || body.rule_id || body.ruleId || body.type) || 'SECURITY_EVENT';
  const action = normalizeAction(body, sourceType);
  const eventTimestamp = body.eventTimestamp || body.timestamp || body.event_time || body.createdAt || new Date();
  const fingerprintBasis = [body.vendorEventId || body.event_id || body.eventId, sourceType, eventType, eventTimestamp, sourceIp, destinationIp, body.username || body.user, body.signatureId || body.signature_id].filter(Boolean).join('|');
  return {
    module,
    sourceType: SOURCE_TYPES.has(sourceType) ? sourceType : undefined,
    sourceVendor: text(body.sourceVendor || body.vendor || body.detectionSource || body.detection_source || body.sensor) || undefined,
    normalizedEventType: eventType,
    eventName: text(body.eventName || body.event_name || body.description || body.signatureName || body.signature_name) || eventType,
    eventTimestamp: new Date(eventTimestamp),
    receivedAt: new Date(),
    action,
    sourceIp,
    sourcePort: number(body.sourcePort ?? body.src_port ?? body.srcPort),
    destinationIp,
    destinationPort: number(body.destinationPort ?? body.dst_port ?? body.destPort ?? body.port),
    url: text(body.url) || undefined,
    signatureId: text(body.signatureId || body.signature_id || body.sid) || undefined,
    signatureName: text(body.signatureName || body.signature_name) || undefined,
    mitreTactic: text(body.mitreTactic || body.mitre_tactic) || undefined,
    mitreTechnique: text(body.mitreTechnique || body.mitre_technique || body.mitreId) || undefined,
    eventFingerprint: crypto.createHash('sha256').update(fingerprintBasis || JSON.stringify(body)).digest('hex'),
    metadata: body.metadata && typeof body.metadata === 'object' ? body.metadata : {},
  };
}

function normalizeEventCategory(value, fallback = 'other') {
  const category = text(value).toLowerCase().replace(/[\s-]+/g, '_');
  if (EVENT_CATEGORIES.has(category)) return category;
  if (['dns', 'web', 'http', 'https', 'ssl', 'tls', 'connection', 'ids', 'ips', 'zeek'].includes(category)) return 'network';
  if (['iam', 'auth', 'authentication', 'identity', 'user'].includes(category)) return 'edr';
  if (['process', 'service', 'host', 'endpoint'].includes(category)) return 'system';
  if (['fim', 'file_integrity'].includes(category)) return 'file';
  return EVENT_CATEGORIES.has(fallback) ? fallback : 'other';
}

function isThreatInvestigationEligible(event = {}) {
  const sourceType = event.sourceType || inferSourceType(event);
  if (!sourceType) return false;
  if (event.iocMatched || (event.iocMatches || []).length) return true;
  if (event.correlationIds?.length) return true;
  if (event.actionable === true || ['blocked', 'dropped', 'rejected', 'quarantined'].includes(event.action)) return true;
  if (['malicious', 'suspicious'].includes(String(event.vtVerdict || '').toLowerCase())) return true;
  if (event.tiEnriched === true && Number(event.tiConfidence) >= 50) return true;
  const hasThreatPattern = /brute|impossible|malicious|suspicious|exploit|scan|c2|command.?and.?control|mfa.?bypass|disabled.?account|ioc.?match|dns.?tunnel|dga|tor|onion|spoof|cache.?poison/i.test(`${event.ruleId || ''} ${event.normalizedEventType || ''} ${event.eventName || ''} ${event.description || ''}`);
  if (hasThreatPattern) return true;
  // Zeek dns/conn/http rows are network telemetry, even when a collector gives
  // them a high severity. They enter Investigation only with threat evidence.
  if (sourceType === 'ZEEK') return false;
  if (sourceType === 'THREAT_FEED') return true;
  return ['high', 'critical'].includes(String(event.severity || '').toLowerCase());
}

function calculateSecurityRisk(event = {}) {
  const severity = { informational: 5, low: 15, medium: 35, high: 65, critical: 85 }[String(event.severity || '').toLowerCase()] || 10;
  let score = severity;
  score += Math.round((number(event.iocConfidence || event.tiConfidence) || 0) * 0.2);
  if (event.privilegedUser) score += 10;
  if (event.assetCriticality === 'critical') score += 10;
  if ((event.correlationIds || []).length) score += 12;
  if (event.action === 'allowed' && event.iocMatched) score += 8;
  if (['blocked', 'dropped', 'quarantined'].includes(event.action)) score -= 5;
  return Math.max(0, Math.min(100, score));
}

module.exports = { inferSecurityModule, inferSourceType, normalizeAction, normalizeSecurityEvent, normalizeEventCategory, isThreatInvestigationEligible, calculateSecurityRisk };
