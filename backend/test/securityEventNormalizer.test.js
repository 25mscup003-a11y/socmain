const test = require('node:test');
const assert = require('node:assert/strict');
const { inferSecurityModule, normalizeSecurityEvent, normalizeEventCategory, isThreatInvestigationEligible, calculateSecurityRisk } = require('../src/utils/securityEventNormalizer');

test('normalizes IAM login fields and produces a stable fingerprint', () => {
  const raw = { sourceType: 'IAM', event_type: 'LOGIN_FAILED', username: 'alice', src_ip: '203.0.113.8', timestamp: '2026-01-01T00:00:00Z' };
  const first = normalizeSecurityEvent(raw); const second = normalizeSecurityEvent(raw);
  assert.equal(first.sourceType, 'IAM'); assert.equal(first.sourceIp, '203.0.113.8'); assert.equal(first.action, 'detected');
  assert.equal(first.eventFingerprint, second.eventFingerprint);
});

test('IDS remains detected unless prevention is explicitly reported', () => {
  assert.equal(normalizeSecurityEvent({ module: 'IDS', sensor: 'Suricata', action: 'alert' }).action, 'detected');
});

test('IPS action mapping preserves blocked and dropped outcomes', () => {
  assert.equal(normalizeSecurityEvent({ module: 'IPS', action: 'block' }).action, 'blocked');
  assert.equal(normalizeSecurityEvent({ module: 'IPS', action: 'drop' }).action, 'dropped');
});

test('Zeek IOC match is investigation eligible', () => {
  const event = { ...normalizeSecurityEvent({ source: 'zeek', event_type: 'dns' }), iocMatched: true, severity: 'medium' };
  assert.equal(isThreatInvestigationEligible(event), true);
});

test('routine Zeek DNS telemetry is excluded even when marked high severity', () => {
  const event = { ...normalizeSecurityEvent({ source: 'zeek', event_type: 'dns' }), severity: 'high', ruleId: 'ZEEK_dns' };
  assert.equal(isThreatInvestigationEligible(event), false);
});

test('explicitly suspicious Zeek detection remains investigation eligible', () => {
  const event = { ...normalizeSecurityEvent({ source: 'zeek', event_type: 'dns_tunnel' }), severity: 'medium', ruleId: 'ZEEK_DNS_TUNNEL' };
  assert.equal(isThreatInvestigationEligible(event), true);
});

test('maps DNS and network sensor aliases to the canonical network category', () => {
  assert.equal(normalizeEventCategory('dns'), 'network');
  assert.equal(normalizeEventCategory('zeek'), 'network');
  assert.equal(normalizeEventCategory('network'), 'network');
});

test('legacy DNS alerts normalize before mongoose enum validation', async () => {
  const Alert = require('../src/models/Alert.model');
  const alert = new Alert({ eventCategory: 'dns', description: 'Zeek DNS IOC match' });
  await assert.rejects(alert.validate(), /companyId/);
  assert.equal(alert.eventCategory, 'network');
});

test('normal resource usage is excluded without malicious evidence', () => {
  assert.equal(isThreatInvestigationEligible({ sourceType: 'IDS', eventName: 'Memory spike', severity: 'medium' }), false);
});

test('generic EDR telemetry is not classified as a Threat Investigation source', () => {
  const event = normalizeSecurityEvent({ source: 'edr', event_type: 'PROC_SUSPICIOUS', severity: 'high' });
  assert.equal(event.sourceType, undefined);
});

test('classifies endpoint telemetry for module-specific dashboards', () => {
  assert.equal(inferSecurityModule({ rule_id: 'PROC_INVENTORY_SUMMARY', category: 'system' }), 'EDR');
  assert.equal(inferSecurityModule({ rule_id: 'ANDROID_APP_ACTIVITY', category: 'edr' }), 'EDR');
  assert.equal(inferSecurityModule({ rule_id: 'ANDROID_NETWORK_STATUS', category: 'network' }), 'IDS');
  assert.equal(inferSecurityModule({ rule_id: 'android_ips_block', blocked: true }), 'IPS');
  assert.equal(inferSecurityModule({ rule_id: 'FIREWALL_BLOCK_IP' }), 'FIREWALL');
  assert.equal(inferSecurityModule({ rule_id: 'WAF_AGENT_STATUS', category: 'network', source: 'waf' }), 'WAF');
  assert.equal(inferSecurityModule({ rule_id: 'WAF_SQL_INJECTION', source: 'waf', blocked: true }), 'WAF');
});

test('inferred IDS and IPS modules also populate canonical source type', () => {
  assert.equal(normalizeSecurityEvent({ rule_id: 'NET_CONNECTION_SUMMARY', category: 'network' }).sourceType, 'IDS');
  assert.equal(normalizeSecurityEvent({ rule_id: 'ANDROID_IPS_BLOCK', blocked: true }).sourceType, 'IPS');
});

test('risk score accounts for IOC, privilege, correlation and prevention', () => {
  const allowed = calculateSecurityRisk({ severity: 'medium', tiConfidence: 70, privilegedUser: true, iocMatched: true, action: 'allowed', correlationIds: ['x'] });
  const blocked = calculateSecurityRisk({ severity: 'medium', tiConfidence: 70, privilegedUser: true, iocMatched: true, action: 'blocked', correlationIds: ['x'] });
  assert.ok(allowed > blocked); assert.ok(allowed <= 100);
});
