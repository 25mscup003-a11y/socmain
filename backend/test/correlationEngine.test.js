const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const CorrelationEvent = require('../src/models/CorrelationEvent.model');
const CorrelationRule = require('../src/models/CorrelationRule.model');
const EdrIncident = require('../src/models/EdrIncident.model');
const SoarRule = require('../src/models/SoarRule.model');
const {
  PATTERNS,
  PATTERN_INTELLIGENCE,
  alertTimeline,
  calculateRisk,
  severityFromCorrelationRisk,
  calculateCorrelationConfidence,
  extractIocs,
  isConfirmedMalware,
  isSuspiciousOutbound,
  isRansomwareImpact,
  isSuspiciousExecution,
  matchPatternAlerts,
  matchLatestPatternAlerts,
  matchSignature,
  shouldNotifyCorrelationUpdate,
  mergeByAlertId,
  conditionMatches,
  customRuleToPattern,
  isCredentialAccess,
  isHighConfidenceEdrExecution,
  isThreatIntelNetwork,
  ROUTINE_RULE_IDS,
  correlationEligibleFilter,
  correlationGroupKey,
  correlationIncidentSource,
  EDR_CAPABILITY_COVERAGE,
  patternCapabilityIds,
} = require('../src/services/correlation.service');

test('correlation rules expose complete MITRE mappings', () => {
  assert.ok(PATTERNS.length >= 7);
  for (const pattern of PATTERNS) {
    assert.ok(PATTERN_INTELLIGENCE[pattern.id], `${pattern.id} requires MITRE mapping`);
    assert.ok(PATTERN_INTELLIGENCE[pattern.id].techniques.length > 0);
    assert.ok(PATTERN_INTELLIGENCE[pattern.id].tactics.length > 0);
  }
});

test('routine kernel inventory is excluded from correlation candidates', () => {
  assert.ok(ROUTINE_RULE_IDS.includes('KERNEL_INVENTORY_SNAPSHOT'));
});

test('correlation rules cover every core EDR capability from 1 through 31', () => {
  const covered = new Set(Object.values(EDR_CAPABILITY_COVERAGE).flat());
  assert.deepEqual(Array.from({ length: 31 }, (_, index) => index + 1).filter(id => !covered.has(id)), []);
  for (const pattern of PATTERNS) {
    assert.deepEqual(patternCapabilityIds(pattern.id), [...patternCapabilityIds(pattern.id)].sort((a, b) => a - b));
  }
});

test('timeline is chronological and preserves evidence identity', () => {
  const later = { _id: 'b', createdAt: new Date('2026-01-02'), eventCategory: 'network', severity: 'critical', description: 'C2' };
  const earlier = { _id: 'a', createdAt: new Date('2026-01-01'), eventCategory: 'malware', severity: 'high', description: 'Dropper' };
  const timeline = alertTimeline([later, earlier]);
  assert.deepEqual(timeline.map(item => item.alertId), ['a', 'b']);
  assert.equal(timeline[0].category, 'malware');
});

test('risk scoring is bounded and severity-aware', () => {
  const pattern = { confidence: 90 };
  const high = calculateRisk(pattern, [{ severity: 'critical', eventCategory: 'malware' }, { severity: 'high', eventCategory: 'network' }]);
  const low = calculateRisk(pattern, [{ severity: 'low', eventCategory: 'file' }]);
  assert.ok(high > low);
  assert.ok(high <= 100 && low >= 0);
});

test('calibrated correlation scoring can produce low and medium risk chains', () => {
  const pattern = { confidence: 80, riskScore: 70 };
  const low = calculateRisk(pattern, [
    { severity: 'medium', eventCategory: 'edr' },
    { severity: 'medium', eventCategory: 'edr' },
  ]);
  const medium = calculateRisk(pattern, [
    { severity: 'high', eventCategory: 'edr' },
    { severity: 'high', eventCategory: 'network' },
  ]);
  assert.ok(low >= 50 && low < 65, `expected low band, received ${low}`);
  assert.ok(medium >= 65 && medium < 75, `expected medium band, received ${medium}`);
});

test('custom correlation risk stays inside its configured start/end range', () => {
  const pattern = { confidence: 75, riskScore: 65, riskScoreMin: 60, riskScoreMax: 70 };
  const score = calculateRisk(pattern, [
    { severity: 'critical', eventCategory: 'malware', vtVerdict: 'malicious' },
    { severity: 'critical', eventCategory: 'network', blocked: true },
  ]);
  assert.ok(score >= 60 && score <= 70);
});

test('correlation severity follows configured risk thresholds', () => {
  assert.equal(severityFromCorrelationRisk(50), 'low');
  assert.equal(severityFromCorrelationRisk(64), 'low');
  assert.equal(severityFromCorrelationRisk(65), 'medium');
  assert.equal(severityFromCorrelationRisk(74), 'medium');
  assert.equal(severityFromCorrelationRisk(75), 'high');
  assert.equal(severityFromCorrelationRisk(89), 'high');
  assert.equal(severityFromCorrelationRisk(90), 'critical');
});

test('correlation confidence is derived from risk and matched evidence', () => {
  const pattern = { confidence: 70, requires: [() => true, () => true] };
  const weak = calculateCorrelationConfidence(pattern, [{ severity: 'medium', eventCategory: 'edr' }], 55);
  const strong = calculateCorrelationConfidence(pattern, [
    { severity: 'high', eventCategory: 'malware', vtVerdict: 'malicious' },
    { severity: 'high', eventCategory: 'network', action: 'blocked', blocked: true },
  ], 85);
  assert.ok(strong > weak);
  assert.ok(weak >= 0 && strong <= 100);
});

test('IOC extraction deduplicates multi-module indicators', () => {
  const iocs = extractIocs([
    { srcip: '10.0.0.8', domain: 'evil.test', fileHash: 'abc' },
    { srcip: '10.0.0.8', destip: '203.0.113.9' },
  ]);
  assert.deepEqual(iocs, ['10.0.0.8', 'evil.test', 'abc', '203.0.113.9']);
});

test('malware plus C2 correlation rejects unclassified network traffic', () => {
  assert.equal(isConfirmedMalware({
    eventCategory: 'malware', ruleId: 'YARA_MATCH', status: 'open',
    severity: 'high', yaraRules: ['Known_Trojan'],
  }), true);
  assert.equal(isConfirmedMalware({
    eventCategory: 'malware', ruleId: 'YARA_MATCH', status: 'open', severity: 'low',
  }), false);
  assert.equal(isConfirmedMalware({
    eventCategory: 'malware', ruleId: 'RANSOMWARE_MASS_ENCRYPTION',
    description: 'Mass encryption [UNDER OBSERVATION — VT data unavailable]', status: 'open',
  }), false);
  assert.equal(isConfirmedMalware({ eventCategory: 'malware', description: 'generic observation', status: 'open' }), false);
  assert.equal(isSuspiciousOutbound({ eventCategory: 'network', direction: 'outbound', severity: 'low' }), false);
  assert.equal(isSuspiciousOutbound({
    eventCategory: 'network', direction: 'outbound', severity: 'critical',
    description: 'C2 beacon detected',
  }), true);
  assert.equal(isSuspiciousOutbound({
    eventCategory: 'network', direction: 'outbound', severity: 'high',
    description: 'DNS resolution changed for google.com',
  }), false);
  assert.equal(isSuspiciousOutbound({
    eventCategory: 'network', direction: 'outbound', severity: 'medium',
    description: 'Threat intelligence scan: connection requires reputation review',
  }), false);
  assert.equal(isSuspiciousOutbound({
    eventCategory: 'network', direction: 'inbound', severity: 'critical',
    description: 'C2 beacon detected',
  }), false);
});

test('ransomware chain rejects routine file, service and network telemetry', () => {
  assert.equal(isRansomwareImpact({
    eventCategory: 'file', fileAction: 'modified', severity: 'low',
    ruleId: 'FILE_MODIFIED', description: 'File modified: Chrome.sqlite-wal',
  }), false);
  assert.equal(isSuspiciousExecution({
    eventCategory: 'system', severity: 'medium',
    ruleId: 'SYS_SERVICE_FAIL', description: 'System service failed',
  }), false);
  assert.equal(isSuspiciousOutbound({
    eventCategory: 'network', direction: 'outbound', severity: 'low',
    ruleId: 'NET_CONNECTION_SUMMARY', description: 'Live network summary',
  }), false);
});

test('ransomware chain requires confirmed impact and suspicious execution', () => {
  assert.equal(isRansomwareImpact({
    eventCategory: 'malware', severity: 'critical', actionable: true,
    ruleId: 'RANSOMWARE_MASS_ENCRYPTION', description: 'Mass file encryption detected: 900 files changed',
  }), true);
  assert.equal(isRansomwareImpact({
    eventCategory: 'malware', severity: 'critical', actionable: false,
    ruleId: 'RANSOMWARE_MASS_ENCRYPTION',
    description: 'Mass file encryption detected [UNDER OBSERVATION — VT data unavailable]',
  }), false);
  assert.equal(isSuspiciousExecution({
    eventCategory: 'edr', severity: 'high', ruleId: 'LOLBIN_DETECTED',
    description: 'PowerShell launched encoded command',
  }), true);
});

test('a correlation contains only the exact ordered evidence chain', () => {
  const pattern = {
    requires: [
      alert => alert.eventCategory === 'malware',
      alert => alert.eventCategory === 'network',
    ],
  };
  const alerts = [
    { _id: 'm1', createdAt: '2026-01-01T00:00:00Z', eventCategory: 'malware' },
    { _id: 'm2', createdAt: '2026-01-01T00:01:00Z', eventCategory: 'malware' },
    { _id: 'n1', createdAt: '2026-01-01T00:02:00Z', eventCategory: 'network' },
    { _id: 'n2', createdAt: '2026-01-01T00:03:00Z', eventCategory: 'network' },
  ];
  assert.deepEqual(matchPatternAlerts(alerts, pattern).map(alert => alert._id), ['m1', 'n1']);
});

test('IDS prevention correlation accepts normalized IPS and confirmed firewall outcomes', () => {
  const pattern = PATTERNS.find(item => item.id === 'IDS_IPS_CORRELATION');
  const ids = { _id: 'ids', createdAt: '2026-01-01T00:00:00Z', sourceType: 'IDS', action: 'detected' };
  const ips = { _id: 'ips', createdAt: '2026-01-01T00:01:00Z', sourceType: 'IPS', normalizedEventType: 'IPS_BLOCK_ATTEMPT', ruleId: 'IPS_AUTO_BLOCK', action: 'blocked' };
  const applied = { _id: 'applied', createdAt: '2026-01-01T00:01:00Z', sourceType: 'IPS', ruleId: 'IPS_BLOCK_APPLIED', action: 'blocked' };
  const firewall = { _id: 'fw', createdAt: '2026-01-01T00:01:00Z', ruleId: 'FIREWALL_BLOCK_IP', blocked: true, actionTaken: 'Blocked' };
  assert.deepEqual(matchPatternAlerts([ids, ips], pattern).map(item => item._id), ['ids', 'ips']);
  assert.deepEqual(matchPatternAlerts([ids, applied], pattern).map(item => item._id), ['ids', 'applied']);
  assert.deepEqual(matchPatternAlerts([ids, firewall], pattern).map(item => item._id), ['ids', 'fw']);
});

test('latest matcher advances an incident when genuinely new evidence arrives', () => {
  const pattern = {
    id: 'TEST_CHAIN',
    requires: [
      alert => alert.eventCategory === 'malware',
      alert => alert.eventCategory === 'network',
    ],
  };
  const alerts = [
    { _id: 'm1', createdAt: '2026-01-01T00:00:00Z', eventCategory: 'malware' },
    { _id: 'n1', createdAt: '2026-01-01T00:01:00Z', eventCategory: 'network' },
    { _id: 'm2', createdAt: '2026-01-01T00:02:00Z', eventCategory: 'malware' },
    { _id: 'n2', createdAt: '2026-01-01T00:03:00Z', eventCategory: 'network' },
  ];
  const latest = matchLatestPatternAlerts(alerts, pattern);
  assert.deepEqual(latest.map(alert => alert._id), ['m2', 'n2']);
  assert.equal(matchSignature(pattern, latest), 'TEST_CHAIN:m2:n2');
});

test('correlation update notifications use the last notification, not continuous activity', () => {
  const now = new Date('2026-08-27T12:00:00Z').getTime();
  const elevenMinutesAgo = new Date(now - (11 * 60 * 1000));
  const oneMinuteAgo = new Date(now - (60 * 1000));

  assert.equal(shouldNotifyCorrelationUpdate({
    createdAt: new Date(now - (60 * 60 * 1000)),
    lastNotifiedAt: elevenMinutesAgo,
    lastActivityAt: oneMinuteAgo,
    riskScore: 70,
  }, 70, now), true);
  assert.equal(shouldNotifyCorrelationUpdate({
    createdAt: new Date(now - (60 * 60 * 1000)),
    lastNotifiedAt: oneMinuteAgo,
    lastActivityAt: oneMinuteAgo,
    riskScore: 70,
  }, 70, now), false);
  assert.equal(shouldNotifyCorrelationUpdate({
    lastNotifiedAt: oneMinuteAgo,
    riskScore: 70,
  }, 80, now), true);
});

test('routine correlation decision logs are debug-only', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/services/correlation.service.js'), 'utf8');
  assert.doesNotMatch(source, /console\.log\(`\[CORRELATION\] decision=/);
  assert.match(source, /if \(CORRELATION_DEBUG\) \{[\s\S]*console\.debug\(`\[CORRELATION\] decision=/);
});

test('incident timeline merge is deduplicated, chronological, and bounded', () => {
  const existing = [{ alertId: 'a', timestamp: '2026-01-01T00:00:00Z' }];
  const incoming = [
    { alertId: 'a', timestamp: '2026-01-01T00:00:00Z' },
    { alertId: 'b', timestamp: '2026-01-01T00:01:00Z' },
    { alertId: 'c', timestamp: '2026-01-01T00:02:00Z' },
  ];
  assert.deepEqual(mergeByAlertId(existing, incoming, 2).map(item => item.alertId), ['b', 'c']);
});

test('correlation incident schema contains investigation fields and tenant indexes', () => {
  for (const field of [
    'incidentId', 'tenantId', 'riskScore', 'timeline', 'mitreTechniques',
    'evidence', 'resolutionHistory', 'lastActivityAt', 'suppressedDuplicateCount',
    'relatedAlertIds', 'occurrenceCount', 'lastMatchSignature', 'lastNotifiedAt',
    'verdict', 'dispositionReason', 'managerVisibleAt', 'linkedIncidentId', 'coveredCapabilityIds',
  ]) {
    assert.ok(CorrelationEvent.schema.path(field), `${field} must exist`);
  }
  const indexes = CorrelationEvent.schema.indexes().map(([keys]) => Object.keys(keys).join(','));
  assert.ok(indexes.some(keys => keys.includes('tenantId') && keys.includes('companyId')));
});

test('correlated incidents have a deduplicating correlation link', () => {
  assert.ok(EdrIncident.schema.path('correlationId'));
  const indexes = EdrIncident.schema.indexes();
  assert.ok(indexes.some(([keys, options]) => keys.companyId && keys.correlationId && options.unique && options.sparse));
});

test('custom rule DSL is bounded and honors thresholds and windows', () => {
  assert.equal(conditionMatches({ source: 'suricata' }, { field: 'source', operator: 'equals', value: 'Suricata' }), true);
  assert.equal(conditionMatches({ description: 'secret' }, { field: 'description', operator: 'contains', value: 'secret' }), false, 'unapproved fields fail closed');
  const pattern = customRuleToPattern({
    _id: 'rule1', name: 'Repeated C2', severity: 'critical', confidence: 90,
    departmentId: 'department-1',
    threshold: 2, timeWindowSeconds: 300, logic: 'AND',
    conditions: [{ field: 'eventCategory', operator: 'equals', value: 'network' }, { field: 'blocked', operator: 'equals', value: false }],
  });
  assert.equal(pattern.requires.length, 2);
  assert.equal(pattern.timeWindowMs, 300000);
  assert.equal(pattern.departmentId, 'department-1');
  assert.equal(pattern.requires[0]({ eventCategory: 'network', blocked: false }), true);
});

test('custom correlation rules support validated department scope end to end', () => {
  assert.ok(CorrelationRule.schema.path('departmentId'));
  const service = fs.readFileSync(path.join(__dirname, '../src/services/correlation.service.js'), 'utf8');
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/correlation.routes.js'), 'utf8');
  const page = fs.readFileSync(path.join(__dirname, '../../company/src/pages/CorrelationPage.jsx'), 'utf8');
  assert.match(service, /pattern\.departmentId[\s\S]+sysData\.departmentId/);
  assert.match(routes, /resolveRuleDepartment[\s\S]+Department\.findOne\(\{ _id: departmentId, companyId \}\)/);
  assert.match(page, /<option value="">All Departments<\/option>/);
  assert.match(page, /departmentId: form\.departmentId \|\| null/);
  assert.match(page, /isDepartmentAdmin[\s\S]+visibleDepartments[\s\S]+disabled=\{isDepartmentAdmin\}/);
  assert.match(routes, /CUSTOM_RULE_ROLES[\s\S]+department_admin/);
  assert.match(routes, /customRuleScope[\s\S]+departmentId: req\.user\.departmentId/);
  assert.match(routes, /resolveAuthorizedRuleDepartment[\s\S]+req\.user\.departmentId/);
});

test('SOC/SIEM/EDR rules match real actionable telemetry and reject summaries', () => {
  assert.equal(isCredentialAccess({ severity: 'high', ruleId: 'FILE_MODIFIED', description: 'Credential file accessed: application_default_credentials.json' }), true);
  assert.equal(isCredentialAccess({ severity: 'low', ruleId: 'FILE_MODIFIED', description: 'File modified: Chrome.sqlite-wal' }), false);
  assert.equal(isHighConfidenceEdrExecution({ severity: 'high', ruleId: 'PROC_UNAUTHORIZED_EXECUTION', processName: 'bwrap', processCmdline: '/usr/bin/bwrap --bind /run/user/1000' }), false);
  assert.equal(isHighConfidenceEdrExecution({ severity: 'critical', ruleId: 'LOLBIN_DETECTED', processName: 'powershell', processCmdline: 'powershell -encodedcommand AAA' }), true);
  assert.equal(isThreatIntelNetwork({ eventCategory: 'network', severity: 'medium', ruleId: 'NET_THREAT_INTEL_SUMMARY', description: '2 connections require reputation review' }), true);
  assert.equal(isThreatIntelNetwork({ eventCategory: 'network', severity: 'low', ruleId: 'NET_CONNECTION_SUMMARY', description: 'Live network summary' }), false);
  for (const id of ['EDR_CREDENTIAL_ACCESS', 'REMOTE_ROOT_ACCESS', 'EDR_PERSISTENCE_CHAIN', 'DNS_NETWORK_ANOMALY']) {
    assert.ok(PATTERNS.some(pattern => pattern.id === id), `${id} must be registered`);
  }
});

test('correlation query excludes routine telemetry and synthetic events', () => {
  for (const id of ['FILE_CREATED', 'PROC_STARTED', 'PROC_INVENTORY_SUMMARY', 'NET_CONNECTION_SUMMARY',
    'SURICATA_stats', 'SURICATA_2200003', 'SURICATA_2210045', 'SURICATA_2210046',
    'ZEEK_truncated_tcp_payload']) {
    assert.ok(ROUTINE_RULE_IDS.includes(id));
  }
  const filter = correlationEligibleFilter('company-id', new Date('2026-01-01'));
  assert.equal(filter.isSynthetic.$ne, true);
  assert.ok(filter.$and.some(part => part.ticketOpenedAt === null));
  assert.ok(filter.$and.some(part => part.ticketSource?.$ne === 'soar'));
  assert.ok(filter.$and.some(part => part.socCaseType?.$ne === 'ticket'));
  assert.ok(filter.$and.some(part => part.ruleId?.$nin?.includes('PROC_INVENTORY_SUMMARY')));
  const evidenceGate = filter.$and.find(part => Array.isArray(part.$or));
  assert.ok(evidenceGate.$or.some(part => part.iocMatched === true), 'low IOC evidence must be eligible');
  assert.ok(evidenceGate.$or.some(part => part.normalizedEventType?.$regex), 'low suspicious detections must be eligible');
});

test('correlation entity grouping enforces department isolation', () => {
  const sharedEndpoint = { systemId: 'asset-1', agentName: 'linux', hostname: 'host' };
  assert.notEqual(
    correlationGroupKey({ ...sharedEndpoint, departmentId: 'department-a' }),
    correlationGroupKey({ ...sharedEndpoint, departmentId: 'department-b' }),
  );
  assert.equal(correlationGroupKey({ ruleId: 'SURICATA_stats' }), null);
});

test('correlation incidents are routed by evidence origin', () => {
  assert.equal(correlationIncidentSource({ id: 'ZEEK_IOC_MATCH' }, [{ sourceType: 'ZEEK', iocMatched: true }]), 'threat_intelligence');
  assert.equal(correlationIncidentSource({ id: 'DNS_NETWORK_ANOMALY' }, [{ sourceType: 'ZEEK' }]), 'threat_intelligence');
  assert.equal(correlationIncidentSource({ id: 'IAM_IDS_CORRELATION' }, [{ sourceType: 'IAM' }, { sourceType: 'IDS' }]), 'edr');
  assert.equal(correlationIncidentSource({ id: 'IAM_IDS_CORRELATION' }, [{ sourceType: 'IAM', iocMatched: true }, { sourceType: 'IDS' }]), 'threat_intelligence');
});

test('SOAR rules support correlation lifecycle triggers', () => {
  const triggerTypes = SoarRule.schema.path('triggerType').enumValues;
  assert.ok(triggerTypes.includes('correlation_created'));
  assert.ok(triggerTypes.includes('correlation_updated'));
});
