const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const workspace = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(workspace, relative), 'utf8');
const { _private } = require('../src/routes/time-anomaly.routes');

test('time anomaly canonical event preserves agent baseline evidence', () => {
  const event = _private.canonicalTimeEvent({
    ruleId: 'TIME_SCRIPT_EXECUTION',
    severity: 'high',
    riskScore: 72,
    createdAt: new Date('2026-08-30T18:45:00.000Z'),
    rawEvent: {
      actual_time: '2026-08-31T00:15:00+05:30',
      expected_time: '08:00-20:00',
      baseline_diff: 'Historical frequency 1.2%',
      baseline_confidence: 85,
      raw: { local_hour: 0, weekday: 0, after_hours: true, source_event: 'WIN_POWERSHELL' },
    },
  });
  assert.equal(event.localHour, 0);
  assert.equal(event.afterHours, true);
  assert.equal(event.expectedTime, '08:00-20:00');
  assert.equal(event.baselineConfidence, 85);
  assert.equal(event.sourceEvent, 'WIN_POWERSHELL');
});

test('time anomaly summary counts all affected actors, not only top ten', () => {
  const events = Array.from({ length: 14 }, (_, index) => ({
    username: `user-${index}`,
    hostname: `host-${index}`,
    anomalyType: 'After-hours Authentication',
    severity: 'medium',
    riskScore: 50,
    localHour: 2,
    weekday: 0,
    afterHours: true,
    timestamp: new Date(2026, 7, 30, 2, index),
  }));
  const summary = _private.summarize(events, events.length, []);
  assert.equal(summary.affectedUsers, 14);
  assert.equal(summary.affectedHosts, 14);
  assert.equal(summary.topUsers.length, 10);
});

test('time policy payload is bounded and rejects malformed values', () => {
  const policy = _private.policyInput({
    name: 'After-hours admin',
    enabled: true,
    workingHoursStart: 8,
    workingHoursEnd: 20,
    weekendDays: [5, 6, 6],
    holidays: ['2026-10-02'],
    exceptions: [{ type: 'user', value: 'backup-user', reason: 'Approved backup' }],
  });
  assert.deepEqual(policy.weekendDays, [5, 6]);
  assert.equal(policy.exceptions[0].value, 'backup-user');
  assert.throws(() => _private.policyInput({ name: 'bad', anomalyRiskThreshold: 101 }), /0 to 100/);
  assert.throws(() => _private.policyInput({ name: 'bad', holidays: ['02-10-2026'] }), /ISO dates/);
});

test('temporary agent bypass requires scoped agents, a reason and bounded duration', () => {
  const exception = _private.exceptionInput({
    name: 'Approved maintenance',
    reason: 'CHG-1042',
    systemIds: ['507f1f77bcf86cd799439011'],
    startsAt: '2026-08-30T10:00:00.000Z',
    expiresAt: '2026-08-30T12:00:00.000Z',
  });
  assert.equal(exception.systemIds.length, 1);
  assert.equal(exception.reason, 'CHG-1042');
  assert.throws(() => _private.exceptionInput({ name: 'bad', reason: 'missing agent', systemIds: [], startsAt: '2026-08-30T10:00:00.000Z', expiresAt: '2026-08-30T12:00:00.000Z' }), /Select at least one/);
  assert.throws(() => _private.exceptionInput({ name: 'bad', reason: 'bad range', systemIds: ['507f1f77bcf86cd799439011'], startsAt: '2026-08-30T12:00:00.000Z', expiresAt: '2026-08-30T10:00:00.000Z' }), /later than/);
});

test('time anomaly API, heartbeat, sockets and dashboard use the dedicated real-data pipeline', () => {
  const routes = read('backend/src/routes/time-anomaly.routes.js');
  const heartbeat = read('backend/src/routes/agent.routes.js');
  const ingestion = read('backend/src/routes/alert.routes.js');
  const sender = read('backend/soc-agent/core/sender.py');
  const dashboard = read('company/src/pages/edrdashbordpage/Time-Based Anomaly Detection.jsx');
  const reportsPanel = read('company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboardRoutes = read('backend/src/routes/dashboard.routes.js');
  const details = read('company/src/pages/EDRDashboardDetails.jsx');

  for (const endpoint of ['/overview', '/events', '/statistics', '/hourly-trends', '/heatmap', '/policies', '/exceptions', '/export/csv', '/export/pdf']) {
    assert.ok(routes.includes(`'${endpoint}'`), `missing ${endpoint}`);
  }
  assert.match(heartbeat, /time_anomaly_exceptions/);
  assert.match(heartbeat, /time_anomaly_policy_version/);
  assert.match(heartbeat, /time_anomaly_bypass_active/);
  assert.match(heartbeat, /time_anomaly_bypass_until/);
  assert.match(sender, /TimeAnomalyDetector/);
  assert.ok((ingestion.match(/emit\('time:anomaly'/g) || []).length >= 2);
  assert.match(details, /api\.get\('\/time-anomaly\/overview'/);
  assert.match(details, /socket\.on\('time:anomaly', liveAlertBuffer\.add\)/);
  assert.match(details, /socket\.on\('time:policy-updated', liveAlertBuffer\.add\)/);
  assert.match(details, /socket\.on\('time:exception-updated', liveAlertBuffer\.add\)/);
  assert.match(dashboard, /api\.get\('\/time-anomaly\/events'/);
  assert.match(dashboard, /socket\.on\('time:anomaly', buf\.add\)/);
  assert.match(dashboard, /<CapabilityReportsPanel capabilityId=\{22\} alerts=\{alerts\}/);
  assert.match(reportsPanel, /22: \{/);
  assert.match(reportsPanel, /socket\.on\('time:anomaly', scheduleRefresh\)/);
  assert.match(dashboardRoutes, /new Set\(\[18, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31\]\)/);
  assert.match(dashboard, /id: 'configure', icon: '⚙️', label: 'Configure'/);
  assert.doesNotMatch(dashboard, /id: 'inspector', icon: '⏱️', label: 'Time Anomaly Monitor'/);
  assert.match(dashboard, /<TimeAnomalyConfigureTab systems=\{backendSystems\} onRefresh=\{onRefresh\} embedded/);
  assert.match(dashboard, /api\.get\('\/time-anomaly\/policies'/);
  assert.match(dashboard, /api\.post\('\/time-anomaly\/policies'/);
  assert.match(dashboard, /api\.put\(`\/time-anomaly\/policies\/\$\{editingId\}`/);
  assert.match(dashboard, /api\.delete\(`\/time-anomaly\/policies\/\$\{policy\._id\}`/);
  assert.match(dashboard, /togglePolicyEnabled/);
  assert.match(dashboard, /policy\.enabled === false \? 'Enable' : 'Disable'/);
  assert.match(dashboard, /socket\.on\('time:policy-updated', refresh\)/);
  assert.match(dashboard, /ONLINE' : 'OFFLINE'/);
  assert.match(dashboard, /Offline agents receive this rule when they reconnect/);
  assert.doesNotMatch(dashboard, /id: 'exceptions', icon: '✅', label: 'Approved Exceptions'/);
  assert.match(dashboard, /<TimeAnomalyExceptionsTab systems=\{backendSystems\} onRefresh=\{onRefresh\} embedded/);
  assert.match(dashboard, /No Time Detection Rules created yet/);
  assert.match(routes, /res\.json\(\{ policies, defaultPolicy: DEFAULT_POLICY \}\)/);
  assert.match(dashboard, /api\.get\('\/time-anomaly\/exceptions'/);
  assert.match(dashboard, /api\.post\('\/time-anomaly\/exceptions'/);
  assert.match(dashboard, /api\.delete\(`\/time-anomaly\/exceptions\/\$\{exception\._id\}`/);
  assert.match(dashboard, /All Time-Based Anomaly rules are skipped only on selected agents/);
  assert.doesNotMatch(dashboard, /Historical 30-day behavioral baseline indicates zero prior activity/);
  assert.doesNotMatch(dashboard, /data = \[5, 9, 7, 14, 12, 18, 15, 22\]/);
});

test('time anomaly PDF export produces a valid PDF payload', () => {
  const pdf = _private.buildPdf(['AJNAT Time Anomaly Report', 'No hardcoded findings']);
  assert.equal(pdf.subarray(0, 8).toString(), '%PDF-1.4');
  assert.match(pdf.toString(), /%%EOF/);
});
