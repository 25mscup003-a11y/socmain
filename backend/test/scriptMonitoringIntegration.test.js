const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const workspace = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(workspace, relative), 'utf8');
const { _private } = require('../src/routes/script-monitoring.routes');

test('script events normalize agent evidence without inventing process data', () => {
  const event = _private.canonicalScriptEvent({
    ruleId: 'SCRIPT_OBFUSCATED_COMMAND',
    severity: 'high',
    createdAt: new Date('2026-08-30T12:00:00.000Z'),
    rawEvent: {
      raw: {
        process_name: 'powershell.exe',
        command_line: 'powershell.exe -EncodedCommand AAA',
        script_path: 'C:\\Temp\\audit.ps1',
        script_hash: 'a'.repeat(64),
        parent_process_name: 'WINWORD.EXE',
        parent_pid: 100,
        pid: 200,
        obfuscation_score: 72,
        risk_score: 76,
        detection_reasons: ['Encoded command', 'Suspicious parent process'],
        network_connections: [{ destinationIp: '203.0.113.5', destinationPort: 443 }],
      },
    },
  });

  assert.equal(event.interpreter, 'PowerShell');
  assert.equal(event.scriptName, 'audit.ps1');
  assert.equal(event.scriptHash, 'a'.repeat(64));
  assert.equal(event.obfuscationScore, 72);
  assert.equal(event.riskScore, 76);
  assert.deepEqual(event.processTree.map(node => node.pid), [100, 200]);
  assert.equal(event.networkConnections[0].destinationPort, 443);

  const missing = _private.canonicalScriptEvent({ rawEvent: { raw: {} } });
  assert.deepEqual(missing.processTree, []);
  assert.deepEqual(missing.networkConnections, []);
});

test('script monitoring summary derives KPIs from real tenant events', () => {
  const events = [
    { interpreter: 'PowerShell', severity: 'critical', riskScore: 90, hostname: 'host-a', username: 'alice', obfuscationScore: 70, status: 'open', ruleId: 'SCRIPT_OBFUSCATED_COMMAND', detectionReasons: ['Encoded command'] },
    { interpreter: 'Unix Shell', severity: 'medium', riskScore: 45, hostname: 'host-b', username: 'bob', status: 'resolved', actionTaken: 'Process terminated', ruleId: 'SCRIPT_DATA_EXFILTRATION', detectionReasons: ['External network connection'] },
    { interpreter: 'Python', severity: 'low', riskScore: 10, hostname: 'host-a', username: 'alice', status: 'open' },
  ];
  const summary = _private.summarize(events, events.length, [{ isOnline: true }, { isOnline: false }]);

  assert.equal(summary.totalScripts, 3);
  assert.equal(summary.suspiciousScripts, 2);
  assert.equal(summary.criticalAlerts, 1);
  assert.equal(summary.encodedCommands, 1);
  assert.equal(summary.blockedScripts, 1);
  assert.equal(summary.activeThreats, 1);
  assert.equal(summary.affectedHosts, 2);
  assert.equal(summary.affectedUsers, 2);
  assert.equal(summary.endpointsReporting, 1);
  assert.equal(summary.powershellEvents, 1);
  assert.equal(summary.linuxShellEvents, 1);
  assert.equal(summary.outboundEvents, 1);
  assert.equal(summary.detections.encodedCommands, 1);
});

test('script monitoring rule validation bounds risky configuration', () => {
  const rule = _private.ruleInput({
    name: 'Approved automation',
    systemIds: ['507f1f77bcf86cd799439011', '507f1f77bcf86cd799439011'],
    interpreters: ['PowerShell', 'PowerShell'],
    trustedPaths: ['C:\\ProgramData\\AJNAT\\scripts'],
    trustedHashes: ['A'.repeat(64)],
    riskThreshold: 65,
    alertCooldownSeconds: 300,
  });

  assert.equal(rule.systemIds.length, 1);
  assert.deepEqual(rule.interpreters, ['PowerShell']);
  assert.equal(rule.trustedHashes[0], 'a'.repeat(64));
  assert.equal(rule.riskThreshold, 65);
  assert.equal(rule.requireApprovalForResponse, true);
  assert.throws(() => _private.ruleInput({ name: 'Bad hash', trustedHashes: ['not-sha256'] }), /SHA-256/);
  assert.throws(() => _private.ruleInput({ name: 'Bad score', riskThreshold: 101 }), /0 to 100/);
});

test('script monitoring API, agent policy, ingestion and UI share one real-data pipeline', () => {
  const routes = read('backend/src/routes/script-monitoring.routes.js');
  const server = read('backend/src/server.js');
  const heartbeat = read('backend/src/routes/agent.routes.js');
  const ingestion = read('backend/src/routes/alert.routes.js');
  const collector = read('backend/soc-agent/collectors/processes.py');
  const dashboard = read('company/src/pages/edrdashbordpage/Script Execution Monitoring.jsx');
  const reportsPanel = read('company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboardRoutes = read('backend/src/routes/dashboard.routes.js');
  const details = read('company/src/pages/EDRDashboardDetails.jsx');

  for (const endpoint of ['/overview', '/events', '/alerts', '/statistics', '/rules', '/events/:id', '/timeline/:id', '/process-tree/:id', '/export/csv', '/export/pdf']) {
    assert.ok(routes.includes(`'${endpoint}'`), `missing ${endpoint}`);
  }
  assert.match(server, /app\.use\('\/api\/script-monitoring', scriptMonitoringRoutes\)/);
  assert.match(routes, /One or more selected systems are outside your tenant scope/);
  assert.match(heartbeat, /script_monitoring_enabled/);
  assert.match(heartbeat, /script_trusted_hashes/);
  assert.match(heartbeat, /script_trusted_paths/);
  assert.ok((ingestion.match(/emit\('script:event'/g) || []).length >= 2);
  assert.match(collector, /'capabilityId': 21/);
  assert.match(collector, /'source': 'script_execution'/);
  assert.match(details, /api\.get\('\/script-monitoring\/overview'/);
  assert.match(details, /socket\.on\('script:event', liveAlertBuffer\.add\)/);
  assert.match(dashboard, /api\.get\('\/script-monitoring\/overview'/);
  assert.match(dashboard, /api\.get\('\/script-monitoring\/events'/);
  assert.match(dashboard, /socket\.on\('script:event', buf\.add\)/);
  assert.match(dashboard, /<CapabilityReportsPanel capabilityId=\{21\} alerts=\{alerts\}/);
  assert.match(reportsPanel, /21: \{/);
  assert.match(reportsPanel, /socket\.on\('script:event', scheduleRefresh\)/);
  assert.match(dashboardRoutes, /new Set\(\[18, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31\]\)/);
  assert.match(dashboard, /summary=\{summary\}/);
  assert.match(dashboard, /data=\{liveData\}/);
  assert.doesNotMatch(dashboard, /data = \[5, 9, 7, 14, 12, 18, 15, 22\]/);
  assert.doesNotMatch(dashboard, /WINWORD\.EXE\s*\n\s*\|\s*\n\s*\+-->/);
  assert.doesNotMatch(dashboard, /mockProcessTree|fakeProcessTree|sampleScriptEvents/i);
});

test('script monitoring PDF export creates a valid payload', () => {
  const pdf = _private.buildPdf(['AJNAT Script Execution Report', 'No fabricated evidence']);
  assert.equal(pdf.subarray(0, 8).toString(), '%PDF-1.4');
  assert.match(pdf.toString(), /%%EOF/);
});
