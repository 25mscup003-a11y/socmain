const test = require('node:test');
const assert = require('node:assert/strict');
const {
  calculateNetworkRisk,
  applyNetworkPolicies,
  isPrivateIp,
  normalizeConnection,
  severityForRisk,
} = require('../src/services/networkMonitoring.service');
const networkRouter = require('../src/routes/network.routes');

test('network risk requires contextual evidence and is explainable', () => {
  const routine = calculateNetworkRisk({ destinationIp: '8.8.8.8', destinationPort: 443, processName: 'browser' });
  assert.equal(routine.riskScore, 0);
  const suspicious = calculateNetworkRisk({
    destinationIp: '203.0.113.10',
    destinationPort: 4444,
    processName: 'powershell.exe',
    threatIntel: { verdict: 'malicious', score: 90 },
  });
  assert.equal(suspicious.severity, 'high');
  assert.ok(suspicious.reasons.length >= 3);
});

test('risk bands follow the published 0-100 scale', () => {
  assert.equal(severityForRisk(20), 'low');
  assert.equal(severityForRisk(21), 'medium');
  assert.equal(severityForRisk(41), 'elevated');
  assert.equal(severityForRisk(61), 'high');
  assert.equal(severityForRisk(81), 'critical');
});

test('policies are conjunctive and do not match partial evidence', () => {
  const policy = {
    _id: 'policy-1', name: 'Large malicious outbound transfer', enabled: true,
    conditions: [
      { field: 'bytesSent', operator: 'gte', value: 1000 },
      { field: 'destinationReputation', operator: 'eq', value: 'malicious' },
    ],
    actions: { riskScore: 90, createAlert: true },
  };
  const partial = { bytesSent: 5000, destinationReputation: 'clean', riskScore: 0, detectionReasons: [] };
  assert.equal(applyNetworkPolicies(partial, [policy]).length, 0);
  const full = { bytesSent: 5000, destinationReputation: 'malicious', riskScore: 0, detectionReasons: [] };
  assert.equal(applyNetworkPolicies(full, [policy]).length, 1);
  assert.equal(full.riskScore, 90);
});

test('policy reputation alias reads normalized threat intelligence evidence', () => {
  const policy = {
    _id: 'policy-2', name: 'Threat intel match',
    conditions: [{ field: 'destinationReputation', operator: 'eq', value: 'malicious' }],
    actions: { riskScore: 70, severity: 'critical', createAlert: true },
  };
  const connection = { threatIntel: { verdict: 'malicious' }, riskScore: 0, detectionReasons: [] };
  assert.equal(applyNetworkPolicies(connection, [policy]).length, 1);
  assert.equal(connection.riskScore, 81);
  assert.equal(connection.severity, 'critical');
});

test('group-scoped policies fail closed when endpoint group evidence is absent', () => {
  const policy = {
    _id: 'policy-3', name: 'Restricted endpoint group', scope: { endpointGroups: ['finance'] },
    conditions: [{ field: 'state', operator: 'eq', value: 'ESTABLISHED' }],
    actions: { riskScore: 70 },
  };
  assert.equal(applyNetworkPolicies({ state: 'ESTABLISHED', riskScore: 0 }, [policy]).length, 0);
  const scoped = { state: 'ESTABLISHED', endpointGroup: 'finance', riskScore: 0, detectionReasons: [] };
  assert.equal(applyNetworkPolicies(scoped, [policy]).length, 1);
});

test('network route clamps every dashboard query to a rolling 24 hours', () => {
  const now = new Date('2026-08-29T12:00:00.000Z');
  const result = networkRouter.networkWindow({ from: '2026-01-01T00:00:00.000Z', to: '2027-01-01T00:00:00.000Z', hours: 720 }, now);
  assert.equal(result.hours, 24);
  assert.equal(result.from.toISOString(), '2026-08-28T12:00:00.000Z');
  assert.equal(result.to.toISOString(), now.toISOString());
  const historic = networkRouter.networkWindow({ from: '2025-01-01T00:00:00.000Z', to: '2025-01-02T00:00:00.000Z' }, now);
  assert.equal(historic.from.toISOString(), '2026-08-28T12:00:00.000Z');
  assert.equal(historic.to.toISOString(), '2026-08-28T12:00:00.000Z');
});

test('network statistics derive VPN usage from live agent interface deltas', () => {
  const usage = networkRouter.summarizeAdapterUsage([
    {
      systemId: 'endpoint-1',
      rawEvent: { raw: {
        vpn: { active: true, method: 'WireGuard VPN', interfaces: [{ name: 'wg0' }], ports: [] },
        adapter_delta: {
          bytes_sent: 5000,
          bytes_received: 9000,
          interfaces: [
            { interface: 'wg0', bytes_sent: 1200, bytes_received: 3400 },
            { interface: 'eth0', bytes_sent: 3800, bytes_received: 5600 },
            { interface: 'lo', bytes_sent: 999999, bytes_received: 999999 },
          ],
        },
      } },
    },
  ]);
  assert.equal(usage.bytesSent, 5000);
  assert.equal(usage.bytesReceived, 9000);
  assert.equal(usage.vpnBytesSent, 1200);
  assert.equal(usage.vpnBytesReceived, 3400);
  assert.equal(usage.vpnActiveEndpoints, 1);
  assert.deepEqual(usage.vpnMethods, ['WireGuard VPN']);
});

test('a dormant VPN client process is not reported as active VPN traffic', () => {
  const usage = networkRouter.summarizeAdapterUsage([{
    systemId: 'endpoint-1', createdAt: new Date(),
    rawEvent: { raw: {
      vpn: { active: true, method: 'Proton VPN', interfaces: [], ports: [], processes: [{ name: 'protonvpn-app' }] },
      adapter_delta: { interfaces: [{ interface: 'wlan0', bytes_sent: 100, bytes_received: 200 }] },
    } },
  }]);
  assert.equal(usage.vpnActiveEndpoints, 0);
  assert.equal(usage.vpnEndpointsUsed, 0);
  assert.equal(usage.vpnBytesSent + usage.vpnBytesReceived, 0);
});

test('private address detection supports IPv4 and IPv6', () => {
  assert.equal(isPrivateIp('10.1.2.3'), true);
  assert.equal(isPrivateIp('192.168.1.2'), true);
  assert.equal(isPrivateIp('fd00::1'), true);
  assert.equal(isPrivateIp('::ffff:10.1.2.3'), true);
  assert.equal(isPrivateIp('8.8.8.8'), false);
});

test('listening sockets are normalized without inventing a remote peer', () => {
  const document = normalizeConnection({
    companyId: 'company', hostname: 'server-1', agentId: 'agent-1', createdAt: new Date(),
  }, {
    listener: true, state: 'LISTEN', protocol: 'tcp', local_ip: '0.0.0.0', local_port: 443,
    process_name: 'nginx', pid: 42,
  });
  assert.equal(document.state, 'LISTEN');
  assert.equal(document.direction, 'inbound');
  assert.equal(document.sourcePort, 443);
  assert.equal(document.destinationIp, '');
});

test('normalized outbound connection retains observed source port and enrichment', () => {
  const document = normalizeConnection({
    companyId: 'company', hostname: 'endpoint-1', agentId: 'agent-1', createdAt: new Date(),
  }, {
    state: 'ESTABLISHED', protocol: 'tcp', local_ip: '10.0.0.2', local_port: 0,
    observed_local_port: 52123, remote_ip: '203.0.113.10', remote_port: 443,
    process_name: 'browser', pid: 42, domain: 'example.test',
    geo: { country: 'Exampleland' },
  });
  assert.equal(document.sourcePort, 52123);
  assert.equal(document.pid, 42);
  assert.equal(document.domain, 'example.test');
  assert.equal(document.geo.country, 'Exampleland');
  assert.equal(document.rawMetadata.bytesScope, 'not_available');
});

test('missing PID remains unknown instead of being reported as process zero', () => {
  const document = normalizeConnection({
    companyId: 'company', hostname: 'endpoint-1', agentId: 'agent-1', createdAt: new Date(),
  }, {
    state: 'ESTABLISHED', protocol: 'tcp', local_ip: '10.0.0.2',
    remote_ip: '203.0.113.10', remote_port: 443,
  });
  assert.equal(document.pid, null);
});

test('outbound identity ignores recycled PID, client port and socket time', () => {
  const alert = {
    companyId: 'company', hostname: 'endpoint-1', agentId: 'agent-1', createdAt: new Date(),
  };
  const first = normalizeConnection(alert, {
    connection_id: 'kernel-socket-1', state: 'ESTABLISHED', direction: 'outbound',
    protocol: 'tcp', local_ip: '10.0.0.2', local_port: 0, observed_local_port: 51001,
    remote_ip: '203.0.113.10', remote_port: 443, process_name: 'browser', pid: 42,
    start_time: '2026-09-06T01:00:00.000Z',
  });
  const recycled = normalizeConnection(alert, {
    connection_id: 'kernel-socket-2', state: 'ESTABLISHED', direction: 'outbound',
    protocol: 'tcp', local_ip: '10.0.0.2', local_port: 0, observed_local_port: 62002,
    remote_ip: '203.0.113.10', remote_port: 443, process_name: 'browser', pid: 84,
    start_time: '2026-09-06T02:00:00.000Z',
  });
  assert.equal(first.connectionId, recycled.connectionId);
  assert.equal(first.sourcePort, 51001);
  assert.equal(recycled.sourcePort, 62002);
  assert.equal(recycled.pid, 84);
});

test('stable connection identity still separates real process, peer and listener changes', () => {
  const alert = {
    companyId: 'company', hostname: 'endpoint-1', agentId: 'agent-1', createdAt: new Date(),
  };
  const base = {
    state: 'ESTABLISHED', direction: 'outbound', protocol: 'tcp',
    local_ip: '10.0.0.2', observed_local_port: 51001,
    remote_ip: '203.0.113.10', remote_port: 443, process_name: 'browser',
  };
  const baseline = normalizeConnection(alert, base).connectionId;
  assert.notEqual(baseline, normalizeConnection(alert, { ...base, remote_ip: '203.0.113.11' }).connectionId);
  assert.notEqual(baseline, normalizeConnection(alert, { ...base, remote_port: 8443 }).connectionId);
  assert.notEqual(baseline, normalizeConnection(alert, { ...base, process_name: 'curl' }).connectionId);

  const listener443 = normalizeConnection(alert, {
    listener: true, state: 'LISTEN', protocol: 'tcp', local_ip: '0.0.0.0', local_port: 443,
    process_name: 'nginx', pid: 10,
  });
  const listener8443 = normalizeConnection(alert, {
    listener: true, state: 'LISTEN', protocol: 'tcp', local_ip: '0.0.0.0', local_port: 8443,
    process_name: 'nginx', pid: 11,
  });
  assert.notEqual(listener443.connectionId, listener8443.connectionId);
});
