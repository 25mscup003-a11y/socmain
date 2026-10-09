const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../company/src/pages/edrdashbordpage/Network Activity Monitoring.jsx'), 'utf8');
const merge = source.slice(source.indexOf('const NETWORK_SUMMARY_RULES'), source.indexOf('function MiniSparkline')).replaceAll('export function', 'function');
const helpers = source.slice(source.indexOf('function shortNum('), source.indexOf('export function NetworkLogDetailModal('));
const { alertUser, netDnsQuery, netGeo, netGeoDisplay, netTraffic, mergeNetworkLogRows } = vm.runInNewContext(`${merge}\n${helpers}\n({ alertUser, netDnsQuery, netGeo, netGeoDisplay, netTraffic, mergeNetworkLogRows })`);
const plain = value => JSON.parse(JSON.stringify(value));

test('network users survive outer raw envelopes, nested sockets and placeholder usernames', () => {
  assert.equal(alertUser({ username: 'unknown', rawEvent: { username: 'alice', raw: {} } }), 'alice');
  assert.equal(alertUser({ raw: { connection: { username: 'bob' } } }), 'bob');
  assert.equal(alertUser({ user: 'N/A', correlatedConnection: { username: 'root' } }), 'root');
  assert.equal(alertUser({ hostname: 'alice-laptop', username: 'unknown' }), 'Not reported');
});

test('normalized agent summaries retain measured counters and leave missing directions unreported', () => {
  const { normalizeConnection } = require('../src/services/networkMonitoring.service');
  const row = normalizeConnection({ companyId: 'company', agentId: 'agent', hostname: 'endpoint' }, {
    protocol: 'tcp', state: 'ESTABLISHED', local_ip: '10.0.0.2', remote_ip: '8.8.8.8',
    observed_local_port: 51000, remote_port: 443, username: 'alice',
    domain: 'example.test', geo: { city: 'Delhi', country: 'India' },
    bytes_sent: 1024, bytes_scope: 'active_sockets', bytes_source: 'linux_tcp_info', socket_count: 2, measured_socket_count: 1,
  });
  assert.equal(alertUser(row), 'alice');
  assert.equal(netDnsQuery(row), 'example.test');
  assert.equal(netGeo(row), 'Delhi, India');
  assert.deepEqual(plain(netTraffic(row)), { sent: 1024, received: null, scope: 'active_sockets' });
  assert.equal(row.rawMetadata.bytesSource, 'linux_tcp_info');
  assert.equal(row.rawMetadata.socketCount, 2);
});

test('DNS reads outer and nested telemetry without mistaking the endpoint hostname for a domain', () => {
  assert.equal(netDnsQuery({ domain: 'unknown', rawEvent: { dns_query: 'example.test', raw: { state: 'ESTABLISHED' } } }), 'example.test');
  assert.equal(netDnsQuery({ rawEvent: { raw: { tls: { sni: 'tls.example.test' } } } }), 'tls.example.test');
  assert.equal(netDnsQuery({ raw: { dns: { queries: [{ rrname: 'dns.example.test' }] } } }), 'dns.example.test');
  assert.equal(netDnsQuery({ raw: { raw: { connection: { domain: 'socket.example.test' } } } }), 'socket.example.test');
  assert.equal(netDnsQuery({ hostname: 'endpoint', rawEvent: { dns: { queries: {} } } }), '');
});

test('Geo retains outer payload and matched connection locations even when empty objects are present', () => {
  assert.equal(netGeo({ geo: {}, rawEvent: { geoCity: 'Delhi', geoCountry: 'India', raw: {} } }), 'Delhi, India');
  assert.equal(netGeo({ geoCountry: 'unknown', raw: { connection: { geo: { city: 'Paris', country: 'France' } } } }), 'Paris, France');
  assert.equal(netGeo({ geo: {}, correlatedConnection: { geo: { city: 'Boydton', country: 'United States' } } }), 'Boydton, United States');
});

test('Geo distinguishes local addresses and listeners from unreported public locations', () => {
  for (const destinationIp of ['127.0.0.1', '10.0.0.8', '192.168.1.8', '172.16.1.8', '::1', '::ffff:10.0.0.8', 'fd01::1', 'fe80::1%eth0']) {
    assert.equal(netGeoDisplay({ destinationIp }), 'Local network');
  }
  assert.equal(netGeoDisplay({ state: 'LISTEN', destinationIp: '0.0.0.0' }), 'Local listener');
  assert.equal(netGeoDisplay({ destinationIp: '8.8.8.8' }), 'Not reported');
});

test('Traffic reads numeric byte aliases across envelopes, sockets and sensor flows', () => {
  assert.deepEqual(plain(netTraffic({ rawEvent: { bytesSent: '1024', bytesReceived: '2048', raw: {} } })), { sent: 1024, received: 2048, scope: 'connection' });
  assert.deepEqual(plain(netTraffic({ rawEvent: { raw: { connection: { bytes_sent: 12, bytes_received: 34 } } } })), { sent: 12, received: 34, scope: 'connection' });
  assert.deepEqual(plain(netTraffic({ raw: { flow: { bytes_toserver: 56, bytes_toclient: 78 } } })), { sent: 56, received: 78, scope: 'connection' });
  assert.deepEqual(plain(netTraffic({ raw: { orig_bytes: 90, resp_bytes: 123 } })), { sent: 90, received: 123, scope: 'connection' });
});

test('unreported traffic is distinct from measured zero and invalid counters are skipped', () => {
  assert.deepEqual(plain(netTraffic({ bytesSent: 0, bytesReceived: 0 })), { sent: 0, received: 0, scope: 'connection' });
  assert.deepEqual(plain(netTraffic({ bytesSent: 0, bytesReceived: 0, rawMetadata: { bytesScope: 'not_available' } })), { sent: null, received: null, scope: 'not_available' });
  assert.deepEqual(plain(netTraffic({ bytesSent: '', bytesReceived: null, rawEvent: { bytes_sent: true, bytes_received: -1, raw: { bytes_sent: '64' } } })), { sent: 64, received: null, scope: 'connection' });
  assert.equal(netTraffic({ bytesSent: Infinity, bytesReceived: 'unknown' }).scope, 'not_available');
});

test('adapter counters are labelled and are never borrowed from the live host snapshot', () => {
  const adapter_delta = { bytes_sent: 1024, bytes_received: 2048 };
  assert.deepEqual(plain(netTraffic({ rawEvent: { raw: { adapter_delta } } })), { sent: 1024, received: 2048, scope: 'adapter' });
  assert.equal(netTraffic({ liveContext: { networkSnapshot: { adapter_delta } } }).scope, 'not_available');
});

const dns = { _id: 'dns', ruleId: 'PROC_DNS_ATTRIBUTED', agentId: 'agent-a', processName: 'browser', pid: 12, destip: '8.8.8.8', destPort: 443, domain: 'example.test', createdAt: '2026-10-09T12:00:00Z' };
const connection = { _id: 'socket', agentId: 'agent-a', processName: 'browser', pid: 12, destinationIp: '8.8.8.8', destinationPort: 443, direction: 'outbound', observedAt: '2026-10-09T12:00:05Z', geo: { city: 'Delhi', country: 'India' }, bytesSent: 1024, bytesReceived: 2048 };

test('merging a DNS event retains matching socket geo and traffic without changing input records', () => {
  const rows = mergeNetworkLogRows([connection], [dns]);
  assert.equal(rows.length, 1);
  assert.equal(netDnsQuery(rows[0]), 'example.test');
  assert.equal(netGeo(rows[0]), 'Delhi, India');
  assert.equal(netTraffic(rows[0]).received, 2048);
  assert.equal(dns.correlatedConnection, undefined);
  assert.equal(dns.destinationIps, undefined);
});

test('DNS correlation stays within the endpoint and time window and does not borrow sibling-IP location', () => {
  assert.equal(mergeNetworkLogRows([{ ...connection, agentId: 'agent-b' }], [dns]).length, 2);
  assert.equal(mergeNetworkLogRows([{ ...connection, observedAt: '2026-10-09T13:00:00Z' }], [dns]).length, 2);
  const rows = mergeNetworkLogRows([{ ...connection, destinationIp: '8.8.4.4' }], [dns]);
  assert.equal(netGeo(rows.find(row => row._id === 'dns')), '');
  assert.equal(netTraffic(rows.find(row => row._id === 'dns')).scope, 'not_available');
});
