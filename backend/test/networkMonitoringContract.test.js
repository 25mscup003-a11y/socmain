const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');

test('Capability 3 dashboard uses tenant APIs and a fixed 24-hour window without fake traffic totals', () => {
  const source = fs.readFileSync(path.join(root, 'company/src/pages/edrdashbordpage/Network Activity Monitoring.jsx'), 'utf8');
  assert.match(source, /api\.get\('\/network\/connections'/);
  assert.match(source, /api\.get\('\/network\/alerts'/);
  assert.match(source, /api\.get\('\/network\/statistics'/);
  assert.match(source, /api\.get\(`\/network\/forensics\/\$\{initialLog\._id\}`/);
  assert.match(source, /VPN Data Used/);
  assert.match(source, /hours:\s*24/);
  assert.doesNotMatch(source, /52428800|209715200|5\.85 \* 1024|28\.64 \* 1024/);
  assert.doesNotMatch(source, /SOC-NET-AGENT-03|16:24:01\.080|00:15:5D:44:A2:18|Threat Intel blacklist feed/);
  assert.match(source, /api\.post\('\/forensics\/hunts'/);
  assert.match(source, /api\.post\(`\/alerts\/\$\{log\._id\}\/notes`/);
  assert.match(source, /_recordType:\s*'alert'/);
});

test('network backend exposes authoritative KPI fields and refreshed forensic records', () => {
  const route = fs.readFileSync(path.join(root, 'backend/src/routes/network.routes.js'), 'utf8');
  for (const field of [
    'listeningServices', 'c2BeaconDetections', 'torVpnAnonymizers', 'failedDns',
    'webRequests', 'exfiltrationAlerts', 'processMappings', 'portScanDetections',
    'lateralMovement', 'remoteAdminTools', 'eastWestTraffic', 'cloudSaasConnections',
    'windowsSignals', 'linuxSignals', 'webServerTraffic', 'databaseTraffic',
    'vpnDataTransferred',
  ]) assert.match(route, new RegExp(field));
  assert.match(route, /router\.get\('\/forensics\/:id'/);
  assert.match(route, /NET_CONNECTION_SUMMARY/);
});

test('Capability 3 reports expose real 24h, 7d, 30d and 90d windows', () => {
  const source = fs.readFileSync(path.join(__dirname, '../../company/src/pages/edrdashbordpage/Network Activity Monitoring.jsx'), 'utf8');
  assert.match(source, /label: '24 Hours'[\s\S]*days: 1/);
  assert.match(source, /label: '1 Week'[\s\S]*days: 7/);
  assert.match(source, /label: '1 Month'[\s\S]*days: 30/);
  assert.match(source, /label: '3 Months'[\s\S]*days: 90/);
  assert.match(source, /const days = selectedWindow\.days/);
});

test('network API is mounted into the existing backend', () => {
  const server = fs.readFileSync(path.join(root, 'backend/src/server.js'), 'utf8');
  assert.match(server, /app\.use\('\/api\/network', networkRoutes\)/);
});

test('network API excludes known local capture diagnostics from logs and totals', () => {
  const source = fs.readFileSync(path.join(root, 'backend/src/routes/network.routes.js'), 'utf8');
  for (const ruleId of [
    'NET_CONNECTION_SUMMARY', 'NET_DNS_SUMMARY', 'NET_EXPOSURE_SUMMARY',
    'NET_THREAT_INTEL_SUMMARY', 'WAF_AGENT_STATUS', 'IDS_TELEMETRY',
    'NETWORK_TELEMETRY', 'SURICATA_2200003', 'SURICATA_2210045',
    'SURICATA_2210046', 'ZEEK_truncated_tcp_payload',
  ]) {
    assert.match(source, new RegExp(ruleId));
  }
  assert.match(source, /signatureName: \/\^truncated_tcp_payload\$\/i/);
});

test('network API collapses recycled PID and client-port rows by stable topology', () => {
  const source = fs.readFileSync(path.join(root, 'backend/src/routes/network.routes.js'), 'utf8');
  assert.match(source, /function stableConnectionGroupId/);
  assert.match(source, /Client ports and PIDs are observation details/);
  assert.match(source, /latestStableConnections\(filter\)/);
  assert.doesNotMatch(source, /NetworkConnection\.find\(filter\)\.sort\(sort\)/);
});

test('network API supports an uncapped 24-hour view and coalesces DNS answer fan-out', () => {
  const source = fs.readFileSync(path.join(root, 'backend/src/routes/network.routes.js'), 'utf8');
  assert.match(source, /String\(req\.query\.limit\) === '0'/);
  assert.match(source, /function latestLogicalNetworkAlerts/);
  assert.match(source, /PROC_DNS_ATTRIBUTED/);
  assert.match(source, /destinationIps/);
  assert.match(source, /coalescedCount/);
});

test('live network map is active-only, direction-aware and linked to agent GPS', () => {
  const route = fs.readFileSync(path.join(root, 'backend/src/routes/network.routes.js'), 'utf8');
  const page = fs.readFileSync(path.join(root, 'company/src/pages/LiveNetworkMapPage.jsx'), 'utf8');
  const dashboard = fs.readFileSync(path.join(root, 'company/src/pages/edrdashbordpage/Network Activity Monitoring.jsx'), 'utf8');
  const networkMap = fs.readFileSync(path.join(root, 'company/src/components/NetworkConnectionMap.jsx'), 'utf8');
  const idsMap = fs.readFileSync(path.join(root, 'company/src/components/IdsIpsWafMap.jsx'), 'utf8');
  const sharedMap = fs.readFileSync(path.join(root, 'company/src/components/GoogleAttackMap.jsx'), 'utf8');
  assert.match(route, /router\.get\('\/live-map'/);
  assert.match(route, /NetworkConnection\.find\(\{ \.\.\.scope, state: \{ \$nin: \['CLOSED', 'CLOSING'\] \}, endTime: null \}\)/);
  assert.match(route, /directionCounts/);
  assert.match(route, /buildGpsDestinationMap/);
  assert.match(route, /GeolocationPolicy\.find/);
  assert.match(route, /Agent public IP geolocation \(approximate\)/);
  assert.match(route, /gpsLocations\.get\(resolvedSystemId\)[\s\S]*policyLocations\.get\(resolvedSystemId\)[\s\S]*networkAgentLocations\.get\(resolvedSystemId\)/);
  assert.match(route, /connections: verifiedConnections/);
  assert.match(route, /unmapped: verifiedConnections\.length - mappedConnections\.length/);
  assert.match(page, /useLiveNetworkMap/);
  assert.match(page, /<NetworkConnectionMap/);
  assert.match(page, /<IdsIpsWafMap/);
  assert.match(dashboard, /<NetworkConnectionMap/);
  assert.match(networkMap, /dataMode="network"/);
  assert.match(networkMap, /AJNAT LOCATIONS/);
  assert.match(idsMap, /dataMode="ids"/);
  assert.match(sharedMap, /import L from 'leaflet'/);
  assert.match(sharedMap, /AJNAT AGENT LOCATION/);
  assert.doesNotMatch(sharedMap, /unpkg\.com\/leaflet/);
});

test('network UI absorbs a nearby domain-empty socket into its process DNS attribution', () => {
  const source = fs.readFileSync(path.join(root, 'company/src/pages/edrdashbordpage/Network Activity Monitoring.jsx'), 'utf8');
  assert.match(source, /processAttributionKeys/);
  assert.match(source, /direction \|\| ''\)\.toLowerCase\(\) === 'outbound'/);
  assert.match(source, /15 \* 60 \* 1000/);
  assert.match(source, /attribution\.destinationIps\.push\(destinationIp\)/);
});
