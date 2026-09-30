const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const workspace = path.resolve(__dirname, '..', '..');
const read = relativePath => fs.readFileSync(path.join(workspace, relativePath), 'utf8');

const expectedPanels = new Map([
  [2, 'FileActivityDashboard'], [3, 'NetworkActivityDashboard'], [4, 'UserAuthDashboard'],
  [5, 'MemoryActivityDashboard'], [6, 'RegistryActivityDashboard'], [7, 'SystemChangesDashboard'],
  [8, 'PersistenceMechanismDashboard'], [9, 'WebDnsDashboardPanel'], [10, 'UsbDeviceControlDashboard'],
  [11, 'UebaDashboardPanel'], [12, 'DataSecurityDashboardPanel'], [13, 'CredentialSecurityDashboardPanel'],
  [14, 'LateralMovementDashboardPanel'], [15, 'EmailThreatDashboardPanel'], [16, 'InsiderThreatDashboardPanel'],
  [17, 'PatchVulnerabilityDashboardPanel'], [18, 'SandboxAnalysisDashboardPanel'], [19, 'KernelLevelMonitoringDashboardPanel'],
  [20, 'ApiCallMonitoringDashboardPanel'], [21, 'ScriptExecutionDashboardPanel'], [22, 'TimeBasedAnomalyDashboardPanel'],
  [23, 'GeolocationAnomalyDashboardPanel'], [24, 'ServiceMonitoringDashboardPanel'], [25, 'HashSignatureDashboardPanel'],
  [26, 'BeaconingDashboardPanel'], [27, 'RansomwareDashboardPanel'], [28, 'LolbinsDashboard'],
  [29, 'MemoryOverflowDashboard'], [30, 'DnsCachePoisoningDashboard'], [31, 'DnsSinkholeMonitoringDashboard'],
]);

test('company EDR exposes one canonical URL mapping for every capability 2-31', () => {
  const source = read('company/src/utils/capabilityMap.js');
  const rows = [...source.matchAll(/\{\s*id:\s*(\d+),\s*capabilityId:\s*(\d+),\s*backendId:\s*(\d+),[\s\S]*?dashboardRoute:\s*'([^']+)'/g)]
    .map(match => ({ id: Number(match[1]), capabilityId: Number(match[2]), backendId: Number(match[3]), route: match[4] }));

  for (let id = 2; id <= 31; id += 1) {
    const row = rows.find(item => item.id === id);
    assert.ok(row, `missing capability ${id}`);
    assert.equal(row.capabilityId, id, `capabilityId mismatch for ${id}`);
    assert.equal(row.backendId, id, `backendId mismatch for ${id}`);
    assert.equal(row.route, `/company-admin/edr?capabilityId=${id}`);
  }
  assert.equal(new Set(rows.filter(row => row.id >= 2 && row.id <= 31).map(row => row.route)).size, 30);
});

test('every capability 2-31 keeps its specialized dashboard and unified live endpoint', () => {
  const source = read('company/src/pages/EDRDashboardDetails.jsx');
  assert.match(source, /api\.get\(`\/dashboard\/capabilities\/\$\{queryBackendId\}\/live\?/);
  assert.match(source, /const supportsUnifiedLiveAnalytics = Boolean\(capConfig\) && !isNetworkActivityCapability && !isHashSignatureCapability/);

  for (const [id, panel] of expectedPanels) {
    const branch = new RegExp(`cardId === ${id}[\\s\\S]{0,500}<${panel}\\b`);
    assert.match(source, branch, `capability ${id} must render ${panel}`);
  }
});

test('overview cards and opened capability dashboards render one shared 24-hour count snapshot', () => {
  const page = read('company/src/pages/EDRPage.jsx');
  const details = read('company/src/pages/EDRDashboardDetails.jsx');

  assert.match(page, /data=\{overviewCoverage\}/);
  assert.match(page, /overviewData=\{overviewCoverage\}/);
  assert.match(page, /function networkOverviewMetrics/);
  assert.match(page, /api\.get\('\/network\/connections'/);
  assert.match(page, /api\.get\('\/network\/alerts'/);
  assert.match(page, /Number\(capability\.id\) === 3/);
  assert.match(details, /const overviewCount = overviewCapability\?\.live\?\.logs24h \?\? overviewCapability\?\.metrics\?\.logs24h/);
  assert.match(details, /const dashboardTotal = isNetworkActivityCapability[\s\S]*?Number\(total \|\| alerts\.filter\(isNetworkLogRow\)\.length\)/);
  assert.match(details, /networkLogTotal=\{dashboardTotal\}/);

  for (const panel of expectedPanels.values()) {
    assert.match(details, new RegExp(`<${panel}\\b[^>]*\\btotal=\\{dashboardTotal\\}`), `${panel} must use the overview-card count snapshot`);
  }
});

test('Hash/Signature dashboard tabs use dedicated live events, statistics, reports and WebSocket data', () => {
  const details = read('company/src/pages/EDRDashboardDetails.jsx');
  const hashDashboard = read('company/src/pages/edrdashbordpage/hash-signature.jsx');
  assert.match(details, /api\.get\('\/hash-signature\/events'/);
  assert.match(details, /api\.get\('\/hash-signature\/statistics'/);
  assert.match(details, /const next = payload\.events \|\| \[\]/);
  assert.match(details, /socket\.on\('hash:alert', liveAlertBuffer\.add\)/);
  assert.match(hashDashboard, /<HashSignatureLogMonitor alerts=\{alerts\}/);
  assert.match(hashDashboard, /<HashSignatureReportsTab alerts=\{alerts\}/);
  assert.match(hashDashboard, /CapabilityReportsPanel capabilityId=\{25\}/);
});

test('Kernel monitoring uses the API-monitoring report format with its dedicated live report feed', () => {
  const details = read('company/src/pages/EDRDashboardDetails.jsx');
  const kernelDashboard = read('company/src/pages/edrdashbordpage/Kernel-Level Monitoring.jsx');
  const shared = read('company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  assert.match(details, /api\.get\('\/kernel-monitoring\/overview'/);
  assert.match(kernelDashboard, /CapabilityReportsPanel capabilityId=\{19\}/);
  assert.match(shared, /19:\s*\{[\s\S]*?title: 'Kernel-Level Monitoring'/);
  assert.match(shared, /'\/kernel-monitoring\/report'/);
  assert.match(shared, /socket\.on\('kernel:event', scheduleRefresh\)/);
});

test('Sandbox monitoring shows live running VM status reported by installed agents', () => {
  const details = read('company/src/pages/EDRDashboardDetails.jsx');
  const dashboard = read('company/src/pages/edrdashbordpage/Sandbox Analysis.jsx');
  const shared = read('company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboardRoute = read('backend/src/routes/dashboard.routes.js');
  const heartbeat = read('backend/soc-agent/core/heartbeat.py');
  const agentRoute = read('backend/src/routes/agent.routes.js');
  const systemModel = read('backend/src/models/System.model.js');
  assert.match(heartbeat, /'sandboxAnalysisEnabled': sandbox_status == 'active'/);
  assert.match(heartbeat, /'detonation': 'not-applicable'/);
  assert.match(agentRoute, /heartbeatUpdate\.sandboxAnalysisStatus/);
  assert.match(agentRoute, /heartbeatUpdate\.sandboxVmStatus/);
  assert.match(agentRoute, /emit\('sandbox:vm-status'/);
  assert.match(systemModel, /sandboxAnalysisEnabled/);
  assert.match(systemModel, /sandboxVmRunning/);
  assert.match(dashboard, /AJNAT Agent — Running VM Status/);
  assert.match(dashboard, /installed endpoints currently running a VM/);
  assert.match(dashboard, /vm not running/);
  assert.match(dashboard, /CapabilityReportsPanel capabilityId=\{18\}/);
  assert.match(shared, /18:\s*\{[\s\S]*?title: 'Sandbox Analysis'/);
  assert.match(shared, /socket\.on\('sandbox:event', scheduleRefresh\)/);
  assert.match(dashboardRoute, /new Set\(\[18, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31\]\)/);
  assert.match(dashboardRoute, /allowedCapabilities\.add\(16\)/);
  assert.match(dashboard, /api\.get\('\/system', \{ skipCache: true \}\)/);
  assert.match(dashboard, /socket\.on\('sandbox:vm-status', vmBuf\.add\)/);
  assert.match(details, /api\.get\('\/system', \{ skipCache: \[16, 17, 18\]\.includes\(Number\(queryBackendId\)\) \}\)/);
  assert.match(details, /socket\.on\('sandbox:vm-status', liveSystemBuffer\.add\)/);
  assert.doesNotMatch(dashboard, /id: 'vmworkers'/);
});

test('beaconing and ransomware use their dedicated module files', () => {
  const source = read('company/src/pages/EDRDashboardDetails.jsx');
  assert.match(source, /import \{ BeaconingDashboardPanel \} from '\.\/edrdashbordpage\/Beaconing Detection'/);
  assert.match(source, /import \{ RansomwareDashboardPanel \} from '\.\/edrdashbordpage\/Encryption Ransomware Detection'/);
  assert.match(source, /cardId === 26[\s\S]{0,250}<BeaconingDashboardPanel\b/);
  assert.match(source, /cardId === 27[\s\S]{0,250}<RansomwareDashboardPanel\b/);
  const ransomware = read('company/src/pages/edrdashbordpage/Encryption Ransomware Detection.jsx');
  for (const column of ['Suspicious Process', 'PID', 'Command Line', 'File / Directory', 'Variant / Family', 'Canary Status']) {
    assert.match(ransomware, new RegExp(column.replace('/', '\\/')), `missing ransomware column: ${column}`);
  }
});

test('EDR system setup exposes dedicated Memory Overflow and DNS Sinkhole configuration pages', () => {
  const source = read('company/src/pages/EDRSystemSetupPage.jsx');
  const app = read('company/src/App.jsx');
  const memorySetup = read('company/src/pages/MemoryOverflowSetupPage.jsx');
  const sinkholeSetup = read('company/src/pages/DnsSinkholeSetupPage.jsx');
  const memoryDashboard = read('company/src/pages/edrdashbordpage/Memory Overflow Detection.jsx');
  assert.match(source, /api\.get\('\/memory-overflow\/rules'/);
  assert.match(source, /Memory Overflow Detection/);
  assert.match(source, /\$\{setupBase\}\/memory-overflow-detection/);
  assert.match(source, /\$\{setupBase\}\/dns-sinkhole/);
  assert.match(app, /MemoryOverflowSetupPage/);
  assert.match(app, /DnsSinkholeSetupPage/);
  assert.match(memorySetup, /MemoryDetectionRulesTab/);
  assert.match(memorySetup, /Open Monitoring/);
  assert.match(sinkholeSetup, /Open Monitoring/);
  assert.match(sinkholeSetup, /＋ Add New Rule/);
  assert.match(sinkholeSetup, /New DNS rule domain/);
  assert.doesNotMatch(sinkholeSetup, /Sinkhole Destination IP/);
  assert.doesNotMatch(sinkholeSetup, /Save & Apply IP/);
  assert.match(sinkholeSetup, /New DNS rule sinkhole server IP/);
  assert.match(sinkholeSetup, /SERVER IP/);
  assert.match(sinkholeSetup, /Redirect to Safe Server/);
  assert.match(sinkholeSetup, /Original DNS/);
  assert.match(sinkholeSetup, /api\.post\(`\/dns-sinkhole\/\$\{newRule\.type\}`/);
  assert.match(memoryDashboard, /export function MemoryDetectionRulesTab/);
});

test('EDR system setup exposes a dedicated ransomware configuration page', () => {
  const setup = read('company/src/pages/EDRSystemSetupPage.jsx');
  const app = read('company/src/App.jsx');
  const setupPage = read('company/src/pages/RansomwareSetupPage.jsx');
  const ransomware = read('company/src/pages/edrdashbordpage/Encryption Ransomware Detection.jsx');
  assert.match(setup, /api\.get\('\/ransomware\/configuration'/);
  assert.match(setup, /Encryption &amp; Ransomware Detection/);
  assert.match(setup, /\$\{setupBase\}\/encryption-ransomware-detection/);
  assert.match(app, /edrsystemstupe\/encryption-ransomware-detection/);
  assert.match(setupPage, /RansomwareConfigurationTab/);
  assert.match(setupPage, /Open Monitoring/);
  assert.match(ransomware, /export function RansomwareConfigurationTab/);
});

test('EDR system setup exposes a dedicated Beaconing Detection configuration page', () => {
  const setup = read('company/src/pages/EDRSystemSetupPage.jsx');
  const app = read('company/src/App.jsx');
  const setupPage = read('company/src/pages/BeaconingSetupPage.jsx');
  const beaconing = read('company/src/pages/edrdashbordpage/Beaconing Detection.jsx');
  assert.match(setup, /api\.get\('\/network\/beaconing\/configuration'/);
  assert.match(setup, /Beaconing Detection/);
  assert.match(setup, /\$\{setupBase\}\/beaconing-detection/);
  assert.match(app, /edrsystemstupe\/beaconing-detection/);
  assert.match(setupPage, /BeaconingConfigurationTab/);
  assert.match(setupPage, /capabilityId=26&capability=beaconing-detection/);
  assert.match(setupPage, /Open Monitoring/);
  assert.match(beaconing, /export function BeaconingConfigurationTab/);
});

test('EDR system setup exposes the live Time-Based Anomaly configuration card', () => {
  const setup = read('company/src/pages/EDRSystemSetupPage.jsx');
  const app = read('company/src/App.jsx');
  const setupPage = read('company/src/pages/TimeAnomalySetupPage.jsx');
  const dashboard = read('company/src/pages/edrdashbordpage/Time-Based Anomaly Detection.jsx');
  assert.match(setup, /api\.get\('\/time-anomaly\/policies'/);
  assert.match(setup, /api\.get\('\/time-anomaly\/exceptions'/);
  assert.match(setup, /\$\{setupBase\}\/time-based-anomaly-detection/);
  assert.doesNotMatch(setup, /capabilityId=22&capability=time-based-anomaly-detection&tab=configure/);
  assert.match(setup, /Time-Based Anomaly Detection/);
  assert.match(setup, /Active rules:/);
  assert.match(setup, /socket\.on\('time:policy-updated', refreshTimeSetup\)/);
  assert.match(setup, /socket\.on\('time:exception-updated', refreshTimeSetup\)/);
  assert.match(app, /TimeAnomalySetupPage/);
  assert.match(setupPage, /TimeAnomalyConfigureTab/);
  assert.match(setupPage, /TimeAnomalyExceptionsTab/);
  assert.doesNotMatch(setupPage, /Open Monitoring/);
  assert.match(dashboard, /requestedTab === 'configure'/);
  assert.match(dashboard, /export function TimeAnomalyConfigureTab/);
});

test('Script, time anomaly, geolocation, service, hash, beaconing, ransomware, LOLBins, advanced memory and DNS reports use the process-style live report workflow', () => {
  const shared = read('company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboardRoute = read('backend/src/routes/dashboard.routes.js');
  const geoDashboard = read('company/src/pages/edrdashbordpage/Geolocation Anomaly Detection.jsx');
  const timeDashboard = read('company/src/pages/edrdashbordpage/Time-Based Anomaly Detection.jsx');
  const scriptDashboard = read('company/src/pages/edrdashbordpage/Script Execution Monitoring.jsx');
  const hashDashboard = read('company/src/pages/edrdashbordpage/hash-signature.jsx');
  const serviceDashboard = read('company/src/pages/edrdashbordpage/Service Monitoring.jsx');
  const lolbins = read('company/src/pages/edrdashbordpage/Living-off-the-Land (LOLBins) Detection.jsx');
  const ransomware = read('company/src/pages/edrdashbordpage/Encryption Ransomware Detection.jsx');
  const beaconing = read('company/src/pages/edrdashbordpage/Beaconing Detection.jsx');
  const memory = read('company/src/pages/edrdashbordpage/Memory Overflow Detection.jsx');
  const poison = read('company/src/pages/edrdashbordpage/DNS Cache Poisoning Detection.jsx');
  const sinkhole = read('company/src/pages/edrdashbordpage/DNS Sinkhole.jsx');
  assert.match(shared, /capability-report\/\$\{capabilityId\}/);
  assert.match(shared, /90days/);
  assert.match(shared, /Export PDF/);
  assert.match(shared, /Export CSV/);
  assert.match(shared, /Export JSON/);
  assert.match(shared, /process_cmdline/);
  assert.match(shared, /socket\.on\('alert:new', scheduleRefresh\)/);
  assert.match(shared, /socket\.on\('alert:updated', scheduleRefresh\)/);
  assert.match(shared, /socket\.on\('alert:deleted', scheduleDeletedRefresh\)/);
  assert.match(shared, /ids\.some\(id => Number\(id\) === Number\(capabilityId\)\)/);
  assert.match(shared, /window\.setInterval\(pollReport, 30000\)/);
  assert.match(shared, /memory:alert-updated/);
  assert.match(shared, /LIVE POLLING/);
  assert.match(dashboardRoute, /router\.get\('\/capability-report\/:capabilityId', requireAnalyst/);
  assert.match(dashboardRoute, /new Set\(\[18, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31\]\)/);
  assert.match(dashboardRoute, /allowedCapabilities\.add\(16\)/);
  assert.match(dashboardRoute, /rawEvent\.process_cmdline/);
  assert.match(hashDashboard, /CapabilityReportsPanel capabilityId=\{25\}/);
  assert.match(timeDashboard, /CapabilityReportsPanel capabilityId=\{22\}/);
  assert.match(scriptDashboard, /CapabilityReportsPanel capabilityId=\{21\}/);
  assert.match(geoDashboard, /CapabilityReportsPanel capabilityId=\{23\}/);
  assert.match(serviceDashboard, /CapabilityReportsPanel capabilityId=\{24\}/);
  assert.match(shared, /socket\.on\('geo:event', scheduleRefresh\)/);
  assert.match(shared, /socket\.on\('time:anomaly', scheduleRefresh\)/);
  assert.match(shared, /GPS Accuracy \(m\)/);
  assert.match(shared, /socket\.on\('service:alert', scheduleRefresh\)/);
  assert.match(shared, /socket\.on\('script:event', scheduleRefresh\)/);
  assert.match(lolbins, /CapabilityReportsPanel capabilityId=\{28\}/);
  assert.match(ransomware, /CapabilityReportsPanel capabilityId=\{27\}/);
  assert.match(beaconing, /CapabilityReportsPanel capabilityId=\{26\}/);
  assert.match(beaconing, /THREAT SCORE: \{beaconScore\(log\)/);
  assert.match(beaconing, /beaconCommandLine\(log\)/);
  assert.match(shared, /socket\.on\('beaconing:event', scheduleRefresh\)/);
  assert.match(ransomware, /dashboard\/capabilities\/27\/live/);
  assert.match(ransomware, /socket\.on\('ransomware:event', scheduleRefresh\)/);
  assert.match(ransomware, /evidence\.commandLine \|\| '—'/);
  assert.match(memory, /CapabilityReportsPanel capabilityId=\{29\}/);
  assert.match(poison, /CapabilityReportsPanel capabilityId=\{30\}/);
  assert.match(sinkhole, /CapabilityReportsPanel capabilityId=\{31\}/);
});
