const test = require('node:test');
const assert = require('node:assert/strict');
const {
  applyCapabilityTelemetry,
  canonicalCapabilityIds,
  deriveCapabilityIds,
  isSyntheticAlert,
} = require('../src/utils/capabilityTelemetry');
const {
  attachLiveCapabilityMetrics,
  geolocationEvidenceFilter,
  PUBLIC_EDR_CAPABILITY_IDS,
  liveCardCapabilityMatch,
  liveCapabilityMatch,
  liveTargetCapabilityMatch,
  overviewLiveCapabilityMatch,
  processActivityEventFilter,
  resolveCapabilityDepartmentScope,
} = require('../src/utils/capabilityOverview');
const { buildCapabilityAnalyticsPlan } = require('../src/utils/advancedCapability');

test('classifies real agent telemetry into every capability it proves', () => {
  const ids = deriveCapabilityIds({
    ruleId: 'NET_DNS_CACHE_POISON',
    eventCategory: 'network',
    source: 'network',
    domain: 'example.test',
    description: 'DNS cache poisoning unexpected IP and TTL drop',
  });
  for (const id of [3, 9, 30]) assert.ok(ids.includes(id), `expected capability ${id}`);
});

test('preserves explicit advanced capability and adds broad memory coverage', () => {
  const event = applyCapabilityTelemetry({
    capabilityId: 29,
    ruleId: 'MEMORY_OVERFLOW_SIGSEGV',
    description: 'segmentation fault detected',
  });
  assert.ok(event.capabilityIds.includes(5));
  assert.ok(event.capabilityIds.includes(29));
  assert.equal(event.capabilityId, 29);
});

test('preserves explicit multi-capability evidence from the canonical agent', () => {
  const event = applyCapabilityTelemetry({
    capabilityId: 26,
    capabilityIds: [1, 3, 26],
    ruleId: 'BEACON_PERIODIC_CONNECTION',
    processName: 'powershell.exe',
    description: 'Periodic network beacon with measured jitter',
  });
  assert.ok(event.capabilityIds.includes(1));
  assert.ok(event.capabilityIds.includes(3));
  assert.ok(event.capabilityIds.includes(26));
  assert.equal(event.capabilityId, 26);
});

test('system capability cards trust normalized tags and infer only legacy untagged rows', () => {
  const normalized = canonicalCapabilityIds({
    capabilityId: 1,
    capabilityIds: [1],
    ruleId: 'PROC_STARTED',
    processName: 'worker',
    processMemoryPercent: 2.4,
    description: 'Process started with memory metadata',
  });
  assert.deepEqual(normalized, [1]);

  const legacy = canonicalCapabilityIds({
    ruleId: 'MEM_SUSPICIOUS_RWX',
    category: 'memory',
    description: 'Executable RWX memory region detected',
  });
  assert.ok(legacy.includes(5));
});

test('canonical service lifecycle telemetry maps to Service Monitoring capability 24', () => {
  const event = applyCapabilityTelemetry({
    capabilityId: 1,
    ruleId: 'SERVICE_CREATED',
    source: 'process_assets',
    inventoryType: 'service',
    serviceName: 'auditd.service',
    serviceCurrentStatus: 'RUNNING',
  });
  assert.ok(event.capabilityIds.includes(24));
});

test('keeps endpoint domain identity separate from DNS evidence on LOLBins alerts', () => {
  const ids = deriveCapabilityIds({
    capabilityId: 28,
    capabilityIds: [1, 21, 28],
    ruleId: 'LOLBIN_DETECTED',
    source: 'lolbins',
    processName: 'powershell.exe',
    processCmdline: 'powershell.exe -EncodedCommand ZQB4AGEAbQBwAGwAZQ==',
    userDomain: 'CORP',
  });
  assert.ok(ids.includes(28));
  assert.equal(ids.includes(9), false);
});

test('browser and DNS evidence remain assigned to Web and DNS monitoring', () => {
  const browserIds = deriveCapabilityIds({
    capabilityId: 4,
    capabilityIds: [4, 9],
    ruleId: 'AUTH_WEB_LOGIN_PORTAL',
    source: 'browser-history',
    url: 'https://portal.example.test/login',
    httpMethod: 'GET',
  });
  const dnsIds = deriveCapabilityIds({
    capabilityId: 9,
    ruleId: 'NET_DNS_SUMMARY',
    source: 'network',
    protocol: 'dns',
    queryType: 'A',
  });
  assert.ok(browserIds.includes(9));
  assert.ok(dnsIds.includes(9));
});

test('advanced process evidence remains on capability 1 and gains related capability tags', () => {
  const injection = applyCapabilityTelemetry({
    capabilityId: 1,
    ruleId: 'PROC_DLL_INJECTION',
    eventCategory: 'edr',
    processName: 'injector.exe',
    targetProcessName: 'notepad.exe',
    evidenceType: 'sysmon_create_remote_thread',
    description: 'Remote thread DLL injection detected',
  });
  assert.equal(injection.capabilityId, 1);
  assert.ok(injection.capabilityIds.includes(1));
  assert.ok(injection.capabilityIds.includes(5));

  const dns = applyCapabilityTelemetry({
    capabilityId: 1,
    ruleId: 'PROC_DNS_QUERY',
    processName: 'browser.exe',
    domain: 'example.test',
    description: 'Process DNS query',
  });
  assert.equal(dns.capabilityId, 1);
  assert.ok(dns.capabilityIds.includes(9));
});

test('default false flags do not create fake geo, USB or response coverage', () => {
  const ids = deriveCapabilityIds({
    ruleId: 'AUTH_SUCCESS',
    description: 'successful authentication',
    geoProxy: false,
    geoHosting: false,
    highRiskCountry: false,
    usbBlocked: false,
    blocked: false,
    containmentStatus: 'none',
  });
  assert.equal(ids.includes(10), false);
  assert.equal(ids.includes(23), false);
});

test('empty enrichment containers are not treated as live TI or sandbox proof', () => {
  const ids = deriveCapabilityIds({
    ruleId: 'PROC_STARTED',
    description: 'process started',
    yaraRules: [],
    tiFeeds: {},
    vtScore: undefined,
  });
  assert.equal(ids.includes(18), false);
  assert.equal(ids.includes(25), false);
});

test('domain and IP threat intelligence do not masquerade as hash analysis', () => {
  const ids = deriveCapabilityIds({
    ruleId: 'NET_THREAT_INTEL_SUMMARY',
    source: 'network',
    eventCategory: 'network',
    domain: 'suspicious.example',
    tiEnriched: true,
    tiDomain: 'suspicious.example',
    tiSummary: 'Domain reputation enrichment completed',
  });
  assert.ok(ids.includes(3));
  assert.ok(ids.includes(9));
  assert.equal(ids.includes(25), false);
});

test('generic syscall and auditd telemetry stays out of API Call Monitoring', () => {
  const ids = deriveCapabilityIds({
    ruleId: 'SYS_KERNEL_AUDIT',
    source: 'auditd',
    eventCategory: 'system',
    description: 'auditd syscall process execution observed',
  });
  assert.ok(ids.includes(19));
  assert.equal(ids.includes(20), false);
});

test('explicit WAF and API request telemetry remains API Call Monitoring evidence', () => {
  const wafIds = deriveCapabilityIds({
    ruleId: 'WAF_SQL_INJECTION',
    source: 'waf',
    eventCategory: 'network',
    description: 'WAF blocked API request',
  });
  const requestIds = deriveCapabilityIds({
    ruleId: 'API_REQUEST_SLOW',
    source: 'api_monitor',
    eventCategory: 'api',
    description: 'API request latency exceeded policy',
  });
  assert.ok(wafIds.includes(20));
  assert.ok(requestIds.includes(20));
});

test('legacy desktop IDs do not inflate unrelated canonical cards', () => {
  const processIds = deriveCapabilityIds({
    capabilityId: 5,
    ruleId: 'PROC_STARTED',
    category: 'edr',
    processName: 'bash',
    processMemoryPercent: 0.2,
    description: 'Process started',
  });
  const networkIds = deriveCapabilityIds({
    capabilityId: 7,
    ruleId: 'NET_EXPOSURE_SUMMARY',
    category: 'network',
    source: 'network',
    description: 'Network exposure scan',
  });
  const kernelIds = deriveCapabilityIds({
    capabilityId: 22,
    ruleId: 'SYS_MODULE_LOAD',
    category: 'system',
    description: 'Kernel module loaded',
  });

  assert.ok(processIds.includes(1));
  assert.equal(processIds.includes(5), false);
  assert.ok(networkIds.includes(3));
  assert.equal(networkIds.includes(7), false);
  assert.ok(kernelIds.includes(19));
  assert.equal(kernelIds.includes(22), false);
});

test('normalization replaces a legacy primary ID with a canonical primary ID', () => {
  const event = applyCapabilityTelemetry({
    capabilityId: 5,
    ruleId: 'PROC_TERMINATED',
    processName: 'cmd.exe',
    description: 'Process terminated',
  });
  assert.equal(event.capabilityId, 1);
  assert.deepEqual(event.capabilityIds, [1]);
});

test('DNS payload mentioning Azure or VirusTotal is not a cloud or sandbox event', () => {
  const ids = deriveCapabilityIds({
    ruleId: 'NET_DNS_SUMMARY',
    source: 'network',
    eventCategory: 'network',
    description: 'DNS monitor active',
    domain: 'safebrowsing.googleapis.com',
    full_log: 'captured domains: www.virustotal.com cloudapp.azure.com',
  });
  assert.equal(ids.includes(18), false);
  assert.ok(ids.includes(3));
  assert.ok(ids.includes(9));
});

test('editing the DNS sinkhole source file is not DNS sinkhole telemetry', () => {
  const ids = deriveCapabilityIds({
    ruleId: 'FILE_MODIFIED',
    source: 'file_watch',
    eventCategory: 'file',
    filePath: '/home/chaudahry/Desktop/soc/backend/soc-agent/core/dns_sinkhole.py',
    description: 'File modified: dns_sinkhole.py',
  });
  assert.ok(ids.includes(2));
  assert.equal(ids.includes(31), false);
});

test('does not treat ordinary filenames containing registry as registry telemetry', () => {
  const ids = deriveCapabilityIds({
    ruleId: 'FILE_CREATED',
    source: 'file_watch',
    eventCategory: 'file',
    filePath: '/tmp/build/ObservableRegistry.js',
    description: 'File created: ObservableRegistry.js',
  });
  assert.ok(ids.includes(2));
  assert.equal(ids.includes(6), false);
});

test('keeps genuine Windows registry keys and protected Linux config files in capability 6', () => {
  const windowsIds = deriveCapabilityIds({
    ruleId: 'REGISTRY_MODIFIED',
    source: 'registry_monitor',
    eventCategory: 'registry',
    registryKey: 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  });
  const linuxIds = deriveCapabilityIds({
    ruleId: 'FILE_MODIFIED',
    source: 'file_watch',
    eventCategory: 'file',
    filePath: '/etc/ssh/sshd_config',
    description: 'File modified: sshd_config',
  });
  assert.ok(windowsIds.includes(6));
  assert.ok(linuxIds.includes(6));
});

test('recognizes legacy generated demo alerts so live cards can exclude them', () => {
  const event = { ruleId: 'RULE_004', agentName: 'Agent-2', source: 'ids' };
  assert.equal(isSyntheticAlert(event), true);
  applyCapabilityTelemetry(event);
  assert.equal(event.isSynthetic, true);
  assert.equal(event.dataOrigin, 'synthetic');
});

test('live query requires tenant, time, real rows and indexed capability tags', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const match = liveCapabilityMatch('company-a', since, 'dept-a');
  assert.equal(match.companyId, 'company-a');
  assert.equal(match.departmentId, 'dept-a');
  assert.deepEqual(match.createdAt, { $gte: since });
  assert.deepEqual(match.isSynthetic, { $ne: true });
  assert.throws(() => liveCapabilityMatch(null, since), /companyId/);
});

test('department administrators cannot override or omit their assigned department scope', () => {
  assert.equal(
    resolveCapabilityDepartmentScope({ role: 'department_admin', departmentId: 'dept-a' }, 'dept-b'),
    'dept-a',
  );
  assert.throws(
    () => resolveCapabilityDepartmentScope({ role: 'department_admin' }, 'dept-b'),
    /Department scope required/,
  );
  assert.equal(resolveCapabilityDepartmentScope({ role: 'company_admin' }, 'dept-b'), 'dept-b');
  assert.equal(resolveCapabilityDepartmentScope({ role: 'company_admin' }), undefined);
});

test('detail analytics accepts exactly the 31 public card capabilities', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  assert.equal(PUBLIC_EDR_CAPABILITY_IDS.size, 31);
  for (const id of PUBLIC_EDR_CAPABILITY_IDS) {
    const match = liveTargetCapabilityMatch('company-a', id, since, 'dept-a');
    if (id === 12 || id === 16 || id === 17 || id === 18 || id === 20 || id === 26 || id === 27 || id === 28) {
      assert.equal(match.companyId, 'company-a');
    } else {
      assert.ok(Array.isArray(match.$and));
      assert.equal(match.$and[0].companyId, 'company-a');
    }
  }
  assert.throws(() => liveTargetCapabilityMatch('company-a', 32, since), /Unsupported/);
});

test('high-volume registry, UEBA and email totals use dashboard-identical indexed filters', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const registry = liveTargetCapabilityMatch('company-a', 6, since, 'dept-a');
  const ueba = liveTargetCapabilityMatch('company-a', 11, since, 'dept-a');
  const email = liveTargetCapabilityMatch('company-a', 15, since, 'dept-a');

  assert.deepEqual(registry.$and[1], { $or: [{ capabilityId: 6 }, { capabilityIds: 6 }] });
  assert.deepEqual(ueba.$and[1].$and[0], { $or: [{ capabilityId: 11 }, { capabilityIds: 11 }] });
  assert.equal(ueba.$and[1].$and[1].source.$in.includes('suricata'), false);
  assert.deepEqual(email.$and[1], {
    $or: [
      { capabilityId: 15 },
      { capabilityIds: 15 },
      { source: 'email' },
      { eventCategory: 'phishing' },
    ],
  });
  assert.equal(JSON.stringify(registry).includes('description'), false);
  assert.equal(JSON.stringify(ueba).includes('description'), false);
  assert.equal(JSON.stringify(email).includes('ruleId'), false);
});

test('geolocation queries include explicit GEO policy events but reject generic legacy capability-23 rows', () => {
  const filter = geolocationEvidenceFilter();
  const serialized = JSON.stringify(filter);
  assert.equal(serialized.includes('capabilityIds'), false);
  assert.deepEqual(filter.$and[0], { systemId: { $exists: true, $ne: null } });
  assert.equal(filter.$and[1].$or[0].ruleId.test('GEO_GPS_STATUS'), true);
  assert.equal(filter.$and[1].$or[0].ruleId.test('GEO_PROXY_OR_HOSTING'), true);
  assert.equal(filter.$and[1].$or[0].ruleId.test('NET_CONNECTION_SUMMARY'), false);
  assert.equal(filter.$and[1].$or[5].source.test('gps-location'), true);

  const query = liveTargetCapabilityMatch('company-a', 23, new Date('2026-07-19T00:00:00.000Z'), 'dept-a');
  assert.deepEqual(query.$and[1], filter);
});

test('network overview card matches the IDS log headline inside its dashboard', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const query = liveCardCapabilityMatch('company-a', 3, since, 'dept-a');
  assert.equal(query.$and[0].$and[1].$or[0].capabilityId, 3);
  assert.equal(query.$and[1].type.test('IDS_ALERT'), true);
  assert.equal(query.$and[1].type.test('NETWORK_SUMMARY'), false);
});

test('Sandbox live analytics uses only indexed capability tags', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const match = liveTargetCapabilityMatch('company-a', 18, since, 'dept-a');
  assert.deepEqual(match, {
    companyId: 'company-a',
    departmentId: 'dept-a',
    createdAt: { $gte: since },
    isSynthetic: { $ne: true },
    $or: [{ capabilityId: 18 }, { capabilityIds: 18 }],
  });
  assert.equal(Object.hasOwn(match, '$and'), false);
  assert.equal(Object.hasOwn(match, '$nor'), false);
  assert.equal(JSON.stringify(match).includes('full_log'), false);
  assert.equal(JSON.stringify(match).includes('description'), false);
});

test('API monitoring live analytics uses only indexed capability tags', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const match = liveTargetCapabilityMatch('company-a', 20, since, 'dept-a');
  assert.deepEqual(match, {
    companyId: 'company-a',
    departmentId: 'dept-a',
    createdAt: { $gte: since },
    isSynthetic: { $ne: true },
    $or: [{ capabilityId: 20 }, { capabilityIds: 20 }],
  });
  assert.equal(JSON.stringify(match).includes('full_log'), false);
  assert.equal(JSON.stringify(match).includes('description'), false);
});

test('LOLBins live analytics uses the dedicated compound-index query shape', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const match = liveTargetCapabilityMatch('company-a', 28, since, 'dept-a');
  assert.deepEqual(match, {
    companyId: 'company-a',
    departmentId: 'dept-a',
    createdAt: { $gte: since },
    source: 'lolbins',
    isSynthetic: { $ne: true },
  });
  assert.equal(Object.hasOwn(match, '$and'), false);
  assert.equal(Object.hasOwn(match, '$or'), false);
  assert.equal(Object.hasOwn(match, '$nor'), false);
  assert.throws(() => liveTargetCapabilityMatch(null, 28, since), /companyId/);
  assert.throws(() => liveTargetCapabilityMatch('company-a', 28, new Date('invalid')), /since date/);
});

test('process detail analytics includes untagged process events and excludes inventory summaries', () => {
  const filter = processActivityEventFilter();
  assert.equal(filter.ruleId.$ne, 'PROC_INVENTORY_SUMMARY');
  assert.equal(filter.$or[0].ruleId.test('PROC_STARTED'), true);
  assert.equal(filter.$or[0].ruleId.test('AUTH_SUCCESS'), false);

  const match = liveTargetCapabilityMatch('company-a', 1, new Date('2026-07-19T00:00:00.000Z'));
  assert.equal(match.$and[1].ruleId.$ne, 'PROC_INVENTORY_SUMMARY');
  assert.equal(match.$and[1].$or[0].ruleId.test('PROC_TERMINATED'), true);
});

test('beaconing live analytics uses bounded tenant and indexed evidence branches', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const detail = liveTargetCapabilityMatch('company-a', 26, since, 'dept-a');
  assert.equal(detail.companyId, 'company-a');
  assert.equal(detail.departmentId, 'dept-a');
  assert.deepEqual(detail.createdAt, { $gte: since });
  assert.deepEqual(detail.isSynthetic, { $ne: true });
  assert.deepEqual(detail.$or, [
    { source: 'beaconing' },
    { capabilityId: 26 },
    { capabilityIds: 26 },
  ]);
});

test('ransomware live analytics includes canonical and legacy indexed evidence', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const match = liveTargetCapabilityMatch('company-a', 27, since, 'dept-a');
  assert.equal(match.companyId, 'company-a');
  assert.equal(match.departmentId, 'dept-a');
  assert.deepEqual(match.createdAt, { $gte: since });
  assert.deepEqual(match.isSynthetic, { $ne: true });
  assert.deepEqual(match.$or, [
    { source: 'ransomware' },
    { capabilityId: 27 },
    { capabilityIds: 27 },
  ]);
});

test('24h exact count query is independent from the bounded browser row limit', () => {
  const query = liveTargetCapabilityMatch('company-a', 26, new Date('2026-07-19T00:00:00.000Z'), 'dept-a');
  const small = buildCapabilityAnalyticsPlan(query, 10);
  const large = buildCapabilityAnalyticsPlan(query, 5000);
  assert.equal(small.rows.limit, 10);
  assert.equal(large.rows.limit, 500);
  assert.deepEqual(small.count.filter, query);
  assert.deepEqual(large.count.filter, query);
  assert.equal(Object.hasOwn(small.count, 'limit'), false);
  assert.equal(Object.hasOwn(large.count, 'limit'), false);
});

test('overview keeps modules enabled while reporting exact 24h telemetry state', () => {
  const now = new Date('2026-07-19T12:30:00.000Z');
  const result = attachLiveCapabilityMetrics(
    [{ id: 1, metrics: { totalAlerts: 999 } }, { id: 2 }],
    [{ _id: 1, logs24h: 7, previous24h: 5, reportingAgents: 2, highCritical24h: 1 }],
    [{ _id: { capabilityId: 1, hour: '2026-07-19T12' }, count: 3 }],
    now,
  );
  assert.equal(result.capabilities[0].metrics.logs24h, 7);
  assert.equal(result.capabilities[0].live.status, 'active');
  assert.equal(result.capabilities[0].live.missing, 0);
  assert.equal(result.capabilities[0].live.timeline24h.at(-1).count, 3);
  assert.equal(result.capabilities[1].live.status, 'active');
  assert.equal(result.capabilities[1].live.telemetryStatus, 'idle');
  assert.equal(result.capabilities[1].live.missing, 0);
  assert.equal(result.summary.active, 2);
  assert.equal(result.summary.reporting, 1);
  assert.equal(result.summary.countLimited, false);
});
