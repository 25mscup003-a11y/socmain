const { CAPABILITY_IDS } = require('./capabilityTelemetry');
const { authCapabilityFilter } = require('./authCapability');
const { dnsSinkholeActivityFilter } = require('./advancedCapability');

const LEGACY_SYNTHETIC_FILTER = {
  ruleId: /^RULE_\d{3}$/i,
  agentName: /^Agent-\d+$/i,
  source: { $in: ['firewall', 'ids', 'edr', 'syslog'] },
};

// API Call Monitoring (capability 20) patterns — must match what capabilityAlertFilter(20) uses
const API_MONITOR_PATTERN = /api call|waf block|sql injection|xss|command injection|rce|xxe|ssrf|path traversal|file inclusion|credential stuffing|brute force|bot attack|rate abuse|api abuse|sensitive data|pii|credit card/i;

const PUBLIC_EDR_CAPABILITY_IDS = new Set(CAPABILITY_IDS);

// Dashboard totals must be driven by the normalized capability tags written
// at ingestion. Keeping this predicate shared prevents the overview card and
// a capability-specific dashboard from slowly drifting into different event
// populations as their local text heuristics evolve.
function capabilityTagFilter(capabilityId) {
  const id = Number(capabilityId);
  if (!PUBLIC_EDR_CAPABILITY_IDS.has(id)) throw new Error('Unsupported public capabilityId');
  return { $or: [{ capabilityId: id }, { capabilityIds: id }] };
}

// Geo-IP enrichment is attached to many alert types, but that metadata alone
// does not turn a network/web alert into capability-23 telemetry. Accept only
// native GPS observations or explicit AJNAT GEO detector/policy results so all
// policy-category monitoring cards receive their live events without pulling
// generic geo-enriched connection summaries into capability 23.
function geolocationEvidenceFilter() {
  return { $and: [
    { systemId: { $exists: true, $ne: null } },
    { $or: [
      { ruleId: /^GEO_/i },
      { type: /^GEO_/i },
      { $and: [
        { policyTriggered: true },
        { policyCategory: { $exists: true, $nin: ['', null] } },
      ] },
      { ruleId: /^(?:GEO_GPS_STATUS|GPS_LOCATION_TELEMETRY)$/i },
      { type: /^(?:GEO_GPS_STATUS|GPS_LOCATION_TELEMETRY)$/i },
      { source: /^gps-location$/i },
      { gpsStatus: { $exists: true, $nin: ['', null] } },
      { gpsProvider: { $exists: true, $nin: ['', null] } },
      { $and: [{ gpsLat: { $type: 'number' } }, { gpsLon: { $type: 'number' } }] },
      { 'rawEvent.gpsStatus': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.gpsProvider': { $exists: true, $nin: ['', null] } },
      { $and: [{ 'rawEvent.gpsLat': { $type: 'number' } }, { 'rawEvent.gpsLon': { $type: 'number' } }] },
    ] },
  ] };
}

function emailCapabilityFilter() {
  // Exact legacy fields are retained for mail integrations that predate
  // capability tagging. All branches have tenant-leading compound indexes.
  return { $or: [
    { capabilityId: 15 },
    { capabilityIds: 15 },
    { source: 'email' },
    { eventCategory: 'phishing' },
  ] };
}

function uebaCapabilityFilter() {
  // Capability 11 was historically attached to raw Suricata stream alerts.
  // Requiring a behavioural collector/source keeps those packet rows out while
  // remaining indexable through the company/source/time and capability/time
  // indexes.
  return { $and: [
    capabilityTagFilter(11),
    { source: { $in: [
      'anomaly', 'ueba', 'time_anomaly', 'input_behavior', 'authentication',
      'network', 'email', 'data_security', 'lateral_movement', 'usb',
      'file_watch', 'geo', 'geolocation', 'credential_security', 'process',
      'agent-security', 'lolbins', 'memory_activity', 'script', 'system_changes',
    ] } },
  ] };
}

// Capability tags from older/mobile agents were intentionally broad.  A Web
// & DNS row must contain actual web/DNS evidence; a generic network heartbeat
// is not a web request or DNS query.  Likewise capability 28 is restricted to
// the dedicated LOLBins detector so Zeek/IDS text can never leak into it.
function webDnsEvidenceFilter() {
  return {
    $or: [
      { domain: { $exists: true, $nin: ['', null] } },
      { url: { $exists: true, $nin: ['', null] } },
      { queryType: { $exists: true, $nin: ['', null] } },
      { protocol: /^dns|https?$/i },
      { ruleId: /^(NET_DNS_|BEACON_DNS_|PROC_DNS_|AUTH_WEB_|WAF_|WEB_|HTTP_)/i },
      { source: /^(browser-history|web_monitor|dns_monitor|waf|reverse_proxy)$/i },
      { 'rawEvent.domain': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.query': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.dnsQuery': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.raw.domain': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.raw.dns_queries.0': { $exists: true } },
      { 'rawEvent.raw.captured_dns_queries.0': { $exists: true } },
      { 'rawEvent.raw.http_method': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.workload_type': /^(nginx|apache|iis|tomcat|node|nodejs|php|python|java)$/i },
      { 'rawEvent.raw.workload_type': /^(nginx|apache|iis|tomcat|node|nodejs|php|python|java)$/i },
    ],
  };
}

function lolbinsEvidenceFilter() {
  return {
    $or: [
      { ruleId: /^LOLBIN_/i },
      { source: /^lolbins$/i },
      { malwareType: /^LolBin$/i },
      {
        $and: [
          { $or: [{ capabilityId: 28 }, { capabilityIds: 28 }] },
          { $or: [
            { processName: { $exists: true, $nin: ['', null] } },
            { processCmdline: { $exists: true, $nin: ['', null] } },
            { 'rawEvent.process_name': { $exists: true, $nin: ['', null] } },
            { 'rawEvent.command_line': { $exists: true, $nin: ['', null] } },
          ] },
        ],
      },
    ],
  };
}

function resolveCapabilityDepartmentScope(user = {}, requestedDepartmentId) {
  if (user.role === 'department_admin') {
    if (!user.departmentId) throw new Error('Department scope required');
    return user.departmentId;
  }
  return requestedDepartmentId || undefined;
}

// Process events from older agents may predate capability tagging. Rule IDs are
// the canonical boundary so the live dashboard and generated reports count the
// same telemetry without pulling in inventory snapshots.
function processActivityEventFilter() {
  return {
    ruleId: { $ne: 'PROC_INVENTORY_SUMMARY' },
    $or: [
      { ruleId: /^PROC_/i },
      {
        ruleId: {
          $in: [
            'EDR_MALICIOUS_PROCESS', 'EDR_SUSPICIOUS_CMDLINE', 'EDR_HIGH_MEMORY',
            'RANSOMWARE_ENCRYPTION_PROC', 'RANSOMWARE_BACKUP_TAMPER', 'RANSOMWARE_SHADOW_DELETE',
            'LOLBIN_DETECTED',
            'MEM_FILELESS_EXEC', 'MEM_RWX_REGION', 'MEM_CRED_DUMP',
            'MEM_INJECTION_CMDLINE', 'MEM_LSASS_ACCESS',
            'ANDROID_APP_ACTIVITY', 'android_app_change',
          ],
        },
      },
    ],
  };
}

function liveCapabilityMatch(companyId, since, departmentId) {
  if (!companyId) throw new Error('companyId is required');
  if (!(since instanceof Date) || Number.isNaN(since.getTime())) throw new Error('valid since date is required');
  return {
    companyId,
    ...(departmentId ? { departmentId } : {}),
    createdAt: { $gte: since },
    isSynthetic: { $ne: true },
    // Include docs that either have capabilityIds tagged OR match API monitoring patterns
    $or: [
      { capabilityIds: { $elemMatch: { $gte: 1, $lte: 31 } } },
      { capabilityId: { $gte: 1, $lte: 31 } },
      { capabilityIds: 20 },
      { category: /^api$/i },
      { full_log: API_MONITOR_PATTERN },
      { description: API_MONITOR_PATTERN },
    ],
    $nor: [LEGACY_SYNTHETIC_FILTER],
  };
}

function liveTargetCapabilityMatch(companyId, capabilityId, since, departmentId, systemId = null) {
  const id = Number(capabilityId);
  if (!PUBLIC_EDR_CAPABILITY_IDS.has(id)) throw new Error('Unsupported public capabilityId');
  if (!companyId) throw new Error('companyId is required');
  if (!(since instanceof Date) || Number.isNaN(since.getTime())) throw new Error('valid since date is required');
  const dashboardScope = {
    companyId,
    ...(departmentId ? { departmentId } : {}),
    ...(systemId ? { systemId } : {}),
    createdAt: { $gte: since },
    isSynthetic: { $ne: true },
  };

  // These dashboards intentionally apply stricter evidence boundaries than a
  // plain capability tag. Keep the reusable live query identical so the
  // overview-card count and the number shown after opening the card cannot
  // diverge for the same rolling 24-hour window.
  if (id === 4) {
    return { $and: [dashboardScope, authCapabilityFilter()] };
  }
  if (id === 5) {
    const metricEvidence = { $or: [
      { eventType: 'memory.metric' },
      { memoryMetricType: { $in: ['host', 'process'] } },
    ] };
    return { $and: [dashboardScope, {
      $and: [
        { $or: [{ capabilityId: 5 }, { capabilityIds: 5 }] },
        { $or: [
          { category: /^memory$/i },
          { eventCategory: /^memory$/i },
          { source: /memory/i },
          { memoryMetricType: { $in: ['host', 'process'] } },
          { ruleId: /^(?:MEM_|MEM-|MEMORY_OVERFLOW_|PROC_(?:DLL_INJECTION|REMOTE_THREAD_INJECTION|KERNEL_PROCESS_ACCESS|HOLLOWING|SUSPICIOUS_DLL_LOAD))/i },
        ] },
        { $nor: [metricEvidence] },
      ],
    }] };
  }
  if (id === 6) {
    return { $and: [dashboardScope, capabilityTagFilter(6)] };
  }
  if (id === 7) {
    return { $and: [dashboardScope, {
      $and: [
        { $or: [{ capabilityId: 7 }, { capabilityIds: 7 }] },
        { ruleId: { $nin: ['PROC_ASSET_TELEMETRY_HEALTH', 'PROC_ASSET_INVENTORY'] } },
        { eventType: { $nin: ['Sensor Health', 'Inventory Snapshot'] } },
      ],
    }] };
  }
  if (id === 11) {
    return { $and: [dashboardScope, uebaCapabilityFilter()] };
  }
  if (id === 15) {
    return { $and: [dashboardScope, emailCapabilityFilter()] };
  }
  if (id === 19) {
    return { $and: [dashboardScope, {
      $or: [{ capabilityId: 19 }, { capabilityIds: 19 }],
    }, { ruleId: { $ne: 'KERNEL_INVENTORY_SNAPSHOT' } }] };
  }
  if (id === 23) {
    return { $and: [dashboardScope, geolocationEvidenceFilter()] };
  }
  if (id === 24) {
    return { $and: [dashboardScope, {
      $or: [{ capabilityId: 24 }, { capabilityIds: 24 }],
    }, { ruleId: { $not: /^PROC_ASSET_INVENTORY$/i } }] };
  }
  if (id === 25) {
    const hashEvidence = { $or: [
      { sha256: { $exists: true, $ne: '' } },
      { fileHash: { $exists: true, $ne: '' } },
      { processExecutableSha256: { $exists: true, $ne: '' } },
      { hash: { $exists: true, $ne: '' } },
      { currentHash: { $exists: true, $ne: '' } },
      { newHash: { $exists: true, $ne: '' } },
      { oldHash: { $exists: true, $ne: '' } },
      { signatureStatus: { $exists: true, $nin: ['', null] } },
      { 'rawEvent.sha256': { $exists: true, $ne: '' } },
      { 'rawEvent.file_hash': { $exists: true, $ne: '' } },
      { 'rawEvent.executable_sha256': { $exists: true, $ne: '' } },
      { 'rawEvent.current_hash': { $exists: true, $ne: '' } },
      { 'rawEvent.new_hash': { $exists: true, $ne: '' } },
      { 'rawEvent.old_hash': { $exists: true, $ne: '' } },
      { 'rawEvent.signatureStatus': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.signature_status': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.packageVerificationStatus': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.package_verification_status': { $exists: true, $nin: ['', null] } },
      { 'rawEvent.raw.sha256': { $exists: true, $ne: '' } },
      { 'rawEvent.raw.file_hash': { $exists: true, $ne: '' } },
      { 'rawEvent.raw.signature_status': { $exists: true, $nin: ['', null] } },
    ] };
    return { $and: [dashboardScope, { capabilityIds: 25 }, hashEvidence] };
  }
  if (id === 29) {
    const metricEvidence = { $or: [
      { eventType: 'memory.metric' },
      { memoryMetricType: { $in: ['host', 'process'] } },
    ] };
    return { $and: [dashboardScope, {
      $or: [{ capabilityId: 29 }, { capabilityIds: 29 }],
    }, { $or: [
      { source: 'memory_overflow_detector' },
      { category: /^memory$/i },
      { eventCategory: /^memory$/i },
      { subCategory: /memory[ _-]*(?:overflow|metrics?)/i },
      { eventType: /^memory(?:[._ -]|$)/i },
      { ruleId: /^(?:MEM-|MEMORY_OVERFLOW_)/i },
      { detectionRuleId: /^MEM-/i },
      { memoryMetricType: { $in: ['host', 'process'] } },
    ] }, { $nor: [metricEvidence] }] };
  }
  if (id === 31) {
    return { $and: [dashboardScope, {
      $or: [{ capabilityId: 31 }, { capabilityIds: 31 }],
    }, dnsSinkholeActivityFilter()] };
  }
  // Capability 12 reuses existing FIM/USB/ransomware telemetry. Older agents
  // emitted those signals under their source capability only, so include that
  // indexed evidence while excluding generic network alerts that were once
  // cross-tagged because of the `Unknown` classification schema default.
  if (id === 12) {
    const dataEvidence = { $or: [
      { source: 'data_security' },
      { subCategory: /data[-_ ]security|\bdlp\b/i },
      { dataEventType: { $exists: true, $nin: ['', null] } },
      { dataClassification: { $in: ['Public', 'Internal', 'Confidential', 'Restricted', 'Secret'] } },
      { dlpPattern: { $exists: true, $nin: ['', null] } },
      { dlpMatchCount: { $gt: 0 } },
      { transferChannel: { $exists: true, $nin: ['', null] } },
      { filePath: { $exists: true, $nin: ['', null] } },
      { ruleId: /^(?:DLP_|FILE_SENSITIVE|NET_EXFIL|USB_(?:SENSITIVE_FILE_COPIED|FILE_TRANSFER)|DATA_)/i },
    ] };
    return {
      companyId,
      ...(departmentId ? { departmentId } : {}),
      createdAt: { $gte: since },
      isSynthetic: { $ne: true },
      $or: [
        { $and: [{ $or: [{ capabilityId: 12 }, { capabilityIds: 12 }] }, dataEvidence] },
        { $and: [
          { $or: [{ capabilityId: { $in: [2, 10, 27] } }, { capabilityIds: { $in: [2, 10, 27] } }] },
          { $or: [
            { source: 'file_watch' },
            { fimModule: { $exists: true, $nin: ['', null] } },
            { eventCategory: 'file', filePath: { $exists: true, $nin: ['', null] } },
            { eventCategory: 'usb' },
            { ruleId: /^(?:FILE_(?:CREATED|MODIFIED|DELETED|RENAMED|MOVED|HASH_CHANGED|PERMISSION|OWNERSHIP|HIDDEN|SENSITIVE)|USB_|NET_EXFIL|DLP_|DATA_|RANSOMWARE_)/i },
          ] },
        ] },
      ],
    };
  }
  // Insider-risk events are cross-tagged by the agent and normalized again at
  // ingestion. Keep the live query on the capability/time indexes; broad text
  // predicates caused MongoDB's multiplanner to exceed the route timeout.
  if (id === 16) {
    return {
      companyId,
      ...(departmentId ? { departmentId } : {}),
      createdAt: { $gte: since },
      isSynthetic: { $ne: true },
      $or: [
        { capabilityId: id },
        { capabilityIds: id },
      ],
    };
  }
  // Patch inventory is emitted by the dedicated endpoint collector and is
  // always capability-tagged. Keep this frequently-polled query indexable;
  // the generic legacy scope contains broad predicates that are unnecessary
  // for current capability-17 telemetry and can time out on large tenants.
  if (id === 17) {
    return {
      companyId,
      ...(departmentId ? { departmentId } : {}),
      createdAt: { $gte: since },
      isSynthetic: { $ne: true },
      $or: [
        { capabilityId: 17 },
        { capabilityIds: 17 },
      ],
    };
  }
  // Sandbox telemetry produced by current agents is tagged at ingestion. Keep
  // this hot polling query on the two compound capability/time indexes. The
  // former legacy scope nested this inside a broad capability/regex filter,
  // which made MongoDB's multiplanner exceed the route's five-second budget
  // even for tenants with no sandbox events in the selected window.
  if (id === 18) {
    return {
      companyId,
      ...(departmentId ? { departmentId } : {}),
      createdAt: { $gte: since },
      isSynthetic: { $ne: true },
      $or: [
        { capabilityId: 18 },
        { capabilityIds: 18 },
      ],
    };
  }
  // Capability 20 telemetry is normalized and tagged at ingestion. Do not
  // combine its live polling query with the legacy overview/text-evidence
  // expression: regex scans over full_log/description make MongoDB inspect a
  // tenant's whole alert history and repeatedly exceed the route's 5s limit.
  // Both branches below are served by the existing capability/time indexes.
  if (id === 20) {
    return {
      companyId,
      ...(departmentId ? { departmentId } : {}),
      createdAt: { $gte: since },
      isSynthetic: { $ne: true },
      $or: [
        { capabilityId: 20 },
        { capabilityIds: 20 },
      ],
    };
  }
  // Beacon telemetry is tagged at ingestion and emitted by the dedicated
  // agent detector. Keep this query on the three compound-indexable branches
  // rather than combining it with the broad overview expression used by
  // legacy capabilities; large network tenants otherwise hit the 5s limit.
  if (id === 26) {
    return {
      companyId,
      ...(departmentId ? { departmentId } : {}),
      createdAt: { $gte: since },
      isSynthetic: { $ne: true },
      $or: [
        { source: 'beaconing' },
        { capabilityId: 26 },
        { capabilityIds: 26 },
      ],
    };
  }
  // Ransomware telemetry is emitted by the dedicated detector with a canonical
  // source value. Keep the three evidence branches indexed so legacy detector
  // rows without capability tags and correlated malware rows are both visible.
  if (id === 27) {
    return {
      companyId,
      ...(departmentId ? { departmentId } : {}),
      createdAt: { $gte: since },
      isSynthetic: { $ne: true },
      $or: [
        { source: 'ransomware' },
        { capabilityId: 27 },
        { capabilityIds: 27 },
      ],
    };
  }
  // LOLBins telemetry is emitted by the dedicated detector with a canonical
  // source value. Keep this query flat so MongoDB can satisfy live dashboard
  // polling with the { companyId, source, createdAt } index. Combining the
  // generic overview scope with lolbinsEvidenceFilter() creates a deeply
  // nested $and/$or/$nor expression which can make the query multiplanner
  // exceed the route's five-second execution ceiling on large tenants.
  if (id === 28) {
    return {
      companyId,
      ...(departmentId ? { departmentId } : {}),
      createdAt: { $gte: since },
      source: 'lolbins',
      isSynthetic: { $ne: true },
    };
  }
  // Detail dashboards, reports and the EDR overview must use the exact same
  // tenant/time/source boundary. In particular, raw Suricata/Zeek flow rows
  // are not EDR alerts and must not make an inner dashboard disagree with its
  // overview card.
  const liveScope = overviewLiveCapabilityMatch(companyId, since, departmentId);
  const explicitTag = {
    $or: [
      { capabilityId: id },
      { capabilityIds: id },
    ],
  };
  const target = id === 1 ? processActivityEventFilter() : id === 9 ? {
    $and: [explicitTag, webDnsEvidenceFilter()],
  } : id === 19 ? {
    $or: [
      ...explicitTag.$or,
      { ruleId: { $in: ['SYS_MODULE_LOAD', 'SYS_KERNEL_ERR', 'MEMORY_OVERFLOW_SEGFAULT', 'MEMORY_OVERFLOW_GPF', 'MEM_FILELESS_EXEC', 'EDR_MALICIOUS_PROCESS', 'PROC_UNAUTHORIZED_EXECUTION', 'PROC_SUSPICIOUS'] } },
    ],
  } : explicitTag;
  return { $and: [liveScope, target] };
}

// Match the headline number rendered inside each capability dashboard. The
// Network dashboard labels only IDS_ALERT rows as "logs" even though its
// charts can analyse the wider capability-3 event population.
function liveCardCapabilityMatch(companyId, capabilityId, since, departmentId) {
  const id = Number(capabilityId);
  const target = liveTargetCapabilityMatch(companyId, id, since, departmentId);
  return id === 3
    ? { $and: [target, { type: /^IDS_ALERT$/i }] }
    : target;
}

function overviewLiveCapabilityMatch(companyId, since, departmentId) {
  return {
    ...liveCapabilityMatch(companyId, since, departmentId),
    ruleId: { $ne: 'PROC_INVENTORY_SUMMARY' },
    $and: [
      {
        $or: [
          { source: { $nin: ['suricata', 'zeek'] } },
          {
            source: { $in: ['suricata', 'zeek'] },
            sensorEventType: { $in: ['alert', 'weird'] },
          },
        ],
      },
    ],
  };
}

function capabilityCountPipeline(companyId, since48h, since24h, departmentId) {
  return [
    // Raw IDS flow telemetry is intentionally excluded from the EDR card
    // overview. It is available in the IDS/network drill-down, but scanning
    // hundreds of thousands of packet/flow rows here can time out the entire
    // overview and hide every capability card.
    { $match: overviewLiveCapabilityMatch(companyId, since48h, departmentId) },
    // Step 1: Merge capabilityId (scalar) into capabilityIds array
    {
      $addFields: {
        capabilityIds: {
          $setUnion: [
            { $ifNull: ['$capabilityIds', []] },
            { $cond: [{ $and: [{ $gt: ['$capabilityId', 0] }, { $lte: ['$capabilityId', 31] }] }, ['$capabilityId'], []] },
          ],
        },
      },
    },
    // Step 2: Override for Sandbox (18) and Kernel (19) based on ruleId
    {
      $addFields: {
        capabilityIds: {
          $cond: {
            if: {
              $or: [
                { $eq: ['$processName', 'bwrap'] },
                { $in: ['$ruleId', ['SANDBOX_DETECTED', 'SANDBOX_ESCAPE_ATTEMPT']] }
              ]
            },
            then: {
              $setDifference: [
                { $setUnion: ['$capabilityIds', [18]] },
                [19]
              ]
            },
            else: {
              $cond: {
                if: {
                  $in: ['$ruleId', ['SYS_MODULE_LOAD', 'SYS_KERNEL_ERR', 'MEMORY_OVERFLOW_SEGFAULT', 'MEMORY_OVERFLOW_GPF', 'MEM_FILELESS_EXEC', 'EDR_MALICIOUS_PROCESS', 'PROC_UNAUTHORIZED_EXECUTION', 'PROC_SUSPICIOUS']]
                },
                then: {
                  $setDifference: [
                    { $setUnion: ['$capabilityIds', [19]] },
                    [18]
                  ]
                },
                else: '$capabilityIds'
              }
            }
          }
        }
      }
    },
    // Step 3: Tag API Call Monitoring (20) for docs matching API patterns
    {
      $addFields: {
        capabilityIds: {
          $cond: {
            if: {
              $or: [
                { $in: [20, '$capabilityIds'] },
                { $regexMatch: { input: { $ifNull: ['$category', ''] }, regex: 'api', options: 'i' } },
                { $regexMatch: { input: { $ifNull: ['$full_log', ''] }, regex: 'api call|waf block|sql injection|xss|command injection|rce|xxe|ssrf|path traversal|file inclusion|credential stuffing|brute force|bot attack|rate abuse|api abuse|sensitive data|pii|credit card', options: 'i' } },
                { $regexMatch: { input: { $ifNull: ['$description', ''] }, regex: 'api call|waf block|sql injection|xss|command injection|rce|xxe|ssrf|path traversal|file inclusion|credential stuffing|brute force|bot attack|rate abuse|api abuse|sensitive data|pii|credit card', options: 'i' } },
              ]
            },
            then: { $setUnion: ['$capabilityIds', [20]] },
            else: '$capabilityIds'
          }
        }
      }
    },
    { $unwind: '$capabilityIds' },
    { $match: {
      capabilityIds: { $gte: 1, $lte: 31 },
      $or: [
        { capabilityIds: { $nin: [9, 28] } },
        { $and: [{ capabilityIds: 9 }, webDnsEvidenceFilter()] },
        { $and: [{ capabilityIds: 28 }, lolbinsEvidenceFilter()] },
      ],
    } },
    {
      $group: {
        _id: '$capabilityIds',
        logs24h: { $sum: { $cond: [{ $gte: ['$createdAt', since24h] }, 1, 0] } },
        previous24h: { $sum: { $cond: [{ $lt: ['$createdAt', since24h] }, 1, 0] } },
        highCritical24h: {
          $sum: {
            $cond: [
              { $and: [{ $gte: ['$createdAt', since24h] }, { $in: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, ['critical', 'high']] }] },
              1,
              0,
            ],
          },
        },
        unauthorized24h: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $gte: ['$createdAt', since24h] },
                  {
                    $regexMatch: {
                      input: {
                        $concat: [
                          { $ifNull: ['$ruleId', ''] }, ' ',
                          { $ifNull: ['$description', ''] }, ' ',
                          { $ifNull: ['$userAction', ''] },
                        ],
                      },
                      regex: /unauthori[sz]ed|access denied|permission denied|failed login/i,
                    },
                  },
                ],
              },
              1,
              0,
            ],
          },
        },
        lastSeenAt: { $max: { $cond: [{ $gte: ['$createdAt', since24h] }, '$createdAt', null] } },
        reportingAgents: {
          $addToSet: {
            $cond: [
              { $gte: ['$createdAt', since24h] },
              { $ifNull: ['$systemId', { $ifNull: ['$endpointId', { $ifNull: ['$agentId', '$agentName'] }] }] },
              null,
            ],
          },
        },
      },
    },
    {
      $project: {
        _id: 1,
        logs24h: 1,
        previous24h: 1,
        highCritical24h: 1,
        unauthorized24h: 1,
        lastSeenAt: 1,
        reportingAgents: {
          $size: {
            $filter: { input: '$reportingAgents', as: 'agent', cond: { $ne: ['$$agent', null] } },
          },
        },
      },
    },
  ];
}

function capabilityTimelinePipeline(companyId, since24h, departmentId, until) {
  const match = overviewLiveCapabilityMatch(companyId, since24h, departmentId);
  if (until instanceof Date && !Number.isNaN(until.getTime())) {
    match.createdAt = { $gte: since24h, $lte: until };
  }
  return [
    { $match: match },
    // Step 1: Merge capabilityId scalar into array
    {
      $addFields: {
        capabilityIds: {
          $setUnion: [
            { $ifNull: ['$capabilityIds', []] },
            { $cond: [{ $and: [{ $gt: ['$capabilityId', 0] }, { $lte: ['$capabilityId', 31] }] }, ['$capabilityId'], []] },
          ],
        },
      },
    },
    // Step 2: Sandbox (18) / Kernel (19) overrides
    {
      $addFields: {
        capabilityIds: {
          $cond: {
            if: {
              $or: [
                { $eq: ['$processName', 'bwrap'] },
                { $in: ['$ruleId', ['SANDBOX_DETECTED', 'SANDBOX_ESCAPE_ATTEMPT']] }
              ]
            },
            then: {
              $setDifference: [
                { $setUnion: ['$capabilityIds', [18]] },
                [19]
              ]
            },
            else: {
              $cond: {
                if: {
                  $in: ['$ruleId', ['SYS_MODULE_LOAD', 'SYS_KERNEL_ERR', 'MEMORY_OVERFLOW_SEGFAULT', 'MEMORY_OVERFLOW_GPF', 'MEM_FILELESS_EXEC', 'EDR_MALICIOUS_PROCESS', 'PROC_UNAUTHORIZED_EXECUTION', 'PROC_SUSPICIOUS']]
                },
                then: {
                  $setDifference: [
                    { $setUnion: ['$capabilityIds', [19]] },
                    [18]
                  ]
                },
                else: '$capabilityIds'
              }
            }
          }
        }
      }
    },
    // Step 3: Tag API Call Monitoring (20) for matching docs
    {
      $addFields: {
        capabilityIds: {
          $cond: {
            if: {
              $or: [
                { $in: [20, '$capabilityIds'] },
                { $regexMatch: { input: { $ifNull: ['$category', ''] }, regex: 'api', options: 'i' } },
                { $regexMatch: { input: { $ifNull: ['$full_log', ''] }, regex: 'api call|waf block|sql injection|xss|command injection|rce|xxe|ssrf|path traversal|file inclusion|credential stuffing|brute force|bot attack|rate abuse|api abuse|sensitive data|pii|credit card', options: 'i' } },
                { $regexMatch: { input: { $ifNull: ['$description', ''] }, regex: 'api call|waf block|sql injection|xss|command injection|rce|xxe|ssrf|path traversal|file inclusion|credential stuffing|brute force|bot attack|rate abuse|api abuse|sensitive data|pii|credit card', options: 'i' } },
              ]
            },
            then: { $setUnion: ['$capabilityIds', [20]] },
            else: '$capabilityIds'
          }
        }
      }
    },
    { $unwind: '$capabilityIds' },
    { $match: {
      capabilityIds: { $gte: 1, $lte: 31 },
      $or: [
        { capabilityIds: { $nin: [9, 28] } },
        { $and: [{ capabilityIds: 9 }, webDnsEvidenceFilter()] },
        { $and: [{ capabilityIds: 28 }, lolbinsEvidenceFilter()] },
      ],
    } },
    {
      $group: {
        _id: {
          capabilityId: '$capabilityIds',
          hour: { $dateToString: { format: '%Y-%m-%dT%H', date: '$createdAt', timezone: 'UTC' } },
        },
        count: { $sum: 1 },
      },
    },
  ];
}

function hourlyKeys(now = new Date()) {
  const hour = new Date(now);
  hour.setUTCMinutes(0, 0, 0);
  return Array.from({ length: 24 }, (_, index) => {
    const bucket = new Date(hour.getTime() - (23 - index) * 60 * 60 * 1000);
    return bucket.toISOString().slice(0, 13);
  });
}

function attachLiveCapabilityMetrics(capabilities = [], countRows = [], timelineRows = [], now = new Date()) {
  const counts = new Map(countRows.map(row => [Number(row._id), row]));
  const timelineCounts = new Map(
    timelineRows.map(row => [`${Number(row._id?.capabilityId)}:${row._id?.hour}`, Number(row.count || 0)]),
  );
  const hours = hourlyKeys(now);

  const enriched = capabilities.map(capability => {
    const id = Number(capability.id);
    const row = counts.get(id) || {};
    const logs24h = Number(row.logs24h || 0);
    const previous24h = Number(row.previous24h || 0);
    const reporting = logs24h > 0;
    const trendPct = previous24h > 0
      ? Math.round(((logs24h - previous24h) / previous24h) * 100)
      : logs24h > 0 ? 100 : 0;
    const timeline24h = hours.map(hour => ({ hour: `${hour}:00:00.000Z`, count: timelineCounts.get(`${id}:${hour}`) || 0 }));
    const live = {
      // All canonical EDR modules are enabled. Event presence is a separate
      // reporting state so a quiet 24h window never disables a capability.
      status: 'active',
      enabled: true,
      telemetryStatus: reporting ? 'reporting' : 'idle',
      missing: 0,
      logs24h,
      previous24h,
      highCritical24h: Number(row.highCritical24h || 0),
      unauthorized24h: Number(row.unauthorized24h || 0),
      reportingAgents: Number(row.reportingAgents || 0),
      lastSeenAt: row.lastSeenAt || null,
      trendPct,
      timeline24h,
      windowHours: 24,
      source: 'tenant_alerts',
    };
    return {
      ...capability,
      live,
      metrics: {
        ...(capability.metrics || {}),
        logs24h,
        previousLogs24h: previous24h,
        highCritical24h: live.highCritical24h,
        unauthorized24h: live.unauthorized24h,
        reportingAgents: live.reportingAgents,
        timeline24h,
      },
    };
  });

  const active = enriched.length;
  const reporting = enriched.filter(capability => capability.live.telemetryStatus === 'reporting').length;
  return {
    capabilities: enriched,
    summary: {
      active,
      missing: 0,
      reporting,
      idle: active - reporting,
      total: active,
      score: active ? Math.round((reporting / active) * 100) : 0,
      windowHours: 24,
      countMode: 'exact',
      countLimited: false,
    },
  };
}

function mergeCanonicalCapabilityRows(alertRows = [], canonicalRows = [], canonicalIds = new Set()) {
  const rowCapabilityId = row => Number(row?._id?.capabilityId ?? row?._id);
  const replacementIds = new Set(canonicalRows
    .filter(row => canonicalIds.has(rowCapabilityId(row)) && (
      Number(row.logs24h || 0) > 0 || Number(row.previous24h || 0) > 0 || Number(row.count || 0) > 0
    ))
    .map(rowCapabilityId));
  // Incident grouping is stored canonically in EdrIncident. An alert text match
  // must never override an empty canonical incident window.
  if (canonicalIds.has(34)) replacementIds.add(34);
  return [
    ...alertRows.filter(row => !replacementIds.has(rowCapabilityId(row))),
    ...canonicalRows.filter(row => replacementIds.has(rowCapabilityId(row))),
  ];
}

module.exports = {
  LEGACY_SYNTHETIC_FILTER,
  PUBLIC_EDR_CAPABILITY_IDS,
  attachLiveCapabilityMetrics,
  capabilityTagFilter,
  emailCapabilityFilter,
  geolocationEvidenceFilter,
  capabilityCountPipeline,
  capabilityTimelinePipeline,
  hourlyKeys,
  liveCardCapabilityMatch,
  liveCapabilityMatch,
  liveTargetCapabilityMatch,
  overviewLiveCapabilityMatch,
  mergeCanonicalCapabilityRows,
  processActivityEventFilter,
  resolveCapabilityDepartmentScope,
  uebaCapabilityFilter,
  webDnsEvidenceFilter,
  lolbinsEvidenceFilter,
};
