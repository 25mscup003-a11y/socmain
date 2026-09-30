const ADVANCED_CAPABILITY_IDS = new Set([29, 30, 31]);

function clampWindowHours(value, fallback = 24) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(24, Math.max(1, Math.trunc(parsed)));
}

function clampResultLimit(value, fallback = 250) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(500, Math.max(1, Math.trunc(parsed)));
}

function buildCapabilityAnalyticsPlan(query, requestedLimit) {
  if (!query || typeof query !== 'object') throw new Error('query is required');
  return {
    rows: { filter: query, limit: clampResultLimit(requestedLimit, 250) },
    // The exact count deliberately has no row limit. Keeping both operations
    // in one plan prevents dashboard pagination from changing the 24h KPI.
    count: { filter: query },
  };
}

function textEvidence(pattern) {
  return [
    { ruleId: pattern },
    { type: pattern },
    { description: pattern },
    { full_log: pattern },
    { source: pattern },
    { category: pattern },
    { subCategory: pattern },
    { eventType: pattern },
    { userAction: pattern },
    { 'rawEvent.rule_id': pattern },
    { 'rawEvent.ruleId': pattern },
    { 'rawEvent.type': pattern },
    { 'rawEvent.description': pattern },
    { 'rawEvent.user_action': pattern },
    { 'rawEvent.event_type': pattern },
  ];
}

function dnsSinkholeActivityFilter() {
  return {
    $or: [
      { source: /^dns_sinkhole$/i },
      { ruleId: /^DNS_SINKHOLE/i },
      { eventType: /sinkhole/i },
      { subCategory: /^dns-sinkhole$/i },
      { sinkholeIp: { $exists: true, $ne: '' } },
      { responseType: /sinkhole|nxdomain|refused/i },
      {
        $and: [
          { domain: { $exists: true, $ne: '' } },
          {
            $or: [
              { blocked: true },
              { actionTaken: /block|sinkhole/i },
              { containmentStatus: /block|sinkhole/i },
              { userAction: /dns_sinkhole|sinkhole|dns domain block/i },
            ],
          },
        ],
      },
    ],
  };
}

function capabilityEvidenceFilter(capabilityId) {
  const id = Number(capabilityId);
  if (!ADVANCED_CAPABILITY_IDS.has(id)) return null;

  const exact = [
    { capabilityId: id },
    { capabilityIds: id },
    { 'rawEvent.capabilityId': id },
    { 'rawEvent.capability_id': id },
    { 'rawEvent.capabilityIds': id },
    { 'rawEvent.capability_ids': id },
  ];

  if (id === 29) {
    return {
      $or: [
        ...exact,
        ...textEvidence(/memory[_ -]?overflow|memoverflow|buffer overflow|sigsegv|sigabrt|segmentation fault|stack smash|heap spray|asan|nx violation|dep violation|kernel bug/i),
      ],
    };
  }
  if (id === 30) {
    return {
      $or: [
        ...exact,
        ...textEvidence(/cache poison|dns.*poison|ttl drop|txid mismatch|multiple dns responses|unexpected ip|dns anomaly/i),
      ],
    };
  }
  return {
    $or: [
      ...exact,
      ...dnsSinkholeActivityFilter().$or,
    ],
  };
}

function indexedCapabilityFilter(capabilityId) {
  const id = Number(capabilityId);
  if (!ADVANCED_CAPABILITY_IDS.has(id)) return null;
  return { $or: [{ capabilityId: id }, { capabilityIds: id }] };
}

function buildCapabilityQuery({ companyId, capabilityId, since, departmentId }) {
  if (!companyId) throw new Error('companyId is required');
  const evidence = indexedCapabilityFilter(capabilityId);
  if (!evidence) throw new Error('Unsupported capabilityId');
  const scope = { companyId, createdAt: { $gte: since } };
  if (departmentId) scope.departmentId = departmentId;
  const capabilityIdNumber = Number(capabilityId);
  const guards = [scope, evidence];
  if (capabilityIdNumber === 31) {
    guards.push(dnsSinkholeActivityFilter());
  }
  return { $and: guards };
}

function firstValue(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function rawObject(alert = {}) {
  const raw = alert.rawEvent && typeof alert.rawEvent === 'object' ? alert.rawEvent : {};
  const nested = raw.raw && typeof raw.raw === 'object' ? raw.raw : {};
  return { ...raw, ...nested };
}

function indicatorValue(alert = {}, kind) {
  const raw = rawObject(alert);
  if (kind === 'domain') return firstValue(
    alert.domain, alert.tiDomain, raw.domain, raw.query, raw.dns_query, raw.qname,
    raw.hostname, raw.website, raw.indicator_type === 'domain' ? raw.indicator : undefined
  );
  if (kind === 'ip') return firstValue(
    alert.srcip, alert.destip, raw.new_ip, raw.response_ip, raw.answer_ip,
    raw.indicator_type === 'ip' ? raw.indicator : undefined
  );
  if (kind === 'hash') return firstValue(
    alert.fileHash, alert.hash, raw.sha256, raw.file_hash,
    raw.indicator_type === 'hash' ? raw.indicator : undefined
  );
  if (kind === 'process') return firstValue(alert.processName, raw.process, raw.process_name);
  if (kind === 'host') return firstValue(alert.hostname, alert.agentName, alert.systemId?.name, alert.endpointId);
  if (kind === 'source') return firstValue(alert.tiFeeds?.feedSource, alert.detectionSource, alert.source, raw.feed_source, raw.feed);
  if (kind === 'queryType') return firstValue(alert.queryType, raw.query_type, raw.queryType, raw.record_type);
  if (kind === 'responseType') return firstValue(alert.responseType, raw.response_type, raw.responseType, raw.type);
  if (kind === 'category') return firstValue(alert.threatCategory, alert.malwareType, alert.subCategory, alert.eventType, raw.threat_category, raw.reason, raw.type);
  if (kind === 'country') return firstValue(alert.country, alert.geoCountry, alert.destGeoCountry, raw.country, raw.country_code);
  return undefined;
}

function topValues(alerts, kind, limit = 8) {
  const counts = new Map();
  for (const alert of alerts || []) {
    const value = indicatorValue(alert, kind);
    if (value === undefined || value === null || value === '' || value === '-') continue;
    const label = Array.isArray(value) ? value.join(', ') : String(value);
    counts.set(label, (counts.get(label) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([label, value]) => ({ label, value }));
}

function summarizeCapabilityRows(alerts = [], systems = [], capabilityId, exact = {}) {
  const severity = { critical: 0, high: 0, medium: 0, low: 0, ...(exact.severity || {}) };
  if (!exact.severity) {
    alerts.forEach(alert => {
      const key = String(alert.severity || 'low').toLowerCase();
      severity[key] = (severity[key] || 0) + 1;
    });
  }
  const unique = kind => new Set(alerts.map(alert => indicatorValue(alert, kind)).filter(Boolean)).size;
  const blocked = alerts.filter(alert => alert.blocked || /block|sinkhol|quarantin/i.test(`${alert.actionTaken || ''} ${alert.containmentStatus || ''} ${alert.userAction || ''}`)).length;
  const open = alerts.filter(alert => !['resolved', 'false_positive'].includes(String(alert.status || 'open').toLowerCase())).length;
  const onlineAgents = systems.filter(system => system.agentOk || system.isOnline || ['online', 'active'].includes(String(system.status || '').toLowerCase())).length;
  return {
    total: Number(exact.total ?? alerts.length),
    ...severity,
    affectedEndpoints: Number(exact.affectedEndpoints ?? unique('host')),
    blocked,
    open,
    maliciousIps: unique('ip'),
    maliciousDomains: unique('domain'),
    hashMatches: unique('hash'),
    processes: unique('process'),
    onlineAgents,
    monitoredSystems: systems.length,
    breakdowns: {
      rules: topValues(alerts.map(alert => ({ ...alert, eventType: alert.ruleId || alert.eventType })), 'category'),
      sources: topValues(alerts, 'source'),
      domains: topValues(alerts, 'domain'),
      ips: topValues(alerts, 'ip'),
      hashes: topValues(alerts, 'hash'),
      processes: topValues(alerts, 'process'),
      hosts: topValues(alerts, 'host'),
      categories: topValues(alerts, 'category'),
      queryTypes: topValues(alerts, 'queryType'),
      responseTypes: topValues(alerts, 'responseType'),
      countries: topValues(alerts, 'country'),
    },
    capabilityId: Number(capabilityId),
  };
}

module.exports = {
  ADVANCED_CAPABILITY_IDS,
  buildCapabilityAnalyticsPlan,
  buildCapabilityQuery,
  capabilityEvidenceFilter,
  clampResultLimit,
  clampWindowHours,
  dnsSinkholeActivityFilter,
  indicatorValue,
  indexedCapabilityFilter,
  summarizeCapabilityRows,
  topValues,
};
