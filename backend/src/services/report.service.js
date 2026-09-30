const Alert   = require('../models/Alert.model');
const System  = require('../models/System.model');
const SoarLog = require('../models/SoarLog.model');
const FirewallRule = require('../models/FirewallRule.model');
const Firewall = require('../models/Firewall.model');
const CorrelationEvent = require('../models/CorrelationEvent.model');
const ForensicHunt = require('../models/ForensicHunt.model');
const ForensicEvidence = require('../models/ForensicEvidence.model');
const AiAnalysis = require('../models/AiAnalysis.model');
const SoarExecution = require('../models/SoarExecution.model');
const mongoose = require('mongoose');
const { calculateScore, scoreToGrade, scoreToRisk, scoreToHealth } = require('../utils/securityScore');

function normalizeSev(s) {
  return ['critical','high','medium','low'].includes((s||'').toLowerCase())
    ? s.toLowerCase() : 'low';
}

function operationalReport(companyId, type, start, end, records, { systemCount = 0, soarActions = 0 } = {}) {
  const severities = { critical: 0, high: 0, medium: 0, low: 0 };
  const statuses = {};
  const days = {};
  records.forEach(item => {
    const severity = normalizeSev(item.severity);
    const status = item.status || 'open';
    const day = new Date(item.timestamp || item.createdAt || Date.now()).toISOString().slice(0, 10);
    severities[severity] += 1;
    statuses[status] = (statuses[status] || 0) + 1;
    days[day] = (days[day] || 0) + 1;
  });
  const scoreResult = records.length ? calculateScore(severities) : {
    score: 100, grade: 'A', risk: 'low', systemHealth: 'Healthy',
    deductions: { critical: 0, high: 0, medium: 0, low: 0 },
  };
  const resolved = records.filter(item => ['resolved', 'completed', 'verified', 'active'].includes(item.status)).length;
  return {
    meta: { companyId, from: start.toISOString(), to: end.toISOString(), type, generatedAt: new Date().toISOString() },
    summary: {
      totalAlerts: records.length,
      openCritical: records.filter(item => normalizeSev(item.severity) === 'critical' && !['resolved', 'completed'].includes(item.status)).length,
      systemCount,
      soarActionsExecuted: soarActions,
      avgResolutionMinutes: null,
      resolvedCount: resolved,
    },
    securityScore: { ...scoreResult, score: Math.round(scoreResult.score), severity: severities },
    bySeverity: Object.entries(severities).map(([severity, count]) => ({ severity, count })),
    byStatus: Object.entries(statuses).map(([status, count]) => ({ status, count })),
    byDay: Object.entries(days).sort(([a], [b]) => a.localeCompare(b)).map(([date, count]) => ({ date, count })),
    topAgents: [], topRules: [], top10Alerts: records.slice(0, 10), logsSnapshot: records.slice(0, 5000),
  };
}

async function generateOperationalReport(companyId, cid, type, start, end, deptFilter) {
  const dated = { companyId: cid, createdAt: { $gte: start, $lte: end } };
  if (deptFilter) dated.departmentId = Array.isArray(deptFilter)
    ? { $in: deptFilter.map(id => new mongoose.Types.ObjectId(id)) }
    : new mongoose.Types.ObjectId(deptFilter);
  const systemCountPromise = System.countDocuments({ companyId: cid, status: 'active' });

  if (type === 'firewall') {
    const scope = { companyId: cid };
    if (dated.departmentId) scope.departmentId = dated.departmentId;
    const [hierarchyRules, legacyRules, systemCount] = await Promise.all([
      Firewall.find(scope).sort({ createdAt: -1 }).lean(),
      FirewallRule.find(scope).sort({ createdAt: -1 }).lean(),
      systemCountPromise,
    ]);
    const rules = [...hierarchyRules, ...legacyRules];
    const records = rules.map(rule => ({
      id: rule._id, description: rule.ruleName || rule.name || rule.description || 'Firewall rule',
      severity: ['block', 'deny', 'drop', 'reject'].includes(rule.action) ? 'high' : 'low',
      source: `${rule.action || 'allow'} ${rule.protocol || 'all'}`, srcip: rule.sourceIp || 'any',
      system: rule.level || (rule.applyToAll ? 'All systems' : `${rule.systemIds?.length || 0} systems`),
      timestamp: rule.createdAt, status: rule.status || (rule.enabled ? 'active' : 'disabled'),
    }));
    return operationalReport(companyId, type, start, end, records, { systemCount });
  }

  if (type === 'incidents' || type === 'threat-intelligence') {
    const query = type === 'threat-intelligence' ? { ...dated, incidentSource: 'threat_intelligence' } : dated;
    const [incidents, systemCount] = await Promise.all([
      CorrelationEvent.find(query).sort({ lastActivityAt: -1, createdAt: -1 }).limit(5000)
        .populate('assignedTo', 'name email role')
        .populate('resolutionHistory.changedBy', 'name email role')
        .lean(), systemCountPromise,
    ]);
    const records = incidents.map(item => ({
      id: item._id, description: item.patternName || item.description || item.incidentId,
      severity: item.severity, source: item.incidentSource || 'correlation', srcip: item.iocs?.[0] || '—',
      system: item.agentName || '—', timestamp: item.lastActivityAt || item.createdAt, status: item.status,
      assignedTo: item.assignedTo,
      resolvedBy: [...(item.resolutionHistory || [])].reverse().find(entry => entry.changedBy)?.changedBy || item.dispositionBy,
      resolvedAt: item.resolvedAt, incidentId: item.incidentId,
    }));
    return operationalReport(companyId, type, start, end, records, { systemCount });
  }

  if (type === 'forensics') {
    const evidenceQuery = { companyId: cid, collectedAt: { $gte: start, $lte: end } };
    if (dated.departmentId) evidenceQuery.departmentId = dated.departmentId;
    const [hunts, evidence, systemCount] = await Promise.all([
      ForensicHunt.find(dated).sort({ createdAt: -1 }).limit(2500).lean(),
      ForensicEvidence.find(evidenceQuery)
        .sort({ collectedAt: -1 }).limit(2500).lean(),
      systemCountPromise,
    ]);
    const records = [
      ...hunts.map(item => ({ id: item._id, description: item.name, severity: item.status === 'failed' ? 'high' : 'low', source: 'forensic hunt', system: item.clientId || '—', timestamp: item.createdAt, status: item.status })),
      ...evidence.map(item => ({ id: item._id, description: item.name, severity: item.integrityStatus === 'mismatch' ? 'critical' : 'low', source: item.type || 'evidence', system: item.sourceHost || '—', timestamp: item.collectedAt, status: item.integrityStatus })),
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    return operationalReport(companyId, type, start, end, records, { systemCount });
  }

  if (type === 'ai-analysis') {
    const aiQuery = { companyId: cid, createdAt: { $gte: start, $lte: end } };
    // AiAnalysis records do not store departmentId. For department-scoped users,
    // restrict the report to their authorized forensic evidence resources.
    if (deptFilter) {
      const departmentIds = (Array.isArray(deptFilter) ? deptFilter : [deptFilter])
        .map(id => new mongoose.Types.ObjectId(id));
      const evidenceIds = await ForensicEvidence.distinct('_id', {
        companyId: cid,
        departmentId: { $in: departmentIds },
      });
      aiQuery.resourceType = 'ForensicEvidence';
      aiQuery.resourceId = { $in: evidenceIds };
    }
    const [analyses, systemCount] = await Promise.all([
      AiAnalysis.find(aiQuery).sort({ createdAt: -1 }).limit(5000).lean(),
      systemCountPromise,
    ]);
    const records = analyses.map(item => ({
      id: item._id,
      description: item.output?.summary || item.error || String(item.taskType || 'AI security analysis').replace(/_/g, ' '),
      severity: item.status === 'failed' ? 'high' : ['queued', 'processing'].includes(item.status) ? 'medium' : 'low',
      source: item.resourceType || 'AI Analysis',
      srcip: item.sourceIp || '—',
      system: item.inputSummary?.hostname || item.inputSummary?.agentName || item.inputSummary?.title || String(item.resourceId || '—'),
      agent: item.model || 'Configured AI provider',
      timestamp: item.createdAt,
      status: item.status,
      confidence: item.confidence,
      taskType: item.taskType,
      completedAt: item.completedAt,
    }));
    return operationalReport(companyId, type, start, end, records, { systemCount });
  }

  const [executions, systemCount] = await Promise.all([
    SoarExecution.find(dated).sort({ createdAt: -1 }).limit(5000).lean(), systemCountPromise,
  ]);
  const records = executions.map(item => ({
    id: item._id, description: item.ruleName || item.playbookName || 'SOAR execution',
    severity: item.status === 'failed' ? 'high' : 'low', source: item.triggerType || 'automation',
    system: item.ticketId ? `Ticket ${item.ticketId}` : item.currentStepName || '—',
    timestamp: item.createdAt, status: item.status,
  }));
  return operationalReport(companyId, type, start, end, records, { systemCount, soarActions: records.length });
}

async function generateIdsReport(companyId, cid, start, end, deptFilter, exportMode) {
  const match = {
    companyId: cid,
    createdAt: { $gte: start, $lte: end },
    $and: [
      { $or: [
        { sourceType: 'IDS' }, { module: { $in: ['IDS', 'ids'] } },
        { source_type: { $in: ['IDS', 'ids'] } },
        { event_category: { $in: ['ids_alert', 'intrusion_detection'] } },
      ] },
      { module: { $nin: ['IPS', 'ips'] } },
      { source_type: { $nin: ['IPS', 'ips'] } },
      { event_category: { $nin: ['ips_block', 'blacklist_event', 'intrusion_prevention'] } },
      { blocked: { $ne: true } },
    ],
  };
  if (deptFilter) match.departmentId = Array.isArray(deptFilter)
    ? { $in: deptFilter.map(id => new mongoose.Types.ObjectId(id)) }
    : new mongoose.Types.ObjectId(deptFilter);
  const [facet, systemCount] = await Promise.all([
    Alert.aggregate([
      { $match: match },
      { $facet: {
        total: [{ $count: 'count' }],
        severity: [{ $group: { _id: { $toLower: '$severity' }, count: { $sum: 1 } } }],
        status: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
        day: [{ $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } }, { $sort: { _id: 1 } }],
        records: [{ $sort: { createdAt: -1 } }, { $limit: exportMode ? 5000 : 20 }, { $project: { description: 1, severity: 1, source: 1, sourceType: 1, srcip: 1, agentName: 1, createdAt: 1, status: 1 } }],
      } },
    ]).then(rows => rows[0] || {}),
    System.countDocuments({ companyId: cid, status: 'active' }),
  ]);
  const records = (facet.records || []).map(item => ({
    id: item._id, description: item.description || 'IDS event', severity: normalizeSev(item.severity),
    source: item.sourceType || item.source || 'IDS', srcip: item.srcip || '—', system: item.agentName || '—',
    agent: item.agentName || '—', timestamp: item.createdAt, status: item.status || 'open',
  }));
  const report = operationalReport(companyId, 'ids', start, end, records, { systemCount });
  const severity = { critical: 0, high: 0, medium: 0, low: 0 };
  (facet.severity || []).forEach(item => { severity[normalizeSev(item._id)] += item.count; });
  const total = facet.total?.[0]?.count || 0;
  const score = total ? calculateScore(severity) : report.securityScore;
  report.summary.totalAlerts = total;
  report.summary.openCritical = (facet.severity || []).find(item => item._id === 'critical')?.count || 0;
  report.bySeverity = Object.entries(severity).map(([name, count]) => ({ severity: name, count }));
  report.byStatus = (facet.status || []).map(item => ({ status: item._id || 'open', count: item.count }));
  report.byDay = (facet.day || []).map(item => ({ date: item._id, count: item.count }));
  report.securityScore = { ...score, score: Math.round(score.score), severity };
  return report;
}

async function generateWafReport(companyId, cid, start, end, exportMode) {
  const db = mongoose.connection.db;
  const companyValues = [String(companyId), cid];
  const query = {
    company: { $in: companyValues },
    ts: { $gte: start, $lte: end },
  };
  const [events, systemCount] = await Promise.all([
    db.collection('waf_events').find(query)
      .sort({ ts: -1 }).limit(exportMode ? 5000 : 500).toArray(),
    System.countDocuments({ companyId: cid, status: 'active' }),
  ]);
  const records = events.map(item => ({
    id: item._id,
    description: item.attackType || item.ruleId || 'WAF event',
    severity: normalizeSev(item.severity),
    source: item.provider || item.source || 'WAF',
    srcip: item.ip || item.srcip || '—',
    system: item.hostname || item.systemId || '—',
    timestamp: item.ts,
    status: item.blocked === false ? 'detected' : 'blocked',
    ruleId: item.ruleId,
    requestPath: item.requestPath,
  }));
  return operationalReport(companyId, 'waf', start, end, records, { systemCount });
}

const REPORT_FILTERS = {
  fim: [
    { capabilityIds: 2 }, { capabilityId: 2 },
    { eventCategory: 'file' }, { event_category: 'file' },
    { module: { $in: ['FIM', 'fim', 'file_integrity'] } },
    { source_type: { $in: ['FIM', 'fim'] } },
  ],
  network: [
    { capabilityIds: 3 }, { capabilityId: 3 },
    { eventCategory: 'network' }, { event_category: 'network' },
    { module: { $in: ['NETWORK', 'network', 'NETFLOW', 'netflow'] } },
  ],
  ids: [
    { sourceType: 'IDS' }, { module: { $in: ['IDS', 'ids'] } },
    { source_type: 'ids' }, { event_category: { $in: ['ids_alert', 'ids_event'] } },
  ],
  firewall: [
    { module: { $in: ['FIREWALL', 'firewall'] } },
  ],
  ips: [
    { sourceType: 'IPS' }, { module: { $in: ['IPS', 'ips'] } },
    { source_type: 'ips' }, { event_category: { $in: ['ips_block', 'ips_event'] } },
  ],
  waf: [
    { sourceType: 'WAF' }, { source: { $in: ['waf', 'WAF'] } },
    { module: { $in: ['WAF', 'waf'] } },
    { source_type: { $in: ['WAF', 'waf'] } },
    { eventCategory: { $in: ['waf', 'web_attack', 'web_application_firewall'] } },
    { event_category: { $in: ['waf', 'web_attack', 'web_application_firewall'] } },
    { ruleId: { $regex: /^WAF_/i } },
  ],
  'threat-intelligence': [
    { sourceType: 'THREAT_FEED' },
  ],
  forensics: [
    { module: { $in: ['FORENSICS', 'forensics'] } },
  ],
  soar: [
    { module: { $in: ['SOAR', 'soar'] } },
  ],
};

async function generateReport(companyId, { from, to, type = 'siem', exportMode = false } = {}, deptFilter = null) {
  const isDateOnly = value => /^\d{4}-\d{2}-\d{2}$/.test(String(value || ''));
  const start = from ? new Date(isDateOnly(from) ? `${from}T00:00:00.000Z` : from) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const end   = to   ? new Date(isDateOnly(to) ? `${to}T23:59:59.999Z` : to) : new Date();
  const cid   = new mongoose.Types.ObjectId(companyId);
  if (type === 'ids') return generateIdsReport(companyId, cid, start, end, deptFilter, exportMode);
  if (type === 'waf') return generateWafReport(companyId, cid, start, end, exportMode);
  if (['firewall', 'incidents', 'threat-intelligence', 'forensics', 'ai-analysis', 'soar'].includes(type)) {
    return generateOperationalReport(companyId, cid, type, start, end, deptFilter);
  }
  let dateFilter = { companyId: cid, createdAt: { $gte: start, $lte: end } };
  const reportConditions = REPORT_FILTERS[type];
  if (reportConditions) {
    // Keep the selected time window in every aggregation. Building a giant
    // in-memory `_id: { $in: [...] }` list made 30/90-day reports stall before
    // the summary could be returned.
    dateFilter = { $and: [dateFilter, { $or: reportConditions }] };
  }
  if (deptFilter) {
    if (Array.isArray(deptFilter)) {
      dateFilter.departmentId = { $in: deptFilter.map(d => new mongoose.Types.ObjectId(d)) };
    } else {
      dateFilter.departmentId = new mongoose.Types.ObjectId(deptFilter);
    }
  }

  const [
    totalAlerts, bySeverity, byStatus, byDay, topAgents, topRules,
    soarActions, systemCount, resolvedAvg, top10Alerts, logsSnapshot,
  ] = await Promise.all([
    Alert.countDocuments(dateFilter),

    Alert.aggregate([
      { $match: dateFilter },
      { $group: { _id: { $toLower: '$severity' }, count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]),

    Alert.aggregate([
      { $match: dateFilter },
      { $group: { _id: '$status', count: { $sum: 1 } } },
    ]),

    Alert.aggregate([
      { $match: dateFilter },
      { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]),

    Alert.aggregate([
      { $match: dateFilter },
      { $group: { _id: '$agentName', count: { $sum: 1 } } },
      { $sort: { count: -1 } }, { $limit: 5 },
    ]),

    Alert.aggregate([
      { $match: { ...dateFilter, ruleId: { $exists: true } } },
      { $group: { _id: '$ruleId', count: { $sum: 1 }, description: { $first: '$description' } } },
      { $sort: { count: -1 } }, { $limit: 5 },
    ]),

    SoarLog.countDocuments({ companyId: cid, createdAt: { $gte: start, $lte: end } }),
    System.countDocuments({ companyId: cid, status: 'active' }),

    Alert.aggregate([
      { $match: { ...dateFilter, status: 'resolved', resolvedAt: { $exists: true } } },
      { $project: { diffMinutes: { $divide: [{ $subtract: ['$resolvedAt', '$createdAt'] }, 60000] } } },
      { $group: { _id: null, avg: { $avg: '$diffMinutes' } } },
    ]),

    // Top 10 most severe/recent alerts
    Alert.find({ ...dateFilter, severity: { $in: ['critical', 'high'] } })
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('systemId', 'name hostname')
      .populate('departmentId', 'name')
      .lean(),

    // Logs snapshot (last 20, all severities)
    (() => {
      const query = Alert.find(dateFilter)
      .sort({ createdAt: -1 })
      .select('description severity eventCategory srcip agentName createdAt status')
      if (!exportMode) query.limit(20);
      return query.lean();
    })(),
  ]);

  // ── Security Score (logarithmic, same as /api/security-score) ─────────────
  const sevMap = { critical: 0, high: 0, medium: 0, low: 0 };
  bySeverity.forEach(r => { if (sevMap[normalizeSev(r._id)] !== undefined) sevMap[normalizeSev(r._id)] += r.count; });

  const totalSevAlerts = sevMap.critical + sevMap.high + sevMap.medium + sevMap.low;
  const scoreResult = totalSevAlerts === 0
    ? { score: 100, grade: 'A', risk: 'low', systemHealth: 'Healthy', deductions: { critical: 0, high: 0, medium: 0, low: 0 } }
    : calculateScore(sevMap);
  const securityScore = scoreResult.score;
  const scoreGrade    = scoreResult.grade;
  const scoreRisk     = scoreResult.risk;
  const systemHealth  = scoreResult.systemHealth;

  return {
    meta: {
      companyId, from: start.toISOString(), to: end.toISOString(), type,
      generatedAt: new Date().toISOString(),
    },
    summary: {
      totalAlerts, systemCount,
      soarActionsExecuted: soarActions,
      avgResolutionMinutes: resolvedAvg[0]?.avg ? Math.round(resolvedAvg[0].avg) : null,
    },
    securityScore: {
      score: Math.round(securityScore),
      grade: scoreGrade,
      risk:  scoreRisk,
      systemHealth,
      severity: sevMap,
      deductions: scoreResult.deductions,
    },
    bySeverity: bySeverity.map(r => ({ severity: normalizeSev(r._id), count: r.count })),
    byStatus:   byStatus.map(r   => ({ status: r._id,   count: r.count })),
    byDay:      byDay.map(r      => ({ date: r._id,      count: r.count })),
    topAgents:  topAgents.map(r  => ({ agent: r._id,     count: r.count })),
    topRules:   topRules.map(r   => ({ ruleId: r._id, description: r.description, count: r.count })),
    top10Alerts: top10Alerts.map(a => ({
      id:          a._id,
      description: a.description,
      severity:    normalizeSev(a.severity),
      source:      a.source || a.eventCategory || '—',
      srcip:       a.srcip || '—',
      system:      a.systemId?.name || a.agentName || '—',
      department:  a.departmentId?.name || '—',
      timestamp:   a.createdAt,
      status:      a.status,
    })),
    logsSnapshot: logsSnapshot.map(a => ({
      description: a.description,
      severity:    normalizeSev(a.severity),
      source:      a.eventCategory || '—',
      srcip:       a.srcip || '—',
      agent:       a.agentName || '—',
      timestamp:   a.createdAt,
      status:      a.status,
    })),
  };
}

// ── CSV export ────────────────────────────────────────────────────────────────
function reportToCsv(report) {
  const sevMap = {};
  const hideSourceIp = report.meta?.type === 'fim';
  report.bySeverity.forEach(r => { sevMap[r.severity] = r.count; });

  const lines = [
    `# ${(report.meta.type || 'siem').toUpperCase()} Security Report`,
    `# Period: ${report.meta.from.slice(0,10)} to ${report.meta.to.slice(0,10)}`,
    `# Generated: ${report.meta.generatedAt}`,
    `# Security Score: ${report.securityScore?.score ?? 'N/A'}/100 (${report.securityScore?.grade ?? ''}) - ${report.securityScore?.systemHealth ?? ''}`,
    ``,
    `## Summary`,
    `Total Alerts,${report.summary?.totalAlerts}`,
    `Critical,${sevMap.critical || 0}`,
    `High,${sevMap.high || 0}`,
    `Medium,${sevMap.medium || 0}`,
    `Low,${sevMap.low || 0}`,
    `Active Systems,${report.summary?.systemCount}`,
    ``,
    `## Status Summary`,
    ['Status','Count'].join(','),
    ...(report.byStatus || []).map(item => [item.status, item.count].join(',')),
    ``,
    `## Alerts Per Day`,
    ['Date','Total'].join(','),
    ...report.byDay.map(d => [d.date, d.count].join(',')),
    ``,
    `## Top 10 Alerts`,
    ['Timestamp','Description','Severity','Source','System', ...(!hideSourceIp ? ['Source IP'] : []), 'Status'].join(','),
    ...(report.top10Alerts || []).map(a =>
      [
        new Date(a.timestamp).toISOString(),
        `"${(a.description||'').replace(/"/g,'""')}"`,
        a.severity, a.source, a.system, ...(!hideSourceIp ? [a.srcip] : []), a.status,
      ].join(',')
    ),
    ``,
    `## Logs Snapshot`,
    ['Timestamp','Description','Severity','Category','Agent/System', ...(!hideSourceIp ? ['Source IP'] : []), 'Status'].join(','),
    ...(report.logsSnapshot || []).map(l =>
      [
        new Date(l.timestamp).toISOString(),
        `"${(l.description||'').replace(/"/g,'""')}"`,
        l.severity, l.source, l.agent || l.system, ...(!hideSourceIp ? [l.srcip] : []), l.status,
      ].join(',')
    ),
  ];

  return lines.join('\n');
}

// ── HTML / Print-as-PDF report ─────────────────────────────────────────────
function reportToPdf(report) {
  const s    = report.summary;
  const sc   = report.securityScore;
  const hideSourceIp = report.meta?.type === 'fim';

  // Severity colors
  const SEV_COLOR = {
    critical: '#dc2626', high: '#d97706', medium: '#2563eb', low: '#16a34a',
  };

  // Score gauge: SVG arc
  const pct   = (sc?.score ?? 100) / 100;
  const scoreColor = (sc?.score??100) >= 80 ? '#16a34a' : (sc?.score??100) >= 60 ? '#d97706' : '#dc2626';

  // Build severity doughnut (SVG approximation as horizontal bars)
  const sevRows = (report.bySeverity || [])
    .sort((a,b) => ['critical','high','medium','low'].indexOf(a.severity) - ['critical','high','medium','low'].indexOf(b.severity))
    .map(r => {
      const pct = s.totalAlerts > 0 ? Math.round((r.count / s.totalAlerts) * 100) : 0;
      return `
        <tr>
          <td style="padding:5px 8px;color:#374151;font-size:12px;text-transform:capitalize">${r.severity}</td>
          <td style="padding:5px 8px">
            <div style="background:#f1f5f9;border-radius:4px;height:14px;width:200px;overflow:hidden">
              <div style="background:${SEV_COLOR[r.severity]||'#6b7280'};height:100%;width:${pct}%;border-radius:4px"></div>
            </div>
          </td>
          <td style="padding:5px 8px;font-weight:600;color:${SEV_COLOR[r.severity]||'#6b7280'}">${r.count}</td>
          <td style="padding:5px 8px;color:#9ca3af;font-size:11px">${pct}%</td>
        </tr>`;
    }).join('');

  const statusRows = (report.byStatus || []).map(item => `
    <tr>
      <td style="padding:7px 10px;text-transform:capitalize">${String(item.status || 'unknown').replace(/_/g, ' ')}</td>
      <td style="padding:7px 10px;font-weight:700">${item.count || 0}</td>
    </tr>`).join('');

  const top10Rows = (report.top10Alerts || []).map((a, i) => `
    <tr style="background:${i%2===0?'#fff':'#f9fafb'}">
      <td style="padding:6px 10px;font-size:11px;color:#374151">${new Date(a.timestamp).toLocaleString()}</td>
      <td style="padding:6px 10px;font-size:11px;max-width:220px">${a.description}</td>
      <td style="padding:6px 10px"><span style="font-size:10px;padding:2px 7px;border-radius:4px;background:${SEV_COLOR[a.severity]||'#6b7280'}22;color:${SEV_COLOR[a.severity]||'#6b7280'};font-weight:600;text-transform:uppercase">${a.severity}</span></td>
      <td style="padding:6px 10px;font-size:11px;color:#6b7280">${a.source}</td>
      <td style="padding:6px 10px;font-size:11px;color:#2563eb">${a.system}</td>
      ${!hideSourceIp ? `<td style="padding:6px 10px;font-size:11px;font-family:monospace">${a.srcip}</td>` : ''}
      <td style="padding:6px 10px;font-size:11px;font-weight:600;text-transform:capitalize">${a.status || '—'}</td>
    </tr>`).join('');

  const logRows = (report.logsSnapshot || []).map((l, i) => `
    <tr style="background:${i%2===0?'#fff':'#f9fafb'}">
      <td style="padding:5px 10px;font-size:10px;color:#9ca3af;white-space:nowrap">${new Date(l.timestamp).toLocaleString()}</td>
      <td style="padding:5px 10px;font-size:11px;max-width:220px">${l.description}</td>
      <td style="padding:5px 10px"><span style="font-size:10px;padding:2px 6px;border-radius:4px;background:${SEV_COLOR[l.severity]||'#6b7280'}22;color:${SEV_COLOR[l.severity]||'#6b7280'};text-transform:uppercase">${l.severity}</span></td>
      <td style="padding:5px 10px;font-size:11px;color:#7c3aed">${l.source}</td>
      <td style="padding:5px 10px;font-size:11px;color:#374151">${l.agent}</td>
      ${!hideSourceIp ? `<td style="padding:5px 10px;font-size:10px;font-family:monospace;color:#2563eb">${l.srcip}</td>` : ''}
      <td style="padding:5px 10px;font-size:11px;font-weight:600;text-transform:capitalize">${l.status || '—'}</td>
    </tr>`).join('');

  // Day-by-day bar chart as SVG
  const dayData  = report.byDay || [];
  const maxCount = Math.max(...dayData.map(d => d.count), 1);
  const svgW = 600, svgH = 120, barW = Math.max(4, Math.floor((svgW - 40) / Math.max(dayData.length, 1)) - 2);
  const bars = dayData.map((d, i) => {
    const bh = Math.round((d.count / maxCount) * (svgH - 30));
    const x  = 20 + i * (barW + 2);
    const y  = svgH - 20 - bh;
    return `<rect x="${x}" y="${y}" width="${barW}" height="${bh}" fill="#2563eb" rx="2" opacity="0.85"/>`;
  }).join('');
  const xLabels = dayData.length > 0 ? [dayData[0], dayData[Math.floor(dayData.length/2)], dayData[dayData.length-1]]
    .filter(Boolean)
    .map((d, i) => {
      const idx = [0, Math.floor(dayData.length/2), dayData.length-1][i];
      const x = 20 + idx * (barW + 2);
      return `<text x="${x}" y="${svgH - 5}" font-size="9" fill="#9ca3af">${d.date?.slice(5)}</text>`;
    }).join('') : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${(report.meta.type || 'siem').toUpperCase()} Security Report — ${report.meta.from.slice(0,10)} to ${report.meta.to.slice(0,10)}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #1e293b; background: #f8fafc; }
  .page { max-width: 900px; margin: 0 auto; padding: 32px; background: #fff; }
  h1 { font-size: 24px; color: #0f172a; margin-bottom: 4px; }
  h2 { font-size: 15px; color: #1e40af; margin: 28px 0 12px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
  .meta { color: #64748b; font-size: 12px; margin-bottom: 28px; }
  .cards { display: flex; gap: 16px; flex-wrap: wrap; margin: 0 0 28px; }
  .card  { border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px 20px; min-width: 130px; flex: 1; }
  .card-num { font-size: 30px; font-weight: 700; }
  .card-label { font-size: 11px; color: #64748b; margin-top: 4px; }
  .score-card { text-align: center; background: linear-gradient(135deg,#eff6ff,#fff); border: 1px solid #bfdbfe; }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; font-size: 12px; }
  th { background: #f1f5f9; padding: 8px 10px; text-align: left; font-weight: 600; color: #374151; }
  td { border-bottom: 1px solid #f1f5f9; }
  @media print { body { background: #fff; } .page { padding: 16px; } }
</style>
</head>
<body>
<div class="page">
  <h1>🛡️ ${(report.meta.type || 'siem').toUpperCase()} Security Report</h1>
  <div class="meta">
    Period: <strong>${report.meta.from.slice(0,10)}</strong> → <strong>${report.meta.to.slice(0,10)}</strong>
    &nbsp;|&nbsp; Generated: ${new Date(report.meta.generatedAt).toLocaleString()}
  </div>

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card score-card">
      <div class="card-num" style="color:${scoreColor}">${sc?.score ?? '—'}</div>
      <div class="card-label">Security Score / 100</div>
      <div style="font-size:11px;margin-top:4px;color:${scoreColor};font-weight:600">${sc?.grade ?? ''} — ${sc?.systemHealth ?? ''}</div>
    </div>
    <div class="card">
      <div class="card-num" style="color:#2563eb">${s.totalAlerts}</div>
      <div class="card-label">Total Alerts</div>
    </div>
    <div class="card">
      <div class="card-num" style="color:#dc2626">${sc?.severity?.critical ?? 0}</div>
      <div class="card-label">Critical Risks</div>
    </div>
    <div class="card">
      <div class="card-num" style="color:#16a34a">${s.systemCount}</div>
      <div class="card-label">Active Systems</div>
    </div>
    <div class="card">
      <div class="card-num" style="color:#7c3aed">${s.soarActionsExecuted}</div>
      <div class="card-label">SOAR Actions</div>
    </div>
    <div class="card">
      <div class="card-num" style="color:#d97706">${s.avgResolutionMinutes != null ? s.avgResolutionMinutes + 'm' : 'N/A'}</div>
      <div class="card-label">Avg Resolution</div>
    </div>
  </div>

  <!-- Security Score Details -->
  <h2>🎯 Security Score Breakdown</h2>
  <div style="padding:14px;background:#eff6ff;border-radius:8px;border:1px solid #bfdbfe;margin-bottom:14px">
    <div style="display:flex;gap:24px;flex-wrap:wrap;align-items:center">
      <div style="text-align:center">
        <div style="font-size:48px;font-weight:800;color:${scoreColor}">${sc?.score ?? '—'}</div>
        <div style="font-size:12px;color:#64748b">Score / 100</div>
      </div>
      <div style="flex:1;min-width:200px">
        <div style="font-size:13px;color:#374151;margin-bottom:8px">Logarithmic Scoring: min(cap, weight × log₂(1+count))</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap">
          <span style="font-size:11px;padding:3px 10px;background:#fee2e2;color:#dc2626;border-radius:4px">Critical: −${sc?.deductions?.critical ?? 0}</span>
          <span style="font-size:11px;padding:3px 10px;background:#fef3c7;color:#d97706;border-radius:4px">High: −${sc?.deductions?.high ?? 0}</span>
          <span style="font-size:11px;padding:3px 10px;background:#dbeafe;color:#2563eb;border-radius:4px">Medium: −${sc?.deductions?.medium ?? 0}</span>
          <span style="font-size:11px;padding:3px 10px;background:#d1fae5;color:#16a34a;border-radius:4px">Low: −${sc?.deductions?.low ?? 0}</span>
        </div>
      </div>
    </div>
  </div>

  <!-- Alerts by Severity -->
  <h2>📊 Alerts by Severity</h2>
  <table><tbody>${sevRows || '<tr><td colspan="4" style="padding:12px;color:#9ca3af">No alerts in this period</td></tr>'}</tbody></table>

  <h2>📌 Status Summary</h2>
  <table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>${statusRows || '<tr><td colspan="2" style="padding:12px;color:#9ca3af">No status data in this period</td></tr>'}</tbody></table>

  <!-- Alerts over time chart -->
  <h2>📈 Alerts Per Day</h2>
  ${dayData.length > 0 ? `
    <svg width="${svgW}" height="${svgH}" xmlns="http://www.w3.org/2000/svg" style="display:block">
      <rect width="${svgW}" height="${svgH}" fill="#f8fafc" rx="6"/>
      ${bars}
      ${xLabels}
    </svg>` : '<p style="color:#9ca3af;font-size:12px">No data for this period.</p>'}

  <!-- Top 10 Alerts -->
  <h2>🚨 Top 10 Critical/High Alerts</h2>
  ${top10Rows ? `
    <table>
      <thead><tr>
        <th>Timestamp</th><th>Description</th><th>Severity</th>
        <th>Source</th><th>System</th>${!hideSourceIp ? '<th>Source IP</th>' : ''}<th>Status</th>
      </tr></thead>
      <tbody>${top10Rows}</tbody>
    </table>` : '<p style="color:#9ca3af;font-size:12px">No critical/high alerts in this period.</p>'}

  <!-- Logs Snapshot -->
  <h2>📋 Detailed Records</h2>
  ${logRows ? `
    <table>
      <thead><tr>
        <th>Timestamp</th><th>Description</th><th>Severity</th>
        <th>Category</th><th>Agent/System</th>${!hideSourceIp ? '<th>Source IP</th>' : ''}<th>Status</th>
      </tr></thead>
      <tbody>${logRows}</tbody>
    </table>` : '<p style="color:#9ca3af;font-size:12px">No logs in this period.</p>'}

  <!-- Top Agents -->
  ${report.topAgents?.length > 0 ? `
    <h2>🤖 Top Alerting Agents</h2>
    <table>
      <thead><tr><th>Agent</th><th>Alerts</th></tr></thead>
      <tbody>${report.topAgents.map(r => `<tr><td style="padding:6px 10px">${r.agent||'—'}</td><td style="padding:6px 10px;font-weight:600">${r.count}</td></tr>`).join('')}</tbody>
    </table>` : ''}

  <div style="margin-top:32px;padding-top:16px;border-top:1px solid #e2e8f0;font-size:10px;color:#9ca3af;text-align:right">
    SOC Report · Generated ${new Date(report.meta.generatedAt).toLocaleString()} · Powered by SOC4 Platform
  </div>
</div>
<script>
  // Auto-print when opened in browser for PDF
  if (window.location.search.includes('print=1')) setTimeout(() => window.print(), 500);
</script>
</body></html>`;
}

module.exports = { generateReport, reportToCsv, reportToPdf };
