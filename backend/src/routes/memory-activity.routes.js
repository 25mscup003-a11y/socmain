const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const { resolveCapabilityDepartmentScope } = require('../utils/capabilityOverview');

const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));
const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const CAPABILITY_EVIDENCE = {
  $and: [
    { $or: [{ capabilityId: 5 }, { capabilityIds: 5 }] },
    { $or: [
      { category: /^memory$/i }, { eventCategory: /^memory$/i }, { source: /memory/i },
      { memoryMetricType: { $in: ['host', 'process'] } },
      { ruleId: /^(?:MEM_|MEM-|MEMORY_OVERFLOW_|PROC_(?:DLL_INJECTION|REMOTE_THREAD_INJECTION|KERNEL_PROCESS_ACCESS|HOLLOWING|SUSPICIOUS_DLL_LOAD))/i },
    ] },
  ],
};
const METRIC_EVIDENCE = { $or: [{ eventType: 'memory.metric' }, { memoryMetricType: { $in: ['host', 'process'] } }] };

function companyScope(req, requestedDepartmentId = req.query?.departmentId) {
  const rawCompany = req.user.companyId?._id || req.user.companyId;
  if (!mongoose.isValidObjectId(rawCompany)) throw Object.assign(new Error('Invalid tenant scope'), { status: 400 });
  const departmentId = resolveCapabilityDepartmentScope(req.user, requestedDepartmentId);
  return {
    companyId: new mongoose.Types.ObjectId(String(rawCompany)),
    ...(departmentId && mongoose.isValidObjectId(departmentId)
      ? { departmentId: new mongoose.Types.ObjectId(String(departmentId)) }
      : {}),
    ...(req.query?.systemId && mongoose.isValidObjectId(req.query.systemId)
      ? { systemId: new mongoose.Types.ObjectId(String(req.query.systemId)) }
      : {}),
  };
}

function windowMatch(req, source = req.query) {
  const hours = integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const from = source.from ? new Date(source.from) : new Date(Date.now() - hours * 3600000);
  const to = source.to ? new Date(source.to) : null;
  const createdAt = { $gte: Number.isNaN(from.getTime()) ? new Date(Date.now() - 86400000) : from };
  if (to && !Number.isNaN(to.getTime())) createdAt.$lte = to;
  return createdAt;
}

function baseQuery(req, source = req.query) {
  return { ...companyScope(req, source.departmentId), isSynthetic: { $ne: true }, createdAt: windowMatch(req, source), $and: [CAPABILITY_EVIDENCE] };
}

function eventQuery(req, source = req.query) {
  const query = { ...baseQuery(req, source), $and: [CAPABILITY_EVIDENCE, { $nor: [METRIC_EVIDENCE] }] };
  if (source.severity) query.severity = String(source.severity).toLowerCase();
  if (source.hostname) query.hostname = new RegExp(escapeRegex(source.hostname).slice(0, 253), 'i');
  if (source.user) query.username = new RegExp(escapeRegex(source.user).slice(0, 120), 'i');
  if (source.process) query.processName = new RegExp(escapeRegex(source.process).slice(0, 255), 'i');
  if (source.search) {
    const rx = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    query.$and.push({ $or: [{ description: rx }, { ruleId: rx }, { processName: rx }, { hostname: rx }, { username: rx }] });
  }
  return query;
}

function metricQuery(req, source = req.query) {
  return { ...baseQuery(req, source), $and: [CAPABILITY_EVIDENCE, METRIC_EVIDENCE] };
}

const eventProjection = [
  'eventId tenantId companyId departmentId systemId agentId agentName endpointId hostname os osType platform agentVersion capabilityId capabilityIds memoryAddress injectionType',
  'ruleId detectionRuleId description source category subCategory eventCategory eventType severity riskScore confidenceScore status recommendedAction actionTaken',
  'username userSid processName pid parentPid parentProcessName processCmdline processExe processCreateTime processEndTime processStatus',
  'sourceProcessName sourcePid targetProcessName targetPid grantedAccess callTrace',
  'processMemoryPercent processMemoryMb processRssBytes virtualMemoryBytes privateWorkingSetBytes sharedMemoryBytes peakMemoryBytes memoryGrowthBytes memoryGrowthPercent memoryAllocationRate threadCount handleCount',
  'memoryMetricType memoryTotalBytes memoryUsedBytes memoryAvailableBytes commitChargeBytes memoryPressure swapTotalBytes swapUsedBytes swapPercent pageFaults majorPageFaults pagingRate oomEvents',
  'containerId podName namespace containerMemoryBytes containerMemoryLimitBytes containerOomEvents executableRegionCount rwxRegionCount memoryProtection',
  'sha256 processExecutableSha256 signatureStatus processSignatureStatus publisher processPublisher entropy yaraRules iocMatched threatIntelMatch',
  'mitreId mitreTechnique mitreTactic technique processTree childProcesses networkConnections filesCreated filesModified filesDeleted notes assignedTo rawEvent createdAt updatedAt',
].join(' ');

router.use(authenticate, requireAnalyst);

router.get('/dashboard', async (req, res) => {
  try {
    const eventsMatch = eventQuery(req);
    const metricsMatch = metricQuery(req);
    const limit = integer(req.query.limit, 250, 1, 1000);
    const [facets = {}, metricRows, systems] = await Promise.all([
      Alert.aggregate([
        { $match: eventsMatch },
        { $set: { _memoryText: { $toLower: { $concat: [
          { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$eventType', ''] }, ' ',
          { $ifNull: ['$subCategory', ''] }, ' ', { $ifNull: ['$description', ''] },
        ] } } } },
        { $facet: {
          summary: [{ $group: { _id: null, total: { $sum: 1 },
            critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
            high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
            medium: { $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] } },
            low: { $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] } },
            injection: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'inject|remote.thread|hollow|t1055' } }, 1, 0] } },
            credentialTheft: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'lsass|credential.dump|mimikatz|minidump' } }, 1, 0] } },
            fileless: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'fileless|reflective|in.memory.payload|t1620' } }, 1, 0] } },
            rwx: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'rwx|executable.memory|virtualprotect' } }, 1, 0] } },
            dumps: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'memory.dump|minidump|full.dump' } }, 1, 0] } },
            rootkits: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'rootkit|ssdt|dkom|kernel.*tamper' } }, 1, 0] } },
            highEntropy: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'entropy|packed.memory|encrypted.payload' } }, 1, 0] } },
            dllSideload: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'unsigned.dll|sideload|dll.search.order' } }, 1, 0] } },
            protectedProcess: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'protected.process|lsass|winlogon|csrss|kernel.process.access' } }, 1, 0] } },
            exploits: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'heap.corruption|stack.overflow|rop.chain|dep.bypass|buffer.overflow' } }, 1, 0] } },
            browserMiner: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'crypto.miner|cryptominer|browser.miner' } }, 1, 0] } },
            containerSpikes: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'container.*(?:spike|pressure|oom)|pod.*(?:spike|oom)|docker.*memory' } }, 1, 0] } },
            remoteThread: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'remote.thread' } }, 1, 0] } },
            hollowing: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'hollow' } }, 1, 0] } },
            lsassAccess: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'lsass' } }, 1, 0] } },
            dllAnomaly: { $sum: { $cond: [{ $regexMatch: { input: '$_memoryText', regex: 'dll.*(?:inject|sideload|anomaly)|unsigned.dll' } }, 1, 0] } },
            recentEvents: { $sum: { $cond: [{ $gte: ['$createdAt', new Date(Date.now() - 900000)] }, 1, 0] } },
            maximumRisk: { $max: '$riskScore' }, averageRisk: { $avg: '$riskScore' },
          } }],
          timeline: [{ $group: { _id: { hour: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, severity: '$severity' }, count: { $sum: 1 } } }, { $sort: { '_id.hour': 1 } }],
          categories: [{ $group: { _id: { $ifNull: ['$subCategory', { $ifNull: ['$eventType', 'Unclassified'] }] }, count: { $sum: 1 }, maxRisk: { $max: '$riskScore' } } }, { $sort: { count: -1 } }, { $limit: 30 }],
          topProcesses: [{ $group: { _id: '$processName', alerts: { $sum: 1 }, maxRisk: { $max: '$riskScore' }, lastSeen: { $max: '$createdAt' } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { alerts: -1, maxRisk: -1 } }, { $limit: 25 }],
          events: [{ $sort: { createdAt: -1 } }, { $limit: limit }, { $project: Object.fromEntries(eventProjection.split(' ').map(field => [field, 1])) }],
        } },
      ]).option({ allowDiskUse: true, maxTimeMS: 12000 }).then(rows => rows[0] || {}),
      Alert.find(metricsMatch).select(eventProjection).sort({ createdAt: -1 }).limit(2500).maxTimeMS(8000).lean(),
      System.find(companyScope(req)).select('name hostname ip ipAddress os osType platform status isOnline agentOk lastSeen agentVersion memoryMonitorEnabled').sort({ lastSeen: -1 }).limit(2000).lean(),
    ]);
    const systemsById = new Map(systems.map(system => [String(system._id), system]));
    const withSystem = row => ({ ...row, systemId: systemsById.get(String(row.systemId)) || row.systemId });
    const seen = new Set();
    const metrics = metricRows.filter(row => {
      const key = `${row.systemId || row.hostname || row.agentId}:${row.memoryMetricType}:${row.memoryMetricType === 'process' ? `${row.pid}:${row.processName}` : 'host'}`;
      if (seen.has(key)) return false;
      seen.add(key); return true;
    });
    const hostMetrics = metrics.filter(row => row.memoryMetricType === 'host');
    const processMetrics = metrics.filter(row => row.memoryMetricType === 'process');
    const totalRamBytes = hostMetrics.reduce((sum, row) => sum + Number(row.memoryTotalBytes || 0), 0);
    const usedRamBytes = hostMetrics.reduce((sum, row) => sum + Number(row.memoryUsedBytes || 0), 0);
    const pressures = hostMetrics.map(row => Number(row.memoryPressure ?? row.processMemoryPercent)).filter(Number.isFinite);
    const summary = facets.summary?.[0] || {};
    res.json({
      capabilityId: 5,
      summary: { ...summary, _id: undefined, total: summary.total || 0, totalRamBytes, usedRamBytes,
        memoryUsagePercent: totalRamBytes ? Number(((usedRamBytes / totalRamBytes) * 100).toFixed(2)) : null,
        averageMemoryPressure: pressures.length ? Number((pressures.reduce((a, b) => a + b, 0) / pressures.length).toFixed(2)) : null,
        activeProcesses: processMetrics.length, reportingHosts: hostMetrics.length,
      },
      timeline: facets.timeline || [], categories: facets.categories || [], topProcesses: facets.topProcesses || [],
      events: (facets.events || []).map(withSystem), metrics: metrics.map(withSystem), hostMetrics: hostMetrics.map(withSystem), processMetrics: processMetrics.map(withSystem), systems,
      metricHistory: metricRows.filter(row => row.memoryMetricType === 'host'),
      generatedAt: new Date(), realtimeEvents: ['memory:metric', 'memory:alert', 'memory:alert-updated'],
    });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.status ? error.message : 'Memory activity dashboard could not be loaded' });
  }
});

router.get('/events', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 1000000); const limit = integer(req.query.limit, 100, 1, 1000); const query = eventQuery(req);
    const [events, total] = await Promise.all([
      Alert.find(query).select(eventProjection).populate('systemId', 'name hostname ip ipAddress os osType platform status lastSeen agentVersion').sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Alert.countDocuments(query),
    ]);
    res.json({ events, alerts: events, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Memory events could not be loaded' }); }
});

router.get('/metrics', async (req, res) => {
  try {
    const kind = ['host', 'process'].includes(String(req.query.kind)) ? String(req.query.kind) : null;
    const query = metricQuery(req); if (kind) query.memoryMetricType = kind;
    const metrics = await Alert.find(query).select(eventProjection).sort({ createdAt: -1 }).limit(integer(req.query.limit, 1000, 1, 5000)).lean();
    res.json({ metrics, total: metrics.length });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Memory metrics could not be loaded' }); }
});

router.get('/timeline', async (req, res) => {
  try {
    const timeline = await Alert.aggregate([{ $match: eventQuery(req) }, { $group: { _id: { hour: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, severity: '$severity' }, count: { $sum: 1 } } }, { $sort: { '_id.hour': 1 } }, { $limit: 2000 }]);
    res.json({ timeline });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Memory timeline could not be loaded' }); }
});

router.get('/events/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), $and: [CAPABILITY_EVIDENCE, { $nor: [METRIC_EVIDENCE] }] }).select(eventProjection).populate('systemId', 'name hostname ip ipAddress os osType platform status lastSeen agentVersion').lean();
    if (!event) return res.status(404).json({ message: 'Memory event not found' });
    res.json({ event });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Memory event could not be loaded' }); }
});

router.post('/events/:id/notes', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
    const text = String(req.body.text || '').trim();
    if (!text) return res.status(400).json({ message: 'Note text is required' });
    if (text.length > 4000) return res.status(400).json({ message: 'Note text exceeds 4000 characters' });
    const event = await Alert.findOneAndUpdate(
      { _id: req.params.id, ...companyScope(req), $and: [CAPABILITY_EVIDENCE, { $nor: [METRIC_EVIDENCE] }] },
      { $push: { notes: { user: req.user.id || req.user._id, text, at: new Date() }, auditHistory: { action: 'memory.note_added', actorId: req.user.id || req.user._id, at: new Date(), metadata: {} } } },
      { new: true, runValidators: true },
    ).select(eventProjection).lean();
    if (!event) return res.status(404).json({ message: 'Memory event not found' });
    req.app.get('io')?.to(`company:${event.companyId}`).emit('memory:alert-updated', event);
    res.json({ event });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Memory note could not be saved' }); }
});

module.exports = router;
