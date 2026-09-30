const router = require('express').Router();
const crypto = require('crypto');
const mongoose = require('mongoose');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const Company = require('../models/Company.model');
const System = require('../models/System.model');
const ForensicHunt = require('../models/ForensicHunt.model');
const ForensicEvidence = require('../models/ForensicEvidence.model');
const AiAnalysis = require('../models/AiAnalysis.model');
const { isConfigured, veloGetFlow, veloListClients, veloRunHunt } = require('../services/velociraptor.service');
const { enqueueForensicEvidenceAnalysis } = require('../services/azureAi.service');
const { allowedCompanyIds } = require('../services/socAccess.service');

router.use(authenticate, requireAnalyst);

const ALLOWED_ARTIFACT = /^[A-Za-z][A-Za-z0-9_.-]{2,239}$/;
const LAUNCH_ROLES = new Set(['superadmin', 'company_admin', 'department_admin', 'soc_manager', 'l2_analyst', 'l3_analyst', 'l4_analyst']);

function ip(req) {
  return String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
}

async function companyIdFor(req) {
  const requested = req.query.companyId || req.body?.companyId;
  if (req.user.role === 'superadmin') return mongoose.isValidObjectId(requested) ? requested : null;
  const allowed = await allowedCompanyIds(req.user);
  if (requested) {
    return mongoose.isValidObjectId(requested) && allowed.includes(String(requested)) ? String(requested) : null;
  }
  if (req.user.companyId && allowed.includes(String(req.user.companyId))) return String(req.user.companyId);
  return allowed.length === 1 ? allowed[0] : null;
}

function scope(req, companyId) {
  const filter = { companyId };
  if (req.user.role === 'department_admin') filter.departmentId = req.user.departmentId;
  return filter;
}

function publicClient(client) {
  return {
    clientId: client?.client_id || client?.clientId || client?.id || '',
    hostname: client?.hostname || client?.os_info?.hostname || '',
    os: client?.os || client?.os_info?.system || '',
    lastSeenAt: client?.last_seen_at || client?.lastSeenAt || null,
  };
}

function matchingLiveClient(system, clients) {
  const stored = clients.find(item => (item.client_id || item.id) === system?.velociraptorClientId);
  if (stored) return stored;
  const names = [system?.hostname, system?.name].filter(Boolean).map(value => String(value).toLowerCase());
  return clients.find(item => names.includes(String(item.hostname || item.os_info?.hostname || '').toLowerCase())) || null;
}

async function syncHuntIfFinished(hunt, { io } = {}) {
  if (!hunt || hunt.status === 'completed') return hunt;
  const clientId = hunt.clientId;
  const flowId = hunt.providerResult?.launch?.flow_id || hunt.providerResult?.launch?.session_id;
  if (!clientId || !flowId) return hunt;

  try {
    const checked = await veloGetFlow({ clientId, flowId, includeResults: false });
    const flowState = checked?.flow;
    const state = String(flowState?.state || '').toUpperCase();
    if (state === 'FINISHED') {
      const full = await veloGetFlow({ clientId, flowId, includeResults: true });
      const result = { launch: hunt.providerResult?.launch || { flow_id: flowId, session_id: flowId }, ...full };
      const serialized = JSON.stringify(result || {});
      const sha256 = crypto.createHash('sha256').update(serialized).digest('hex');

      let evidence = await ForensicEvidence.findOne({ huntId: hunt._id });
      if (!evidence) {
        const target = hunt.systemId ? await System.findById(hunt.systemId).lean() : null;
        evidence = await ForensicEvidence.create({
          companyId: hunt.companyId,
          departmentId: hunt.departmentId || target?.departmentId || null,
          systemId: hunt.systemId || null,
          huntId: hunt._id,
          evidenceId: `EVD-${crypto.randomUUID()}`,
          name: `${hunt.name} result`,
          type: 'Velociraptor Collection',
          sourceHost: target?.hostname || target?.name || (clientId || 'Fleet'),
          artifactName: Array.isArray(hunt.artifacts) ? hunt.artifacts.join(', ') : String(hunt.artifacts || ''),
          sizeBytes: Buffer.byteLength(serialized),
          sha256,
          collectedBy: hunt.requestedBy,
          custody: [{ action: 'collected', actorId: hunt.requestedBy, actorRole: hunt.requestedByRole, sourceIp: hunt.sourceIp, note: `Collected by hunt ${hunt._id}` }],
        });
        const actor = { id: hunt.requestedBy, role: hunt.requestedByRole };
        enqueueForensicEvidenceAnalysis(evidence, { io, user: actor, sourceIp: hunt.sourceIp })
          .catch(error => console.error('[forensics/ai]', error.message));
      }

      const updated = await ForensicHunt.findByIdAndUpdate(hunt._id, {
        $set: {
          status: 'completed',
          providerResult: result,
          error: null,
          completedAt: new Date(),
        },
      }, { new: true }).lean();

      io?.to(`company:${hunt.companyId}`).emit('forensics:updated', { huntId: hunt._id, evidenceId: evidence._id });
      io?.to('superadmin').emit('forensics:updated', { companyId: hunt.companyId, huntId: hunt._id, evidenceId: evidence._id });
      return updated || hunt;
    }
  } catch (err) {
    // Retain existing hunt record on transient lookup failure
  }
  return hunt;
}

async function executeHuntJob({ huntId, companyId, target, clientId, name, artifacts, actor, sourceIp, io }) {
  let hunt = await ForensicHunt.findByIdAndUpdate(huntId, {
    $set: { status: 'running', startedAt: new Date() },
  }, { new: true });
  if (!hunt) return;
  try {
    const launchResult = await veloRunHunt({ name, artifacts, clientId });
    const flowId = launchResult?.flow_id || launchResult?.session_id;
    let result = launchResult;
    if (clientId && flowId) {
      hunt = await ForensicHunt.findByIdAndUpdate(huntId, {
        $set: { providerResult: { launch: launchResult } },
      }, { new: true });

      let flowState = null;
      for (let attempt = 0; attempt < 90; attempt += 1) {
        const checked = await veloGetFlow({ clientId, flowId, includeResults: false });
        flowState = checked.flow;
        const state = String(flowState?.state || '').toUpperCase();
        if (['FINISHED', 'ERROR'].includes(state)) break;
        await new Promise(resolve => setTimeout(resolve, 2000));
      }

      if (!flowState) throw new Error(`Velociraptor flow ${flowId} was not found`);

      const state = String(flowState.state || '').toUpperCase();
      if (state === 'RUNNING') {
        hunt.status = 'running';
        hunt.error = `Velociraptor flow ${flowId} is currently running in background`;
        await hunt.save();
        io?.to(`company:${companyId}`).emit('forensics:updated', { huntId: hunt._id, status: 'running' });
        return;
      }

      if (state !== 'FINISHED') {
        throw new Error(`Velociraptor flow ${flowId} did not complete (state: ${flowState.state || 'unknown'})`);
      }
      const failedQuery = (flowState.query_stats || []).find(item => String(item.status || '').toUpperCase() === 'ERROR');
      if (failedQuery) throw new Error(failedQuery.error_message || `Velociraptor flow ${flowId} failed`);
      result = { launch: launchResult, ...(await veloGetFlow({ clientId, flowId, includeResults: true })) };
    }
    const serialized = JSON.stringify(result || {});
    const sha256 = crypto.createHash('sha256').update(serialized).digest('hex');
    const evidence = await ForensicEvidence.create({
      companyId, departmentId: target?.departmentId || null, systemId: target?._id || null,
      huntId: hunt._id, evidenceId: `EVD-${crypto.randomUUID()}`, name: `${name} result`,
      type: 'Velociraptor Collection', sourceHost: target?.hostname || target?.name || (clientId || 'Fleet'),
      artifactName: artifacts.join(', '), sizeBytes: Buffer.byteLength(serialized), sha256,
      collectedBy: actor.id,
      custody: [{ action: 'collected', actorId: actor.id, actorRole: actor.role, sourceIp, note: `Collected by hunt ${hunt._id}` }],
    });
    hunt.status = 'completed';
    hunt.providerResult = result;
    hunt.error = null;
    hunt.completedAt = new Date();
    await hunt.save();
    await enqueueForensicEvidenceAnalysis(evidence, { io, user: actor, sourceIp })
      .catch(error => console.error('[forensics/ai]', error.message));
    io?.to(`company:${companyId}`).emit('forensics:updated', { huntId: hunt._id, evidenceId: evidence._id });
    io?.to('superadmin').emit('forensics:updated', { companyId, huntId: hunt._id, evidenceId: evidence._id });
  } catch (error) {
    hunt.status = 'failed';
    hunt.error = String(error.message || error).slice(0, 4000);
    hunt.completedAt = new Date();
    await hunt.save();
    io?.to(`company:${companyId}`).emit('forensics:updated', { huntId: hunt._id, status: 'failed' });
    io?.to('superadmin').emit('forensics:updated', { companyId, huntId: hunt._id, status: 'failed' });
  }
}

router.get('/dashboard', async (req, res) => {
  try {
    const companyId = await companyIdFor(req);
    if (!companyId) return res.status(400).json({ message: 'Company scope is required' });
    const base = scope(req, companyId);
    const aggregateBase = { companyId: new mongoose.Types.ObjectId(companyId) };
    if (base.departmentId) aggregateBase.departmentId = new mongoose.Types.ObjectId(base.departmentId);
    const aiBase = {
      companyId: new mongoose.Types.ObjectId(companyId),
    };
    if (base.departmentId) {
      aiBase.resourceType = 'ForensicEvidence';
      aiBase.taskType = 'forensic_evidence_analysis';
      aiBase.resourceId = { $in: await ForensicEvidence.distinct('_id', base) };
    }
    const [company, systems, hunts, evidence, huntCounts, evidenceBytes, aiAnalyses, aiCounts] = await Promise.all([
      Company.findById(companyId).select('name tenantId').lean(),
      System.find(base).select('name hostname osType status lastSeen agentVersion velociraptorClientId departmentId').sort({ lastSeen: -1 }).lean(),
      ForensicHunt.find(base).populate('systemId', 'name hostname').populate('requestedBy', 'name email').sort({ createdAt: -1 }).limit(50).lean(),
      ForensicEvidence.find(base).populate('systemId', 'name hostname').populate('collectedBy', 'name email').sort({ collectedAt: -1 }).limit(100).lean(),
      ForensicHunt.aggregate([{ $match: aggregateBase }, { $group: { _id: '$status', count: { $sum: 1 } } }]),
      ForensicEvidence.aggregate([{ $match: aggregateBase }, { $group: { _id: null, bytes: { $sum: '$sizeBytes' }, count: { $sum: 1 }, verified: { $sum: { $cond: [{ $eq: ['$integrityStatus', 'verified'] }, 1, 0] } } } }]),
      AiAnalysis.find(aiBase)
        .select('requestedBy requestedByRole taskType resourceType resourceId status model promptVersion inputSummary output confidence reasoning error sourceIp startedAt completedAt createdAt updatedAt')
        .populate('requestedBy', 'name email role').sort({ createdAt: -1 }).limit(100).lean(),
      AiAnalysis.aggregate([{ $match: aiBase }, { $group: { _id: '$status', count: { $sum: 1 } } }]),
    ]);
    if (!company) return res.status(404).json({ message: 'Company not found' });
    const status = Object.fromEntries(huntCounts.map(item => [item._id, item.count]));
    const aiStatus = Object.fromEntries(aiCounts.map(item => [item._id, item.count]));
    const evidenceById = new Map(evidence.map(item => [String(item._id), item]));
    const publicAiAnalyses = aiAnalyses.map(item => {
      const linkedEvidence = evidenceById.get(String(item.resourceId));
      return {
        ...item,
        evidence: linkedEvidence ? {
          _id: linkedEvidence._id,
          evidenceId: linkedEvidence.evidenceId,
          name: linkedEvidence.name,
          sourceHost: linkedEvidence.sourceHost,
          artifactName: linkedEvidence.artifactName,
        } : null,
      };
    });
    let connected = false;
    let serverError = '';
    let clients = [];
    if (isConfigured()) {
      try {
        clients = await veloListClients();
        connected = true;
      } catch (error) { serverError = error.message; }
    }
    res.json({
      company,
      server: {
        configured: isConfigured(), connected, error: serverError,
        clientCount: clients.length, checkedAt: new Date(),
      },
      clients: clients.map(client => ({
        clientId: client.client_id || client.clientId || client.id || '',
        hostname: client.hostname || client.os_info?.hostname || '',
        os: client.os || client.os_info?.system || '',
        lastSeenAt: client.last_seen_at || client.lastSeenAt || null,
      })),
      systems,
      hunts,
      evidence,
      aiAnalyses: publicAiAnalyses,
      kpis: {
        clients: systems.filter(item => item.velociraptorClientId).length,
        online: systems.filter(item => item.velociraptorClientId && ['online', 'active'].includes(String(item.status).toLowerCase())).length,
        activeHunts: (status.queued || 0) + (status.running || 0),
        failedHunts: status.failed || 0,
        evidence: evidenceBytes[0]?.count || 0,
        evidenceBytes: evidenceBytes[0]?.bytes || 0,
        integrityVerified: evidenceBytes[0]?.verified || 0,
        aiAnalyses: Object.values(aiStatus).reduce((sum, count) => sum + count, 0),
        aiCompleted: aiStatus.completed || 0,
        aiProcessing: (aiStatus.queued || 0) + (aiStatus.processing || 0),
        aiFailed: aiStatus.failed || 0,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Lightweight incident-tab endpoint. The full dashboard performs company-wide
// aggregates and can take seconds on large tenants; incident collection only
// needs one endpoint, its live client and recent jobs.
router.get('/endpoint', async (req, res) => {
  try {
    const companyId = await companyIdFor(req);
    if (!companyId) return res.status(400).json({ message: 'Company scope is required' });
    if (!mongoose.isValidObjectId(req.query.systemId)) return res.status(400).json({ message: 'Valid systemId is required' });
    const system = await System.findOne({ _id: req.query.systemId, ...scope(req, companyId) })
      .select('name hostname osType status lastSeen agentVersion velociraptorClientId departmentId')
      .lean().maxTimeMS(5000);
    if (!system) return res.status(404).json({ message: 'Endpoint not found in authorized company scope' });

    let clients = [];
    let serverError = '';
    if (isConfigured()) {
      try { clients = await veloListClients(); } catch (error) { serverError = error.message; }
    }
    const liveClient = matchingLiveClient(system, clients);
    const resolvedClientId = liveClient?.client_id || liveClient?.id || '';
    if (resolvedClientId && resolvedClientId !== system.velociraptorClientId) {
      await System.updateOne({ _id: system._id }, { $set: { velociraptorClientId: resolvedClientId } }).maxTimeMS(3000).catch(() => {});
      system.velociraptorClientId = resolvedClientId;
    }
    const hunts = await ForensicHunt.find({ companyId, systemId: system._id })
      .select([
        'name', 'artifacts', 'status', 'error', 'clientId', 'systemId', 'incidentId',
        'createdAt', 'startedAt', 'completedAt',
        'providerResult.launch.flow_id', 'providerResult.launch.session_id',
        'providerResult.flow.session_id', 'providerResult.flow.state',
        'providerResult.flow.total_collected_rows', 'providerResult.flow.artifacts_with_results',
      ].join(' '))
      .sort({ createdAt: -1 }).limit(20).lean().maxTimeMS(5000);
    res.json({
      server: {
        configured: isConfigured(), connected: Boolean(isConfigured() && !serverError),
        error: serverError, clientCount: clients.length, checkedAt: new Date(),
      },
      system,
      client: liveClient ? publicClient(liveClient) : null,
      hunts,
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

// Result rows can be large, so they are loaded only when an analyst opens a
// particular job instead of being sent on every endpoint refresh.
router.get('/hunts/:id/output', async (req, res) => {
  try {
    const companyId = await companyIdFor(req);
    if (!companyId || !mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Valid collection job scope is required' });
    }
    let hunt = await ForensicHunt.findOne({ _id: req.params.id, ...scope(req, companyId) })
      .select('name artifacts status error clientId systemId createdAt startedAt completedAt providerResult requestedBy requestedByRole sourceIp companyId departmentId')
      .lean().maxTimeMS(10000);
    if (!hunt) return res.status(404).json({ message: 'Velociraptor collection job not found' });
    if (hunt.status !== 'completed') {
      hunt = await syncHuntIfFinished(hunt, { io: req.app.get('io') });
    }
    res.json({ hunt });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/hunts/:id/sync', async (req, res) => {
  try {
    const companyId = await companyIdFor(req);
    if (!companyId || !mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Valid collection job scope is required' });
    }
    let hunt = await ForensicHunt.findOne({ _id: req.params.id, ...scope(req, companyId) })
      .select('name artifacts status error clientId systemId createdAt startedAt completedAt providerResult requestedBy requestedByRole sourceIp companyId departmentId')
      .lean().maxTimeMS(10000);
    if (!hunt) return res.status(404).json({ message: 'Velociraptor collection job not found' });
    hunt = await syncHuntIfFinished(hunt, { io: req.app.get('io') });
    res.json({ hunt });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/hunts', async (req, res) => {
  if (!LAUNCH_ROLES.has(req.user.role)) return res.status(403).json({ message: 'Forensic hunt permission required' });
  try {
    const companyId = await companyIdFor(req);
    if (!companyId) return res.status(400).json({ message: 'Company scope is required' });
    const name = String(req.body.name || '').trim();
    const artifacts = (Array.isArray(req.body.artifacts) ? req.body.artifacts : [req.body.artifactName])
      .map(value => String(value || '').trim()).filter(Boolean);
    if (!name || name.length > 240) return res.status(400).json({ message: 'Valid hunt name is required' });
    if (!artifacts.length || artifacts.length > 20 || artifacts.some(item => !ALLOWED_ARTIFACT.test(item))) {
      return res.status(400).json({ message: 'Provide 1-20 valid Velociraptor artifact names' });
    }
    let target = null;
    let clientId = String(req.body.clientId || '').trim();
    const incidentId = mongoose.isValidObjectId(req.body.incidentId) ? req.body.incidentId : null;
    if (req.body.systemId) {
      target = await System.findOne({ _id: req.body.systemId, ...scope(req, companyId) }).select('name hostname departmentId velociraptorClientId').lean();
      if (!target) return res.status(404).json({ message: 'Target endpoint not found in company scope' });
      const liveClients = await veloListClients();
      const verifiedClient = matchingLiveClient(target, liveClients);
      clientId = verifiedClient?.client_id || verifiedClient?.id || '';
      if (!clientId) return res.status(400).json({ message: 'Target endpoint has no Velociraptor client ID' });
      if (clientId !== target.velociraptorClientId) {
        await System.updateOne({ _id: target._id }, { $set: { velociraptorClientId: clientId } }).maxTimeMS(3000).catch(() => {});
      }
    }
    const hunt = await ForensicHunt.create({
      companyId, departmentId: target?.departmentId || null, systemId: target?._id || null,
      incidentId, clientId, name, artifacts, requestedBy: req.user.id, requestedByRole: req.user.role,
      sourceIp: ip(req), status: 'queued',
    });
    const job = {
      huntId: hunt._id, companyId, target, clientId, name, artifacts,
      actor: { id: req.user.id, role: req.user.role }, sourceIp: ip(req), io: req.app.get('io'),
    };
    setImmediate(() => executeHuntJob(job).catch(error => console.error('[forensics/hunt-job]', error.message)));
    res.status(202).json({ hunt });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.post('/evidence/:id/verify', requireManager, async (req, res) => {
  try {
    const companyId = await companyIdFor(req);
    if (!companyId || !mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid evidence scope' });
    const evidence = await ForensicEvidence.findOne({ _id: req.params.id, ...scope(req, companyId) });
    if (!evidence) return res.status(404).json({ message: 'Evidence not found' });
    evidence.custody.push({ action: 'integrity_verified', actorId: req.user.id, actorRole: req.user.role, sourceIp: ip(req), note: String(req.body.note || '').slice(0, 1000) });
    await evidence.save();
    res.json({ ok: true, integrityStatus: evidence.integrityStatus, verifiedAt: new Date() });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.get('/evidence/:id/custody', async (req, res) => {
  try {
    const companyId = await companyIdFor(req);
    if (!companyId || !mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid evidence scope' });
    const evidence = await ForensicEvidence.findOne({ _id: req.params.id, ...scope(req, companyId) })
      .select('evidenceId name sha256 integrityStatus custody').populate('custody.actorId', 'name email').lean();
    if (!evidence) return res.status(404).json({ message: 'Evidence not found' });
    res.json(evidence);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
