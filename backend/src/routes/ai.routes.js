const router = require('express').Router();
const mongoose = require('mongoose');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const CorrelationEvent = require('../models/CorrelationEvent.model');
const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const AiAnalysis = require('../models/AiAnalysis.model');
const {
  configured, autoAnalysisEnabled, enqueueCorrelationAnalysis, enqueueSecurityEventAnalysis, enqueueEdrIncidentAnalysis,
} = require('../services/azureAi.service');

router.use(authenticate, requireAnalyst);

function sourceIp(req) {
  return String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1');
}

async function companyScope(req, requestedCompanyId) {
  if (req.user.role === 'superadmin') {
    if (!mongoose.isValidObjectId(requestedCompanyId)) return null;
    return new mongoose.Types.ObjectId(requestedCompanyId);
  }
  const { allowedCompanyIds } = require('../services/socAccess.service');
  const allowed = await allowedCompanyIds(req.user);
  const targetId = requestedCompanyId || req.user.companyId;
  if (!targetId || !mongoose.isValidObjectId(targetId)) return null;
  if (allowed.includes(String(targetId))) {
    return new mongoose.Types.ObjectId(targetId);
  }
  return null;
}

router.get('/status', (req, res) => {
  res.json({
    configured: configured(),
    autoAnalysisEnabled: autoAnalysisEnabled(),
    provider: process.env.AZURE_AI_CHAT_COMPLETIONS_URL ? 'chat_completions' : 'responses_api',
    model: process.env.AZURE_AI_MODEL || '',
  });
});

router.post('/correlation/:id/analyze', async (req, res) => {
  try {
    if (!configured()) return res.status(503).json({ message: 'AI provider is not configured' });
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid incident' });
    const companyId = await companyScope(req, req.body?.companyId);
    if (!companyId) return res.status(400).json({ message: 'Valid company scope is required' });
    const filter = { _id: req.params.id, companyId };
    if (req.user.role === 'department_admin') filter.departmentId = req.user.departmentId;
    const incident = await CorrelationEvent.findOne(filter).lean();
    if (!incident) return res.status(404).json({ message: 'Incident not found in your scope' });
    const result = await enqueueCorrelationAnalysis({
      incident, user: req.user, sourceIp: sourceIp(req), io: req.app.get('io'),
      force: req.body?.force === true,
    });
    res.status(result.cached ? 200 : 202).json(result);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/alerts/:id/analyze', async (req, res) => {
  try {
    if (!configured()) return res.status(503).json({ message: 'AI provider is not configured' });
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid alert' });
    const companyId = await companyScope(req, req.body?.companyId);
    if (!companyId) return res.status(400).json({ message: 'Valid company scope is required' });
    const filter = { _id: req.params.id, companyId };
    if (req.user.role === 'department_admin') filter.departmentId = req.user.departmentId;
    const alert = await Alert.findOne(filter);
    if (!alert) return res.status(404).json({ message: 'Alert not found in your scope' });
    const job = await enqueueSecurityEventAnalysis(alert, {
      io: req.app.get('io'), force: true, user: req.user, sourceIp: sourceIp(req),
    });
    res.status(202).json({ job: job.toObject ? job.toObject() : job, cached: false });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/edr-incidents/:id/analyze', async (req, res) => {
  try {
    if (!configured()) return res.status(503).json({ message: 'AI provider is not configured' });
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid EDR incident' });
    const companyId = await companyScope(req, req.body?.companyId);
    if (!companyId) return res.status(400).json({ message: 'Valid company scope is required' });
    const incident = await EdrIncident.findOne({ _id: req.params.id, companyId });
    if (!incident) return res.status(404).json({ message: 'EDR incident not found in your scope' });
    const job = await enqueueEdrIncidentAnalysis(incident, {
      io: req.app.get('io'), user: req.user, sourceIp: sourceIp(req),
    });
    res.status(202).json({ job: job.toObject ? job.toObject() : job });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/jobs/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid AI job' });
    const filter = { _id: req.params.id };
    if (req.user.role !== 'superadmin') {
      const { allowedCompanyIds } = require('../services/socAccess.service');
      const allowed = await allowedCompanyIds(req.user);
      filter.companyId = { $in: allowed };
    }
    const job = await AiAnalysis.findOne(filter).lean();
    if (!job) return res.status(404).json({ message: 'AI job not found' });
    res.set('Cache-Control', 'no-store');
    res.json(job);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/correlation/:id/latest', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid incident' });
    const filter = { resourceId: req.params.id, taskType: 'correlation_analysis' };
    if (req.user.role !== 'superadmin') {
      const { allowedCompanyIds } = require('../services/socAccess.service');
      const allowed = await allowedCompanyIds(req.user);
      filter.companyId = { $in: allowed };
    }
    const job = await AiAnalysis.findOne(filter).sort({ createdAt: -1 }).lean();
    res.json(job || null);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/alerts/:id/latest', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid alert' });
    const filter = { resourceId: req.params.id, taskType: 'security_event_analysis' };
    if (req.user.role !== 'superadmin') {
      const { allowedCompanyIds } = require('../services/socAccess.service');
      const allowed = await allowedCompanyIds(req.user);
      filter.companyId = { $in: allowed };
    }
    const job = await AiAnalysis.findOne(filter).sort({ createdAt: -1 }).lean();
    res.json(job || null);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
