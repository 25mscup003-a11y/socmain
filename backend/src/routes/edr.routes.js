/**
 * edr.routes.js
 * EDR integration routes — Velociraptor forensic + native SOC4 EDR stats.
 *
 * GET  /api/edr/velociraptor      — List Velociraptor clients
 * POST /api/edr/velociraptor/hunt — Start forensic hunt
 * GET  /api/edr/status            — Show Velociraptor connection status
 * GET  /api/edr/stats             — 7-day EDR alert stats (from DB)
 * GET  /api/edr/endpoints-stats   — Per-system alert counts
 */
const router = require('express').Router();
const { authenticate, requireAnalyst, requireManager, requireCompanyAdmin } = require('../middleware/auth.middleware');
const Alert = require('../models/Alert.model');
const Log = require('../models/Log.model');
const System = require('../models/System.model');
const { isConfigured, veloListClients, veloRunHunt } = require('../services/velociraptor.service');

// ── Velociraptor clients ──────────────────────────────────────────────────────
router.get('/velociraptor', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const clients = await veloListClients();
    res.json({ clients, total: clients.length });
  } catch (err) {
    res.status(503).json({ message: err.message });
  }
});

// ── Velociraptor forensic hunt ────────────────────────────────────────────────
router.post('/velociraptor/hunt', authenticate, requireCompanyAdmin, async (req, res) => {
  const { name, artifactName, artifacts, systemId } = req.body;
  let { clientId } = req.body;
  const startedAt = new Date();
  try {
    let targetSystem = null;
    if (systemId) {
      targetSystem = await System.findOne({ _id: systemId, companyId: req.user.companyId })
        .select('name hostname velociraptorClientId')
        .lean();
      if (!targetSystem) return res.status(404).json({ message: 'Selected system not found' });
      clientId = targetSystem.velociraptorClientId || clientId || '';
      if (!clientId) return res.status(400).json({ message: 'Selected system does not have a Velociraptor client id' });
    }

    const result = await veloRunHunt({ name, artifactName, artifacts, clientId });
    const artifactList = Array.isArray(artifacts) && artifacts.length ? artifacts : [artifactName].filter(Boolean);
    const log = await Log.create({
      companyId: req.user.companyId,
      systemId: systemId || undefined,
      source: 'velociraptor',
      logType: 'edr',
      level: 'info',
      message: `Velociraptor forensic hunt launched: ${name || 'Untitled hunt'}${targetSystem ? ` on ${targetSystem.name || targetSystem.hostname}` : ''}`,
      program: 'velociraptor',
      logTime: startedAt,
      receivedAt: new Date(),
      fields: {
        action: 'forensic_hunt_launched',
        huntName: name,
        artifactName,
        artifacts: artifactList,
        systemId: systemId || '',
        systemName: targetSystem?.name || '',
        clientId: clientId || '',
        result,
      },
      raw: JSON.stringify({ name, artifactName, artifacts: artifactList, systemId, clientId, result }),
      format: 'json',
      tags: ['forensic', 'velociraptor', 'hunt', 'siem'],
    });
    const io = req.app.get('io');
    if (io) io.to(`company:${req.user.companyId}`).emit('log:new', log.toObject());
    res.json({ ok: true, hunt: result });
  } catch (err) {
    try {
      const log = await Log.create({
        companyId: req.user.companyId,
        systemId: systemId || undefined,
        source: 'velociraptor',
        logType: 'edr',
        level: 'error',
        message: `Velociraptor forensic hunt failed: ${name || 'Untitled hunt'} — ${err.message}`,
        program: 'velociraptor',
        logTime: startedAt,
        receivedAt: new Date(),
        fields: {
          action: 'forensic_hunt_failed',
          huntName: name,
          artifactName,
          artifacts,
          systemId: systemId || '',
          clientId: clientId || '',
          error: err.message,
        },
        raw: JSON.stringify({ name, artifactName, artifacts, systemId, clientId, error: err.message }),
        format: 'json',
        tags: ['forensic', 'velociraptor', 'hunt', 'siem', 'error'],
      });
      const io = req.app.get('io');
      if (io) io.to(`company:${req.user.companyId}`).emit('log:new', log.toObject());
    } catch (logErr) {
      console.error('[edr/velociraptor/hunt log]', logErr.message);
    }
    res.status(503).json({ message: err.message });
  }
});

// ── EDR connection status ─────────────────────────────────────────────────────
router.get('/status', authenticate, requireAnalyst, async (req, res) => {
  const status = {
    velociraptor: {
      url:        process.env.VELOCIRAPTOR_URL || 'http://localhost:8889',
      configured: isConfigured(),
      connected:  false,
    },
  };
  try {
    await veloListClients();
    status.velociraptor.connected = true;
  } catch { /* not connected */ }
  res.json(status);
});

// ── SOC4-native EDR stats (from Alert model) ──────────────────────────────────
router.get('/stats', authenticate, requireAnalyst, async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const base  = { companyId: req.user.companyId, createdAt: { $gte: since } };

    const [privEsc, bruteForce, malware, ransomware, processAlerts] = await Promise.all([
      Alert.countDocuments({ ...base, $or: [{ userAction: 'privilege_escalation' }, { ruleId: /priv|escalat|sudo/i }] }),
      Alert.countDocuments({ ...base, $or: [{ userAction: 'brute_force' }, { ruleId: /brute|fail.*login|auth/i }, { description: /brute|failed.*auth/i }] }),
      Alert.countDocuments({ ...base, eventCategory: 'malware' }),
      Alert.countDocuments({ ...base, $or: [{ malwareType: 'Ransomware' }, { userAction: 'ransomware_detected' }, { ruleId: /ransomware/i }] }),
      Alert.countDocuments({ ...base, $or: [{ eventCategory: 'system' }, { eventCategory: 'edr' }] }),
    ]);

    res.json({ period: '24h', privEsc, bruteForce, malware, ransomware, processAlerts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/edr/endpoints-stats — per-system alert counts ───────────────────
router.get('/endpoints-stats', authenticate, requireAnalyst, async (req, res) => {
  try {
    const mongoose = require('mongoose');
    const System   = require('../models/System.model');
    const since    = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const cid      = new mongoose.Types.ObjectId(req.user.companyId);
    const base     = { companyId: cid, createdAt: { $gte: since } };

    const systems = await System.find({ companyId: cid, isActive: true }).lean();

    const stats = await Promise.all(
      systems.map(async (sys) => {
        const sysBase = { ...base, systemId: sys._id };
        const [critical, malware, network] = await Promise.all([
          Alert.countDocuments({ ...sysBase, severity: 'critical' }),
          Alert.countDocuments({ ...sysBase, eventCategory: 'malware' }),
          Alert.countDocuments({ ...sysBase, eventCategory: 'network' }),
        ]);
        return { systemId: sys._id, name: sys.name, critical, malware, network };
      })
    );

    res.json({ stats });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
