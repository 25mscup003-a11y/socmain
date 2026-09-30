/**
 * soc-agent-edr.routes.js
 *
 * SOC AI Agent EDR API Routes
 *
 * GET  /api/soc-edr/incidents          — List all correlated incidents (paginated)
 * GET  /api/soc-edr/incidents/:id      — Get single incident details
 * PATCH /api/soc-edr/incidents/:id     — Update incident (status, assignee, notes)
 * POST /api/soc-edr/incidents/:id/action — Execute EDR response action
 * GET  /api/soc-edr/dashboard          — Full dashboard statistics
 * GET  /api/soc-edr/hunt               — Run proactive threat hunt
 * GET  /api/soc-edr/timeline/:systemId — Per-endpoint attack timeline
 * GET  /api/soc-edr/mitre-coverage     — MITRE ATT&CK coverage map
 */

const router = require('express').Router();
const mongoose = require('mongoose');
const { authenticate, requireAnalyst, requireManager, requireCompanyAdmin } = require('../middleware/auth.middleware');
const EdrIncident = require('../models/EdrIncident.model');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const {
  runThreatHunt,
  getEdrDashboardStats,
  logResponseAction,
  MITRE_MAP,
  CORRELATION_RULES,
} = require('../services/soc-agent-edr.service');

// ── All routes require JWT + analyst role ─────────────────────────────────────
router.use(authenticate, requireAnalyst);

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/soc-edr/dashboard — Full SOC AI EDR dashboard statistics
// ─────────────────────────────────────────────────────────────────────────────
router.get('/dashboard', async (req, res) => {
  try {
    const data = await getEdrDashboardStats(req.user.companyId);
    res.json(data);
  } catch (err) {
    console.error('[soc-edr/dashboard]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/soc-edr/incidents — paginated incident list
// ─────────────────────────────────────────────────────────────────────────────
router.get('/incidents', async (req, res) => {
  try {
    const {
      page = 1, limit = 25,
      severity, status, category,
      from, to, systemId,
    } = req.query;

    const filter = {
      companyId: req.user.companyId,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
    };
    if (severity) filter.severity = severity;
    if (status) filter.status = status;
    if (category) filter.category = category;
    if (systemId) filter.systemId = systemId;
    if (from || to) {
      filter.createdAt = {};
      if (from) filter.createdAt.$gte = new Date(from);
      if (to) filter.createdAt.$lte = new Date(to);
    }

    const [incidents, total] = await Promise.all([
      EdrIncident.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(Number(limit))
        .populate('systemId', 'name hostname ip os')
        .populate('assignedTo', 'name email')
        .lean(),
      EdrIncident.countDocuments(filter),
    ]);

    res.json({ incidents, total, page: Number(page), limit: Number(limit) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/soc-edr/incidents/:id — single incident
// ─────────────────────────────────────────────────────────────────────────────
router.get('/incidents/:id', async (req, res) => {
  try {
    const incident = await EdrIncident.findOne({
      _id: req.params.id,
      companyId: req.user.companyId,
    })
      .populate('systemId', 'name hostname ip os osType')
      .populate('assignedTo', 'name email')
      .populate('alertIds')
      .lean();

    if (!incident) return res.status(404).json({ message: 'Incident not found' });
    res.json(incident);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// PATCH /api/soc-edr/incidents/:id — update status, assignee, notes
// ─────────────────────────────────────────────────────────────────────────────
router.patch('/incidents/:id', requireManager, async (req, res) => {
  try {
    const allowed = ['status', 'severity', 'assignedTo', 'notes'];
    const update = {};
    for (const k of allowed) {
      if (req.body[k] !== undefined) update[k] = req.body[k];
    }
    if (update.status === 'resolved') update.resolvedAt = new Date();
    if (req.body.note) {
      update.$push = {
        notes: { user: req.user._id, text: req.body.note, at: new Date() }
      };
      delete update.notes;
    }

    const incident = await EdrIncident.findOneAndUpdate(
      { _id: req.params.id, companyId: req.user.companyId },
      update,
      { new: true }
    );
    if (!incident) return res.status(404).json({ message: 'Incident not found' });

    const io = req.app.get('io');
    if (io) io.to(`company:${incident.companyId}`).emit('edr:incident:updated', incident);

    res.json(incident);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/soc-edr/incidents/:id/action — execute EDR response action
// Supported actions: isolate_endpoint | kill_process | quarantine_file |
//                    block_ip | disable_user | mark_false_positive
// ─────────────────────────────────────────────────────────────────────────────
router.post('/incidents/:id/action', requireManager, async (req, res) => {
  try {
    const { action, target, reason } = req.body;
    if (!action) return res.status(400).json({ message: 'action is required' });

    const incident = await EdrIncident.findOne({
      _id: req.params.id,
      companyId: req.user.companyId,
    }).populate('systemId');
    if (!incident) return res.status(404).json({ message: 'Incident not found' });

    let result = `Action ${action} logged`;
    let alertUpdate = {};

    switch (action) {
      case 'isolate_endpoint': {
        // Update system isolation flag in DB — SOC Agent will pick this up on next poll
        if (incident.systemId) {
          await System.findByIdAndUpdate(incident.systemId._id, {
            isIsolated: true,
            isolatedAt: new Date(),
            isolationReason: reason || `SOC AI: ${incident.title}`,
          });
          result = `Endpoint ${incident.systemId.name || incident.affectedEndpoint} isolation scheduled`;
        } else {
          result = 'No system linked — manual isolation required';
        }
        alertUpdate = { isolated: true, isolatedAt: new Date(), isolationReason: reason };
        break;
      }

      case 'kill_process': {
        // Emit via Socket.IO to agent system room — agent listens for 'edr:kill_process'
        const io = req.app.get('io');
        if (io && incident.systemId) {
          io.to(`system_${incident.systemId._id}`).emit('edr:kill_process', {
            processName: target || incident.iocs.find(i => i.type === 'process')?.value,
            incidentId: incident._id,
            reason: reason || incident.title,
          });
          result = `Kill-process command sent to ${incident.systemId.name}`;
        } else {
          result = 'Kill-process command logged (no socket connection to agent)';
        }
        break;
      }

      case 'quarantine_file': {
        const fileTarget = target || incident.iocs.find(i => i.type === 'file')?.value;
        const io = req.app.get('io');
        if (io && incident.systemId) {
          io.to(`system_${incident.systemId._id}`).emit('edr:quarantine_file', {
            filePath: fileTarget,
            incidentId: incident._id,
          });
          result = `Quarantine command sent for ${fileTarget}`;
        } else {
          result = `Quarantine logged for ${fileTarget}`;
        }
        // Update related alerts
        await Alert.updateMany(
          { _id: { $in: incident.alertIds }, filePath: fileTarget },
          { quarantined: true, actionTaken: 'Quarantined', containmentStatus: 'quarantined' }
        );
        break;
      }

      case 'block_ip': {
        const ip = target || incident.iocs.find(i => i.type === 'ip')?.value;
        if (ip) {
          // Trigger IPS auto-block through existing service
          try {
            const { autoBlockIp } = require('../services/ips.service');
            await autoBlockIp(ip, incident.companyId, `SOC AI: ${incident.title}`);
            result = `IP ${ip} blocked via IPS`;
          } catch (e) {
            result = `IP ${ip} block request logged — IPS: ${e.message}`;
          }
          await Alert.updateMany(
            { _id: { $in: incident.alertIds } },
            { blocked: true, containmentStatus: 'blocked' }
          );
        } else {
          result = 'No target IP found — specify target';
        }
        break;
      }

      case 'disable_user': {
        const User = require('../models/User.model');
        const username = target || incident.affectedUser;
        if (username) {
          await User.findOneAndUpdate(
            { $or: [{ email: username }, { name: username }], companyId: incident.companyId },
            { isActive: false }
          );
          result = `User ${username} disabled`;
        } else {
          result = 'No user target specified';
        }
        break;
      }

      case 'mark_false_positive': {
        await EdrIncident.findByIdAndUpdate(incident._id, {
          status: 'false_positive',
          resolvedAt: new Date(),
        });
        result = 'Incident marked as false positive';
        break;
      }

      case 'resolve': {
        await EdrIncident.findByIdAndUpdate(incident._id, {
          status: 'resolved',
          resolvedAt: new Date(),
          closedBy: req.user._id,
        });
        result = 'Incident marked as resolved';
        break;
      }

      case 'escalate': {
        await EdrIncident.findByIdAndUpdate(incident._id, {
          status: 'investigating',
          severity: 'critical',
        });
        result = 'Incident escalated to critical / investigating';
        break;
      }

      default:
        result = `Unknown action: ${action}`;
    }

    // Log the action
    const actionLog = await logResponseAction(
      incident._id,
      action,
      target || 'N/A',
      result,
      req.user._id?.toString()
    );

    // Push socket update
    const io = req.app.get('io');
    if (io) {
      const updated = await EdrIncident.findById(incident._id).lean();
      io.to(`company:${incident.companyId}`).emit('edr:incident:updated', updated);
    }

    res.json({ ok: true, result, actionLog });
  } catch (err) {
    console.error('[soc-edr/action]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/soc-edr/hunt — proactive threat hunting
// ─────────────────────────────────────────────────────────────────────────────
router.get('/hunt', async (req, res) => {
  try {
    const result = await runThreatHunt(req.user.companyId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/soc-edr/timeline/:systemId — endpoint attack timeline
// ─────────────────────────────────────────────────────────────────────────────
router.get('/timeline/:systemId', async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const cid = req.user.companyId;
    const sid = req.params.systemId;

    const [alerts, incidents] = await Promise.all([
      Alert.find({
        companyId: cid,
        systemId: sid,
        createdAt: { $gte: since },
      }).sort({ createdAt: -1 }).limit(100).lean(),

      EdrIncident.find({
        companyId: cid,
        systemId: sid,
        createdAt: { $gte: since },
      }).sort({ createdAt: -1 }).lean(),
    ]);

    // Build unified timeline
    const timeline = [
      ...alerts.map(a => ({
        id: a._id,
        timestamp: a.createdAt,
        type: 'alert',
        severity: a.severity,
        title: a.ruleId || a.description?.substring(0, 60) || 'Alert',
        category: a.eventCategory,
        details: a.description,
      })),
      ...incidents.map(i => ({
        id: i._id,
        timestamp: i.createdAt,
        type: 'incident',
        severity: i.severity,
        title: i.title,
        category: i.category,
        details: i.description,
        mitre: i.mitreTechnique,
      })),
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({ timeline, systemId: sid });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/soc-edr/mitre-coverage — MITRE ATT&CK coverage map
// ─────────────────────────────────────────────────────────────────────────────
router.get('/mitre-coverage', async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const incidents = await EdrIncident.find({
      companyId: req.user.companyId,
      createdAt: { $gte: since },
      mitreTechnique: { $exists: true },
    }).select('mitreTechnique mitreTechniqueName mitreTactics category severity').lean();

    const techniqueMap = {};
    for (const inc of incidents) {
      const tid = inc.mitreTechnique;
      if (!techniqueMap[tid]) {
        techniqueMap[tid] = {
          id: tid,
          name: inc.mitreTechniqueName,
          tactics: inc.mitreTactics,
          count: 0,
          severityMax: 'low',
        };
      }
      techniqueMap[tid].count++;
      const sev = { low: 0, medium: 1, high: 2, critical: 3 };
      if (sev[inc.severity] > sev[techniqueMap[tid].severityMax]) {
        techniqueMap[tid].severityMax = inc.severity;
      }
    }

    // Also report all detectable techniques from CORRELATION_RULES
    const detectable = CORRELATION_RULES.map(r => {
      const mitreKey = r.mitre;
      const mitreData = Object.values(MITRE_MAP).find(m => m.id.startsWith(mitreKey.split('_')[0]));
      return {
        ruleId: r.id,
        name: r.name,
        category: r.category,
        mitre: mitreKey,
      };
    });

    res.json({
      detectedTechniques: Object.values(techniqueMap).sort((a, b) => b.count - a.count),
      detectableRules: detectable,
      totalDetected: Object.keys(techniqueMap).length,
      period: '24h',
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/soc-edr/live-telemetry — recent alert stream for live feed
// ─────────────────────────────────────────────────────────────────────────────
router.get('/live-telemetry', async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const alerts = await Alert.find({
      companyId: req.user.companyId,
      createdAt: { $gte: since },
    })
      .sort({ createdAt: -1 })
      .limit(100)
      .select('ruleId description severity eventCategory agentName srcip createdAt username')
      .lean();

    res.json({ alerts, count: alerts.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/soc-edr/endpoint-risk — per-endpoint risk score
// ─────────────────────────────────────────────────────────────────────────────
router.get('/endpoint-risk', async (req, res) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const cid = mongoose.Types.ObjectId.createFromHexString(req.user.companyId.toString());
    const now = Date.now();
    const onlineThresholdMs = 10 * 60 * 1000;

    const systems = await System.find({
      companyId: cid,
      isActive: true,
      agentVersion: { $exists: true, $nin: [null, ''] },
      lastSeen: { $exists: true, $ne: null },
    }).lean();

    const riskData = await Promise.all(systems.map(async (sys) => {
      const [critical, high, medium, low, incidents] = await Promise.all([
        Alert.countDocuments({ systemId: sys._id, severity: 'critical', createdAt: { $gte: since24h } }),
        Alert.countDocuments({ systemId: sys._id, severity: 'high', createdAt: { $gte: since24h } }),
        Alert.countDocuments({ systemId: sys._id, severity: 'medium', createdAt: { $gte: since24h } }),
        Alert.countDocuments({ systemId: sys._id, severity: 'low', createdAt: { $gte: since24h } }),
        EdrIncident.countDocuments({ systemId: sys._id, status: { $in: ['open', 'investigating'] }, createdAt: { $gte: since24h } }),
      ]);

      // Risk score: weighted formula
      const score = Math.min(100, critical * 25 + high * 10 + medium * 4 + low * 1 + incidents * 15);
      const riskLevel = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
      const isOnline = Boolean(
        sys.status === 'active' &&
        sys.lastSeen &&
        (now - new Date(sys.lastSeen).getTime()) < onlineThresholdMs
      );
      const status = sys.isIsolated ? 'isolated' : isOnline ? 'active' : 'disconnected';

      return {
        systemId: sys._id,
        name: sys.name || sys.hostname || 'Endpoint',
        hostname: sys.hostname || sys.name || '—',
        ip: sys.ip,
        os: sys.os,
        status,
        lastSeen: sys.lastSeen,
        isOnline,
        isIsolated: sys.isIsolated,
        riskScore: score,
        riskLevel,
        alerts: { critical, high, medium, low },
        openIncidents: incidents,
      };
    }));

    riskData.sort((a, b) => b.riskScore - a.riskScore);
    res.json({ endpoints: riskData, total: riskData.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/soc-edr/incidents/:id/notes — add analyst note
// ─────────────────────────────────────────────────────────────────────────────
router.post('/incidents/:id/notes', requireManager, async (req, res) => {
  const text = String(req.body.text || '').trim();
  if (!text) return res.status(400).json({ message: 'Analyst note is required' });
  if (text.length > 4000) return res.status(400).json({ message: 'Analyst note cannot exceed 4000 characters' });
  try {
    const actorId = req.user.id || req.user._id;
    const incident = await EdrIncident.findOneAndUpdate(
      { _id: req.params.id, companyId: req.user.companyId },
      { $push: { notes: { user: actorId, text, at: new Date() } } },
      { new: true }
    ).populate('notes.user', 'name email role');
    if (!incident) return res.status(404).json({ message: 'Incident not found in your company' });
    const io = req.app.get('io');
    io?.to(`company:${incident.companyId}`).emit('edr:incident:updated', incident);
    res.json(incident);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
