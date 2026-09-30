/**
 * ips-engine.routes.js — IPS Engine REST API
 * ============================================
 * Exposes the IPS Decision Engine to dashboards:
 *
 * POST /api/ips-engine/notify     — IDS → IPS notification (called by IDS internally)
 * POST /api/ips-engine/isolate    — Admin manually isolates
 * POST /api/ips-engine/recover    — Admin manually recovers
 * GET  /api/ips-engine/incidents  — List active incidents with phase/status
 */

const router    = require('express').Router();
const mongoose  = require('mongoose');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const ipsEngine = require('../services/ipsEngine.service');
const System    = require('../models/System.model');
const User      = require('../models/User.model');
const { listAttackTypes } = require('../constants/idsIpsCapabilities');

router.use(authenticate, requireAnalyst);

// ── GET /api/ips-engine/attack-types — supported IPS attack classes ─────────
router.get('/attack-types', (req, res) => {
  const attackTypes = listAttackTypes();
  res.json({ ok: true, count: attackTypes.length, attackTypes });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/ips-engine/notify
// Called by the IDS alert receivers to pass detection data into the IPS engine.
// IDS → event → IPS Engine → block with retry → isolation fallback
// ─────────────────────────────────────────────────────────────────────────────
router.post('/notify', async (req, res) => {
  try {
    const { srcIp, attackType, severity, adminEmail, description, companyId: bodyCompanyId } = req.body;

    if (!srcIp || !attackType) {
      return res.status(400).json({ message: 'srcIp and attackType are required' });
    }

    // Strict: superadmin may specify companyId; all others use their own
    const isSuperAdmin = req.user.role === 'superadmin';
    const companyId = isSuperAdmin
      ? (bodyCompanyId || req.query.companyId || req.user.companyId?.toString())
      : req.user.companyId?.toString();

    if (!companyId) return res.status(400).json({ message: 'companyId is required' });

    // Fire-and-forget: IPS engine handles retries and isolation asynchronously
    ipsEngine.handleDetection({
      companyId,
      srcIp,
      attackType,
      severity:   severity || 'high',
      adminEmail: adminEmail || req.user.email || process.env.SMTP_USER,
      description,
    }).catch(err => console.error('[IPS Engine Route] handleDetection error:', err.message));

    res.json({
      ok: true,
      message: 'IPS Engine notified. Auto-block + retry + isolation running asynchronously.',
      srcIp,
      attackType,
      severity: severity || 'high',
      companyId,
    });
  } catch (err) {
    console.error('[IPS Engine] /notify error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/ips-engine/isolate
// Admin manually isolates a threat. Stops alert emails, applies block via IPS.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/isolate', requireManager, async (req, res) => {
  try {
    const { srcIp, attackType, systemId, companyId: bodyCompanyId } = req.body;
    if (!srcIp || !attackType) {
      return res.status(400).json({ message: 'srcIp and attackType are required' });
    }

    const isSuperAdmin = req.user.role === 'superadmin';
    const companyId = isSuperAdmin
      ? (bodyCompanyId || req.user.companyId?.toString())
      : req.user.companyId?.toString();

    const incident = await ipsEngine.manualIsolate({
      companyId, srcIp, attackType, systemId,
      adminEmail: req.user.email || process.env.SMTP_USER,
    });

    res.json({
      ok: true,
      incident,
      message: 'System manually isolated. Alert emails stopped. Recovery email will be sent when unblocked.',
    });
  } catch (err) {
    console.error('[IPS Engine] /isolate error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/ips-engine/recover
// Admin removes isolation, unblocks IP, sends recovery email.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/recover', requireManager, async (req, res) => {
  try {
    const { srcIp, attackType, systemId, companyId: bodyCompanyId } = req.body;
    if (!srcIp || !attackType) {
      return res.status(400).json({ message: 'srcIp and attackType are required' });
    }

    const isSuperAdmin = req.user.role === 'superadmin';
    const companyId = isSuperAdmin
      ? (bodyCompanyId || req.user.companyId?.toString())
      : req.user.companyId?.toString();

    const incident = await ipsEngine.manualRecover({
      companyId, srcIp, attackType, systemId,
      adminEmail: req.user.email || process.env.SMTP_USER,
    });

    res.json({
      ok: true,
      incident,
      message: 'System restored to normal. Recovery email sent.',
    });
  } catch (err) {
    console.error('[IPS Engine] /recover error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/ips-engine/incidents
// List all active incidents with current phase, block status, timers remaining.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/incidents', async (req, res) => {
  try {
    const isSuperAdmin = req.user.role === 'superadmin';
    const companyId = isSuperAdmin
      ? (req.query.companyId || null)  // null = all companies (superadmin overview)
      : req.user.companyId?.toString();

    const incidents = ipsEngine.getIncidents(companyId);
    res.json({ ok: true, incidents, count: incidents.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/ips-engine/audit — Automated response audit trail ───────────────
router.get('/audit', async (req, res) => {
  try {
    const isSuperAdmin = req.user.role === 'superadmin';
    const companyId = isSuperAdmin
      ? (req.query.companyId || null)
      : req.user.companyId?.toString();
    const limit = Math.min(1000, Math.max(1, Number(req.query.limit) || 300));
    const events = await ipsEngine.getAuditEvents(companyId, limit);
    res.json({ ok: true, events, count: events.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

async function queueManualReconnect({ companyId, systemId, reason, req }) {
  if (!systemId || !mongoose.Types.ObjectId.isValid(systemId)) {
    return { queued: false, reason: 'no valid systemId' };
  }

  const system = await System.findOne({ _id: systemId, companyId, isActive: true })
    .select('_id name hostname companyId');

  if (!system) return { queued: false, reason: 'system not found or inactive' };
  const { queueEndpointCommand } = require('../services/ips.service');
  const delivery = await queueEndpointCommand({
    companyId,
    systemId: system._id,
    command: 'reconnect',
    reason: reason || 'Manual override approved — server restored',
  });
  return {
    queued: delivery.queued > 0 || delivery.pending > 0,
    confirmed: delivery.confirmed === true,
    status: delivery.status,
    commandId: delivery.commandId || null,
    systemId: String(system._id),
    systemName: system.name || system.hostname,
  };
}

// ── POST /api/ips-engine/audit/manual — record admin/manual audit event ─────
router.post('/audit/manual', requireManager, async (req, res) => {
  try {
    const isSuperAdmin = req.user.role === 'superadmin';
    const companyId = isSuperAdmin
      ? (req.body.companyId || req.query.companyId || req.user.companyId?.toString())
      : req.user.companyId?.toString();
    const recipients = new Set([req.user.email].filter(Boolean));

    if ((req.body.action === 'Manual Override Approved' || req.body.emailSubject) && companyId) {
      const requestedSystemId = req.body.systemId || req.body.manualOverride?.systemId;
      let departmentId = req.user.role === 'department_admin' ? req.user.departmentId : null;

      if (requestedSystemId && mongoose.Types.ObjectId.isValid(requestedSystemId)) {
        const system = await System.findOne({
          _id: requestedSystemId,
          companyId,
          isActive: true,
        }).select('departmentId').lean();
        if (system?.departmentId) departmentId = system.departmentId;
      }

      const recipientFilters = [{ role: 'company_admin' }];
      if (departmentId) {
        recipientFilters.push(
          { role: 'department_admin', departmentId },
          { role: 'department_admin', departmentIds: departmentId },
        );
      }
      const admins = await User.find({
        companyId,
        isActive: true,
        $or: recipientFilters,
      }).select('email').lean();
      admins.forEach(admin => {
        if (admin.email) recipients.add(admin.email);
      });
    }
    if (!recipients.size && process.env.SMTP_USER) recipients.add(process.env.SMTP_USER);

    let reconnectResult = null;
    if (['Manual Override Approved', 'Server Restored'].includes(req.body.action)) {
      const systemId = req.body.systemId || req.body.manualOverride?.systemId;
      reconnectResult = await queueManualReconnect({
        companyId,
        systemId,
        reason: req.body.detail || req.body.manualOverride?.reason || 'Manual override approved — server restored',
        req,
      });
    }

    const event = await ipsEngine.recordAuditEvent({
      ...req.body,
      companyId,
      actor: req.user.name || req.user.email || 'Admin',
      emailTo: [...recipients],
      metadata: {
        ...(req.body.metadata || {}),
        ...(req.body.manualOverride ? { manualOverride: req.body.manualOverride } : {}),
        ...(reconnectResult ? { reconnect: reconnectResult } : {}),
      },
    });
    res.status(201).json({ ok: true, event });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
