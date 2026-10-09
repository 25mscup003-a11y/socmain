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
router.post('/notify', requireManager, async (req, res) => {
  try {
    const { srcIp, attackType, severity, description, systemId, companyId: bodyCompanyId } = req.body;

    if (!srcIp || !attackType) {
      return res.status(400).json({ message: 'srcIp and attackType are required' });
    }

    // Strict: superadmin may specify companyId; all others use their own
    const isSuperAdmin = req.user.role === 'superadmin';
    const companyId = isSuperAdmin
      ? (bodyCompanyId || req.query.companyId || req.user.companyId?.toString())
      : req.user.companyId?.toString();

    if (!companyId) return res.status(400).json({ message: 'companyId is required' });
    if (systemId && (!mongoose.Types.ObjectId.isValid(systemId) || !await System.exists({ _id: systemId, companyId, isActive: true }))) {
      return res.status(404).json({ message: 'Target system not found in this company' });
    }

    // Fire-and-forget: IPS engine handles retries and isolation asynchronously
    ipsEngine.handleDetection({
      companyId,
      srcIp,
      attackType,
      severity:   severity || 'high',
      adminEmail: req.user.email,
      systemId,
      description,
    }).catch(err => console.error('[IPS Engine Route] handleDetection error:', err.message));

    res.status(202).json({
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

    if (!companyId || !systemId || !mongoose.Types.ObjectId.isValid(systemId)) return res.status(400).json({ message: 'companyId and a valid target systemId are required' });
    if (!await System.exists({ _id: systemId, companyId, isActive: true })) return res.status(404).json({ message: 'Target system not found in this company' });
    const incident = await ipsEngine.manualIsolate({
      companyId, srcIp, attackType, systemId,
      adminEmail: req.user.email || process.env.SMTP_USER,
    });

    res.status(incident.phase === 'isolated' ? 200 : incident.phase === 'isolation_failed' ? 502 : 202).json({
      ok: incident.phase === 'isolated', accepted: incident.phase === 'isolation_pending',
      incident: { ...incident, timers: undefined },
      message: incident.phase === 'isolated' ? 'Endpoint confirmed isolation' : incident.phase === 'isolation_failed' ? 'Endpoint isolation failed' : 'Isolation queued; waiting for endpoint acknowledgement',
    });
  } catch (err) {
    console.error('[IPS Engine] /isolate error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/ips-engine/recover
// Admin removes endpoint isolation; IP blocks have a separate lifecycle.
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

    if (!companyId || !systemId || !mongoose.Types.ObjectId.isValid(systemId)) return res.status(400).json({ message: 'companyId and a valid target systemId are required' });
    if (!await System.exists({ _id: systemId, companyId, isActive: true })) return res.status(404).json({ message: 'Target system not found in this company' });
    const incident = await ipsEngine.manualRecover({
      companyId, srcIp, attackType, systemId,
      adminEmail: req.user.email || process.env.SMTP_USER,
    });

    res.status(incident.phase === 'recovered' ? 200 : incident.phase === 'recovery_failed' ? 502 : 202).json({
      ok: incident.phase === 'recovered', accepted: incident.phase === 'recovery_pending',
      incident: { ...incident, timers: undefined },
      message: incident.phase === 'recovered' ? 'Endpoint confirmed reconnection' : incident.phase === 'recovery_failed' ? 'Endpoint reconnection failed' : 'Reconnection queued; confirmation email follows the endpoint acknowledgement',
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
    reason: reason || 'Manual override approved — reconnect requested',
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
    if (!companyId || !mongoose.Types.ObjectId.isValid(companyId)) return res.status(400).json({ message: 'A valid companyId is required' });
    const requestedSystemId = req.body.systemId || req.body.manualOverride?.systemId;
    if (req.body.restoreEndpoint === true) {
      if (!mongoose.Types.ObjectId.isValid(requestedSystemId || '')) return res.status(400).json({ message: 'A valid target systemId is required for reconnection' });
      if (!await System.exists({ _id: requestedSystemId, companyId, isActive: true })) return res.status(404).json({ message: 'Target system not found in this company' });
    }
    const recipients = await ipsEngine.resolveAdminRecipients({ companyId,
      systemId: mongoose.Types.ObjectId.isValid(requestedSystemId || '') ? requestedSystemId : null,
      fallback: req.user.email });

    let reconnectResult = null;
    if (req.body.action === 'Manual Override Approved' && req.body.restoreEndpoint === true) {
      const systemId = req.body.systemId || req.body.manualOverride?.systemId;
      reconnectResult = await queueManualReconnect({
        companyId,
        systemId,
        reason: req.body.detail || req.body.manualOverride?.reason || 'Manual override approved — reconnect requested',
        req,
      });
    }

    const manualActions = new Set(['Manual Override Requested', 'Manual Override Cancelled', 'Manual Override Approved', 'Checklist Submitted', 'User Actions']);
    const action = manualActions.has(req.body.action) ? req.body.action : 'User Actions';
    const event = await ipsEngine.recordAuditEvent({
      ...req.body,
      // Confirmation events belong to authenticated agent ACKs, not browser claims.
      action,
      detail: action !== req.body.action ? `Administrator reported ${String(req.body.action || 'an action').slice(0, 100)}; enforcement confirmation is recorded separately` : req.body.detail,
      companyId,
      actor: req.user.name || req.user.email || 'Admin',
      emailTo: [...recipients],
      metadata: {
        ...(req.body.metadata || {}),
        ...(action !== req.body.action ? { reportedAction: req.body.action } : {}),
        ...(req.body.manualOverride ? { manualOverride: req.body.manualOverride } : {}),
        ...(reconnectResult ? { reconnect: reconnectResult } : {}),
      },
    });
    const reconnectFailed = reconnectResult && !reconnectResult.confirmed && (!reconnectResult.queued || reconnectResult.status === 'failed');
    res.status(reconnectFailed ? 502 : reconnectResult && !reconnectResult.confirmed ? 202 : 201).json({
      ok: !reconnectFailed, event,
      ...(reconnectFailed ? { message: 'Override recorded, but endpoint reconnection failed', reconnect: reconnectResult } : {}),
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
