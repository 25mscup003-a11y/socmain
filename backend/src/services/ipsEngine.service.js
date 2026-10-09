/**
 * ipsEngine.service.js — IPS Decision Engine
 * ============================================
 * Policy/TI decisions use the full retry and isolation lifecycle here.
 * Severity-only, SOAR and threat-feed callers may use ips.service directly.
 * Block confirmation requires a firewall result or endpoint ACK. Three failed
 * attempts trigger fresh-threat verification before isolation; successful blocks only escalate when
 * IPS_ISOLATE_AFTER_SUCCESSFUL_BLOCK is enabled. Recovery uses a durable sweep.
 */

const http       = require('http');
const nodemailer = require('nodemailer');
const System     = require('../models/System.model');
const User       = require('../models/User.model');
const Alert      = require('../models/Alert.model');
const IpsAuditEvent = require('../models/IpsAuditEvent.model');
const isolationGuard = require('./ipsIsolationGuard.service');
const { listAttackTypes, resolveAttackType } = require('../constants/idsIpsCapabilities');

const IPS_URL    = process.env.IPS_WEBHOOK_URL    || 'http://localhost:5050';
const IPS_SECRET = process.env.IPS_WEBHOOK_SECRET || '';

// ── Config ────────────────────────────────────────────────────────────────────
const MAX_RETRIES          = 3;
const RETRY_DELAY_MS       = 5000;    // 5s between block retries
const ALERT_INTERVAL_MS    = parseInt(process.env.IPS_ALERT_INTERVAL_MS || `${45 * 1000}`, 10); // 30-60s reminder window
const AUTO_ISOLATE_DELAY_MS = parseInt(process.env.IPS_AUTO_ISOLATE_DELAY_MS || `${5 * 60 * 1000}`, 10); // 5min before auto-isolation
const AUTO_RECOVER_DELAY_MS = parseInt(process.env.IPS_AUTO_RECOVER_DELAY_MS || `${20 * 60 * 1000}`, 10); // 20min recovery timer
const ISOLATE_AFTER_SUCCESSFUL_BLOCK = process.env.IPS_ISOLATE_AFTER_SUCCESSFUL_BLOCK === 'true';

// ── Attack Types that trigger IPS auto-block ─────────────────────────────────
const AUTO_BLOCK_SEVERITIES = ['high', 'critical'];
const CANONICAL_ATTACK_TYPES = listAttackTypes();

function resolveCanonicalAttackType(...values) {
  return resolveAttackType(...values);
}

function isAcceptedBlockResult(result = {}) {
  return result.agentConfirmed === true || result.webhookOk === true ||
    result.note === 'already blocked' || result.reason === 'already blocked';
}

// ── In-memory incident tracker ────────────────────────────────────────────────
// key → { companyId, srcIp, attackType, phase, timers, ... }
const incidents = new Map();
const auditEvents = [];
const MAX_AUDIT_EVENTS = 1000;
let autoRecoverySweepTimer = null;
let autoRecoveryStartupTimer = null;
let autoRecoverySweepRunning = false;

async function _persistAudit(event) {
  if (!event.companyId) return;
  await IpsAuditEvent.updateOne(
    { eventId: event.id },
    {
      $setOnInsert: {
        eventId: event.id,
        companyId: event.companyId,
        incidentId: event.incidentId || null,
        systemId: event.systemId || null,
        action: event.action,
        severity: event.severity,
        actor: event.actor,
        target: event.target,
        attackType: event.attackType || null,
        phase: event.phase || null,
        detail: event.detail,
        metadata: event.metadata || null,
        ts: new Date(event.ts),
      },
    },
    { upsert: true },
  );
}

function _audit(action, incOrPayload = {}, detail = '', persist = true) {
  const payload = incOrPayload || {};
  const event = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    ts: new Date().toISOString(),
    companyId: payload.companyId,
    incidentId: payload.incidentId,
    systemId: payload.systemId || null,
    action,
    severity: payload.severity || 'info',
    actor: payload.actor || 'IPS Engine',
    target: payload.srcIp || payload.target || '—',
    attackType: payload.attackType,
    phase: payload.phase,
    detail: detail || payload.description || payload.detail || action,
    metadata: payload.metadata || payload.manualOverride || null,
  };
  auditEvents.unshift(event);
  if (auditEvents.length > MAX_AUDIT_EVENTS) auditEvents.length = MAX_AUDIT_EVENTS;
  if (persist) {
    _persistAudit(event).catch(error => {
      console.error(`[IPS Audit] Mongo persistence failed: ${error.message}`);
    });
  }
  _emitEvent(event.companyId, 'ips:audit', event);
  return event;
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

// ── Email transport ───────────────────────────────────────────────────────────
let _transporter = null;
function _getTransporter() {
  if (_transporter) return _transporter;
  _transporter = nodemailer.createTransport({
    host:   process.env.SMTP_HOST || 'smtp.gmail.com',
    port:   parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  return _transporter;
}

async function _sendEmail({ to, subject, html }) {
  const recipients = Array.isArray(to) ? to.filter(Boolean) : to;
  if ((Array.isArray(recipients) && !recipients.length) || !recipients || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log(`[IPS Engine] Email skipped (SMTP not configured): ${subject}`);
    return false;
  }
  try {
    const result = await _getTransporter().sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: recipients,
      subject,
      html: html || `<pre>${escapeHtml(subject)}</pre>`,
    });
    if (result.rejected?.length || (Array.isArray(result.accepted) && !result.accepted.length)) {
      console.warn(`[IPS Engine] SMTP did not accept every recipient for: ${subject}`);
      return false;
    }
    console.log(`[IPS Engine] Email sent to ${Array.isArray(recipients) ? recipients.join(', ') : recipients}: ${subject}`);
    return true;
  } catch (err) {
    console.error(`[IPS Engine] Email failed: ${err.message}`);
    return false;
  }
}

function _recipientLabel(to) {
  return Array.isArray(to) ? to.filter(Boolean).join(', ') : String(to || '');
}

// ── IPS Webhook call (actual block/unblock) ───────────────────────────────────
function _ipsRequest(body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const parsed  = new URL(IPS_URL + '/webhook');
    const opts = {
      hostname: parsed.hostname,
      port:     parseInt(parsed.port || '80', 10),
      path:     '/webhook',
      method:   'POST',
      headers: {
        'Content-Type':     'application/json',
        'Content-Length':   Buffer.byteLength(payload),
        'X-Webhook-Secret': IPS_SECRET,
        'X-Company-ID':     body.company || '',
        'X-Company':        body.company || '',
      },
    };
    const req = http.request(opts, (res) => {
      let d = '';
      res.on('data', c => { d += c; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          if (res.statusCode >= 400) reject(new Error(parsed.message || `HTTP ${res.statusCode}`));
          else resolve(parsed);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('IPS request timeout')); });
    req.write(payload);
    req.end();
  });
}

// ── Incident key ──────────────────────────────────────────────────────────────
function _key(companyId, srcIp, attackType, systemId = null) {
  return `${companyId}|${systemId || "unassigned"}|${srcIp}|${attackType}`;
}

async function _resolveAdminRecipients({ companyId, systemId = null, fallback = null }) {
  const recipients = new Set();
  const add = value => {
    if (Array.isArray(value)) value.forEach(add);
    else if (value) recipients.add(String(value).trim().toLowerCase());
  };
  add(fallback);

  if (!companyId) {
    add(process.env.SMTP_USER);
    return [...recipients].filter(Boolean);
  }

  try {
    let departmentId = null;
    if (systemId) {
      const system = await System.findOne({ _id: systemId, companyId, isActive: true })
        .select('departmentId')
        .lean();
      departmentId = system?.departmentId || null;
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
    admins.forEach(admin => add(admin.email));
  } catch (error) {
    console.error(`[IPS Engine] Admin recipient lookup failed: ${error.message}`);
  }

  add(process.env.SMTP_USER);
  return [...recipients].filter(Boolean);
}

// ── HTML email templates ──────────────────────────────────────────────────────
function safeTemplateIncident(inc) {
  const safe = { ...inc };
  for (const key of ['attackType', 'srcIp', 'severity', 'incidentId', 'failureReason']) {
    safe[key] = escapeHtml(inc[key] || '');
  }
  return safe;
}

function _alertTpl(inc, remaining) {
  inc = safeTemplateIncident(inc);
  const elapsed = Math.round((Date.now() - inc.startedAt) / 1000);
  return {
    subject: `🚨 ATTACK ALERT [${inc.severity?.toUpperCase()}]: ${inc.attackType} from ${inc.srcIp}`,
    html: `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0e1a;color:#e2e8f0;border-radius:12px;border:2px solid #ef4444;overflow:hidden">
  <div style="background:#ef4444;padding:20px;text-align:center">
    <h1 style="margin:0;color:#fff;font-size:22px">🚨 ATTACK DETECTED</h1>
    <p style="margin:4px 0 0;color:#fca5a5;font-size:13px">IPS Engine — SOC4 • Alert Phase</p>
  </div>
  <div style="padding:24px">
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="padding:8px;color:#94a3b8;width:40%">Attack Type</td><td style="padding:8px;color:#f87171;font-weight:bold">${inc.attackType}</td></tr>
      <tr style="background:#0f172a"><td style="padding:8px;color:#94a3b8">Source IP</td><td style="padding:8px;color:#60a5fa;font-family:monospace">${inc.srcIp}</td></tr>
      <tr><td style="padding:8px;color:#94a3b8">Severity</td><td style="padding:8px;color:#f59e0b;font-weight:bold;text-transform:uppercase">${inc.severity}</td></tr>
      <tr style="background:#0f172a"><td style="padding:8px;color:#94a3b8">Block Status</td><td style="padding:8px;color:${inc.blockStatus==='failed'?'#f87171':'#34d399'}">${inc.blockStatus==='failed'?'❌ Block Failed — retries exhausted':'✅ Block Applied'}</td></tr>
      <tr><td style="padding:8px;color:#94a3b8">Elapsed</td><td style="padding:8px;color:#fbbf24">${elapsed}s since detection</td></tr>
      <tr style="background:#0f172a"><td style="padding:8px;color:#94a3b8">Isolation check in</td><td style="padding:8px;color:#ef4444;font-weight:bold">${Math.max(0,remaining)}s</td></tr>
    </table>
    <div style="margin-top:20px;padding:16px;background:#1a0a0e;border-radius:8px;border-left:4px solid #f59e0b">
      <p style="margin:0;color:#fbbf24;font-weight:bold">⚠️ Action Required</p>
      <p style="margin:8px 0 0;color:#94a3b8">No administrator action has been detected. Automatic isolation requires a fresh ongoing threat and a recent endpoint heartbeat after the configured response window. Remaining: <strong style="color:#ef4444">${Math.max(0,remaining)}s</strong>.</p>
    </div>
  </div>
</div>`,
  };
}

function _blockFailedTpl(inc, retries) {
  inc = safeTemplateIncident(inc);
  return {
    subject: `❌ BLOCK FAILED: ${inc.attackType} from ${inc.srcIp} — ${retries} retries exhausted`,
    html: `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0e1a;color:#e2e8f0;border-radius:12px;border:2px solid #f97316;overflow:hidden">
  <div style="background:#7c2d12;padding:20px;text-align:center">
    <h1 style="margin:0;color:#fff;font-size:22px">❌ BLOCK FAILED</h1>
    <p style="margin:4px 0 0;color:#fed7aa;font-size:13px">IPS retry exhausted — Isolation checks required</p>
  </div>
  <div style="padding:24px">
    <p style="color:#fb923c">The IPS server failed to block <strong>${inc.srcIp}</strong> after <strong>${retries} attempts</strong>.</p>
    <p style="color:#94a3b8">Reason: ${inc.failureReason || 'Unknown firewall error'}</p>
    <p style="color:#94a3b8">Attack Type: ${inc.attackType}</p>
    <div style="margin-top:16px;padding:16px;background:#1a0f0a;border-radius:8px;border-left:4px solid #ef4444">
      <p style="margin:0;color:#f87171;font-weight:bold">🔎 Isolation Verification</p>
      <p style="margin:8px 0 0;color:#94a3b8">Automatic isolation will only be requested if fresh ongoing threat activity, endpoint heartbeat and allow-rule checks pass. Missing block acknowledgement alone will not isolate an endpoint. A separate notification follows endpoint confirmation.</p>
    </div>
  </div>
</div>`,
  };
}

function _isolatedTpl(inc, reason = 'auto') {
  inc = safeTemplateIncident(inc);
  return {
    subject: `🔒 SYSTEM ${reason === 'auto' ? 'AUTO-' : 'MANUALLY '}ISOLATED — ${inc.attackType} from ${inc.srcIp}`,
    html: `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0e1a;color:#e2e8f0;border-radius:12px;border:2px solid #ef4444;overflow:hidden">
  <div style="background:#7f1d1d;padding:20px;text-align:center">
    <h1 style="margin:0;color:#fff;font-size:22px">🔒 SYSTEM ${reason === 'auto' ? 'AUTO-' : 'MANUALLY '}ISOLATED</h1>
    <p style="margin:4px 0 0;color:#fca5a5;font-size:13px">${reason === 'auto' ? 'Automatic IPS response confirmed by endpoint' : 'Admin isolation confirmed by endpoint'}</p>
  </div>
  <div style="padding:24px">
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="padding:8px;color:#94a3b8">Attack Type</td><td style="padding:8px;color:#f87171;font-weight:bold">${inc.attackType}</td></tr>
      <tr style="background:#0f172a"><td style="padding:8px;color:#94a3b8">Source IP</td><td style="padding:8px;color:#60a5fa;font-family:monospace">${inc.srcIp}</td></tr>
      <tr><td style="padding:8px;color:#94a3b8">Isolated At</td><td style="padding:8px;color:#e2e8f0">${new Date().toLocaleString()}</td></tr>
      <tr style="background:#0f172a"><td style="padding:8px;color:#94a3b8">Next Recovery Check</td><td style="padding:8px;color:#fbbf24">${Math.round(AUTO_RECOVER_DELAY_MS / 60000)} minutes after isolation</td></tr>
    </table>
    <div style="margin-top:16px;padding:16px;background:#0d2a1e;border-radius:8px;border-left:4px solid #22c55e">
      <p style="margin:0;color:#34d399;font-weight:bold">Recovery Steps</p>
      <p style="margin:8px 0 0;color:#94a3b8">Dashboard → IPS → Isolation Flow → Manual Unisolate</p>
    </div>
  </div>
</div>`,
  };
}

function _recoveredTpl(inc, reason = 'auto') {
  inc = safeTemplateIncident(inc);
  return {
    subject: `✅ SYSTEM RESTORED — ${inc.attackType} from ${inc.srcIp}`,
    html: `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0e1a;color:#e2e8f0;border-radius:12px;border:2px solid #22c55e;overflow:hidden">
  <div style="background:#14532d;padding:20px;text-align:center">
    <h1 style="margin:0;color:#fff;font-size:22px">✅ SYSTEM RESTORED</h1>
    <p style="margin:4px 0 0;color:#bbf7d0;font-size:13px">${reason === 'manual' ? 'Admin manually recovered' : 'Quiet-window checks passed — endpoint reconnection confirmed'}</p>
  </div>
  <div style="padding:24px">
    <p style="color:#34d399">The endpoint confirmed removal of network isolation. IP blocking is managed separately.</p>
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="padding:8px;color:#94a3b8">Attack</td><td style="padding:8px;color:#f87171">${inc.attackType}</td></tr>
      <tr style="background:#0f172a"><td style="padding:8px;color:#94a3b8">Source IP</td><td style="padding:8px;color:#60a5fa;font-family:monospace">${inc.srcIp}</td></tr>
      <tr><td style="padding:8px;color:#94a3b8">Recovery</td><td style="padding:8px;color:#34d399">${reason === 'manual' ? 'Admin Intervention' : `Auto-recovery (${Math.round(AUTO_RECOVER_DELAY_MS / 60000)} minute verification)`}</td></tr>
    </table>
  </div>
</div>`,
  };
}

// ── Core: Attempt to block via IPS (single attempt) ──────────────────────────
// Requires firewall enforcement or an endpoint ACK. Pending commands retry;
// exhausted retries request isolation. A whitelist match bypasses escalation.
async function _attemptBlock(srcIp, attackType, companyId, reason, source = 'Auto', systemId = null) {
  let IpsService;
  try { IpsService = require('./ips.service'); } catch (_) { IpsService = null; }

  if (IpsService) {
    const result = await IpsService.blockIP({
      ip:        srcIp,
      companyId,
      reason:    reason || `IPS Auto-block: ${attackType}`,
      blockedBy: source === 'Manual' ? 'analyst' : 'auto',
      systemId,
    });
    if (result?.whitelisted || result?.tiDeferred) return result;

    // ❌ Private or invalid IP — hard failure, throw so caller counts this attempt
    if (result?.reason === 'private/invalid IP') {
      throw new Error(`Cannot block private/invalid IP: ${srcIp}`);
    }

    // A DB record is only an audit trail.  A successful attempt requires a
    // real enforcement acknowledgement; otherwise retry, then verify whether isolation is justified.
    if (isAcceptedBlockResult(result)) {
      return result;
    }

    throw new Error(result?.webhook?.error || result?.reason || 'firewall enforcement was not acknowledged');
  }

  if (source !== 'Manual') return { ok: false, tiDeferred: true, reason: 'Automatic response service unavailable; verification cannot be bypassed' };
  // Explicit manual fallback only.
  return _ipsRequest({
    action:     'block',
    ip:         srcIp,
    reason:     reason || `IPS Auto-block: ${attackType}`,
    attackType,
    source,
    company:    companyId,
  });
}

async function _queueEndpointCommand(inc, command, reason, options = {}) {
  if (!inc?.systemId) {
    _audit('User Actions', inc, `Endpoint ${command} skipped: no target system was associated with this IDS alert`);
    return { queued: 0, confirmed: false, status: 'no-target' };
  }
  const { queueEndpointCommand } = require('./ips.service');
  const delivery = await queueEndpointCommand({
    companyId: inc.companyId,
    systemId: inc.systemId,
    command,
    reason: reason || inc.description || inc.attackType,
    srcIp: inc.srcIp,
    attackType: inc.attackType,
    ...options,
  });
  if (!delivery.queued && delivery.status === 'no-target') {
    _audit('User Actions', inc, `Endpoint ${command} skipped: target system was not found or inactive`);
    return delivery;
  }
  _audit('User Actions', inc,
    `Endpoint ${command} ${delivery.confirmed ? 'confirmed by agent' : delivery.status === 'deferred' ? 'deferred by safety checks' : delivery.status === 'failed' ? 'failed' : 'queued for agent heartbeat'}`,
  );
  return delivery;
}

// ── IPS Engine: Main entry point called by IDS alert receiver ─────────────────
// This is the ONLY function IDS should call. IDS NEVER calls _ipsRequest directly.
async function handleDetection({ companyId, srcIp, attackType, severity, adminEmail, description, forceBlock = false, systemId = null }) {
  const { normalizeIP, isPrivateIP, isWhitelistedForCompany } = require('./ips.service');
  srcIp = normalizeIP(srcIp);
  if (!srcIp || !companyId || isPrivateIP(srcIp)) {
    console.log(`[IPS Engine] Skipped reserved or invalid source IP: ${srcIp || 'missing'}`);
    return null;
  }
  if (!forceBlock && !AUTO_BLOCK_SEVERITIES.includes((severity || '').toLowerCase())) return;
  if (await isWhitelistedForCompany(srcIp, companyId)) {
    _audit('Block Bypassed', { companyId, srcIp, attackType, severity, systemId }, 'Active Firewall allow rule matched; IPS did not block or isolate this IP');
    return null;
  }
  attackType = resolveCanonicalAttackType(attackType, description);
  const notificationEmails = await _resolveAdminRecipients({ companyId, systemId, fallback: adminEmail });

  const incidentId = _key(companyId, srcIp, attackType, systemId);

  // De-duplicate: if already handling this incident, just touch last-seen
  if (incidents.has(incidentId)) {
    const existing = incidents.get(incidentId);
    if (existing.phase === 'verification_deferred' || (existing.phase === 'blocked' && existing.blockExpiresAt && new Date(existing.blockExpiresAt).getTime() <= Date.now())) {
      incidents.delete(incidentId);
    } else {
      existing.lastSeen = Date.now();
      if (!existing.systemId && systemId) existing.systemId = systemId;
      existing.adminEmail = [...new Set([
        ...(Array.isArray(existing.adminEmail) ? existing.adminEmail : [existing.adminEmail].filter(Boolean)),
        ...notificationEmails,
      ])];
      if (existing.phase === 'isolation_deferred') await _autoIsolate(incidentId);
      console.log(`[IPS Engine] Incident already active: ${incidentId}`);
      return existing;
    }
  }

  const incident = {
    incidentId,
    companyId,
    srcIp,
    attackType,
    severity:     severity || 'high',
    adminEmail:   notificationEmails,
    description:  description || `${attackType} from ${srcIp}`,
    systemId:     systemId || null,
    startedAt:    Date.now(),
    lastSeen:     Date.now(),
    phase:        'blocking',  // blocking → alerting → isolated → recovered
    blockStatus:  'pending',   // pending → success | failed
    blockAttempts: 0,
    failureReason: null,
    isolationApplied: false,
    manuallyIsolated: false,
    manuallyRecovered: false,
    timers: [],
  };

  incidents.set(incidentId, incident);
  console.log(`[IPS Engine] 🚨 New incident: ${incidentId}`);
  _audit('Attack Detected', incident, incident.description);
  _audit('Incident Created', incident, `Incident ${incidentId} created`);
  _audit('User Actions', incident, `Auto-block attack type selected: ${attackType}`);

  // ── Phase 1: Auto-block with retries ─────────────────────────────────────
  await _blockWithRetry(incidentId);

  return incident;
}

async function _blockWithRetry(incidentId) {
  const inc = incidents.get(incidentId);
  if (!inc || inc.phase === 'recovered') return;

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    if (inc.phase !== 'blocking' || incidents.get(incidentId) !== inc) return;
    inc.blockAttempts = attempt;
    inc.blockStatus   = 'pending';

    try {
      const result = await _attemptBlock(
        inc.srcIp,
        inc.attackType,
        inc.companyId,
        `IPS Auto-block (attempt ${attempt}/${MAX_RETRIES}): ${inc.attackType}`,
        'Auto',
        inc.systemId,
      );
      if (inc.phase !== 'blocking' || incidents.get(incidentId) !== inc) return;
      if (result?.whitelisted) {
        inc.phase = 'bypassed';
        inc.blockStatus = 'skipped';
        _audit('Block Bypassed', inc, result.reason || 'Active whitelist matched; isolation skipped');
        incidents.delete(incidentId);
        return;
      }
      if (result?.tiDeferred) {
        inc.phase = 'verification_deferred';
        inc.blockStatus = 'skipped';
        inc.failureReason = result.reason;
        _audit('Threat Verification Deferred', inc, result.reason);
        return;
      }

      const alreadyBlocked = result?.note === 'already blocked' || result?.reason === 'already blocked';
      // Success is an enforcement acknowledgement, never merely a DB record.
      const webhookOk = result?.webhookOk === true;
      const agentAccepted = result?.agentAccepted === true || result?.agentConfirmed === true;
      console.log(
        `[IPS Engine] ✅ Block ${alreadyBlocked ? '(already active)' : 'DB-recorded'}: ${inc.incidentId}` +
        (webhookOk || agentAccepted ? '' : ' [no firewall acknowledgement]'),
      );

      inc.blockStatus = 'success';
      inc.phase = ISOLATE_AFTER_SUCCESSFUL_BLOCK ? 'alerting' : 'blocked';
      inc.blockedAt = Date.now();
      inc.blockExpiresAt = result.expiresAt || null;
      _audit('User Actions', inc,
        `IPS block recorded on attempt ${attempt}/${MAX_RETRIES}` +
        (webhookOk || agentAccepted ? '' : ' (no firewall acknowledgement)'),
      );

      // Emit to dashboard sockets
      _emitEvent(inc.companyId, 'ips:blocked', {
        incidentId: inc.incidentId,
        srcIp: inc.srcIp,
        attackType: inc.attackType,
        severity: inc.severity,
        source: 'Auto',
        blockAttempts: attempt,
        webhookOk,
        agentAccepted,
        agentConfirmed: result?.agentConfirmed === true,
      });
      if (webhookOk || agentAccepted) {
        _emitEvent(inc.companyId, 'ips:block', {
          srcIp: inc.srcIp,
          attackType: inc.attackType,
          severity: inc.severity,
          incidentId: inc.incidentId,
        });
      }

      if (ISOLATE_AFTER_SUCCESSFUL_BLOCK) {
        _startAlertPhase(incidentId);
      } else {
        _audit('Block Confirmed', inc,
          'IP block applied successfully. Endpoint isolation skipped.',
        );
      }
      return; // ← exit loop on first success
    } catch (err) {
      if (inc.phase !== 'blocking' || incidents.get(incidentId) !== inc) return;
      // Only a real exception (e.g. private IP, DB write failure) counts as failure
      console.error(`[IPS Engine] ❌ Block attempt ${attempt}/${MAX_RETRIES} truly failed: ${err.message}`);
      inc.failureReason = err.message;

      if (attempt < MAX_RETRIES) {
        await new Promise(r => setTimeout(r, RETRY_DELAY_MS));
        if (!incidents.has(incidentId)) return; // Incident was cleared
      }
    }
  }

  if (inc.phase !== 'blocking' || incidents.get(incidentId) !== inc) return;

  // All retries truly exhausted (e.g. private IP, DB unreachable)
  console.error(`[IPS Engine] 💀 All ${MAX_RETRIES} block attempts truly failed for ${incidentId}`);
  inc.blockStatus = 'failed';
  inc.phase = 'alerting';

  // Emit failure event
  _emitEvent(inc.companyId, 'ips:blockFailed', {
    incidentId: inc.incidentId,
    srcIp: inc.srcIp,
    attackType: inc.attackType,
    severity: inc.severity,
    reason: inc.failureReason,
    attempts: MAX_RETRIES,
  });

  // Notify admin
  if (inc.adminEmail) {
    const sent = await _sendEmail({ to: inc.adminEmail, ..._blockFailedTpl(inc, MAX_RETRIES) });
    _audit(sent ? 'Email Sent' : 'Email Failed', inc, `Block failed notification ${sent ? 'sent' : 'failed'} to ${_recipientLabel(inc.adminEmail)}`);
  }

  // Missing enforcement ACK alone is insufficient evidence for isolation.
  await _autoIsolate(incidentId);
}

// ── Phase 2: Alert Phase — email every ALERT_INTERVAL_MS until auto-isolate ──
function _startAlertPhase(incidentId) {
  const inc = incidents.get(incidentId);
  if (!inc || inc.phase === 'isolated' || inc.phase === 'recovered') return;
  inc.phase = 'alerting';

  // Send first alert immediately
  if (inc.adminEmail) {
    const remaining = Math.round(AUTO_ISOLATE_DELAY_MS / 1000);
    _sendEmail({ to: inc.adminEmail, ..._alertTpl(inc, remaining) })
      .then(sent => _audit(sent ? 'Email Sent' : 'Email Failed', inc, `Initial critical attack notification ${sent ? 'sent' : 'failed'} to ${_recipientLabel(inc.adminEmail)}`));
  }

  // Repeat alerts
  const alertTimer = setInterval(() => {
    const current = incidents.get(incidentId);
    if (!current || current.phase !== 'alerting') { clearInterval(alertTimer); return; }

    const remaining = Math.round(Math.max(0, AUTO_ISOLATE_DELAY_MS - (Date.now() - current.startedAt)) / 1000);
    if (current.adminEmail) {
      _sendEmail({ to: current.adminEmail, ..._alertTpl(current, remaining) })
        .then(sent => {
          _audit(sent ? 'Reminder Sent' : 'Email Failed', current,
            `Reminder ${sent ? 'accepted by SMTP' : 'failed/skipped'} to ${_recipientLabel(current.adminEmail)}. Isolation check in ${remaining}s`);
        });
    }
  }, ALERT_INTERVAL_MS);
  inc.timers.push(alertTimer);

  // Auto-isolate after the configured response window without admin action.
  const autoIsolateTimer = setTimeout(() => {
    const current = incidents.get(incidentId);
    if (!current || current.manuallyIsolated || current.phase !== 'alerting') return;
    return _autoIsolate(incidentId);
  }, AUTO_ISOLATE_DELAY_MS);
  inc.timers.push(autoIsolateTimer);
}

// ── Phase 3: Auto-Isolation ──────────────────────────────────────────────────
async function _confirmIsolation(inc, reason = 'auto') {
  if (!inc || inc.isolationApplied === true) return inc;
  inc.phase = 'isolated';
  inc.isolationApplied = true;
  inc.isolatedAt = Date.now();
  if (inc.systemId) {
    await System.updateOne(
      { _id: inc.systemId, companyId: inc.companyId },
      { $set: {
        isolationSourceIp: inc.srcIp || null,
        isolationAttackType: inc.attackType || null,
        isolationLastThreatAt: new Date(inc.isolatedAt),
        isolationAutoRecoverAt: new Date(inc.isolatedAt + AUTO_RECOVER_DELAY_MS),
        isolationRecoveryAttempts: Number(inc.recoveryAttempts || 0),
      } },
    ).catch(error => console.warn(`[IPS Engine] Failed to persist recovery deadline: ${error.message}`));
  }
  _audit('Isolation Completed', inc, 'Endpoint agent confirmed network isolation');
  _emitEvent(inc.companyId, 'ips:isolated', {
    incidentId: inc.incidentId,
    systemId: inc.systemId,
    srcIp: inc.srcIp,
    attackType: inc.attackType,
    severity: inc.severity,
    reason,
    blockStatus: inc.blockStatus,
    isolationStatus: 'isolated',
  });
  if (inc.adminEmail && !inc.isolationEmailSent) {
    inc.isolationEmailSent = true;
    const sent = await _sendEmail({ to: inc.adminEmail, ..._isolatedTpl(inc, reason) });
    _audit(sent ? 'Email Sent' : 'Email Failed', inc, `Isolation notification ${sent ? 'sent' : 'failed'} to ${_recipientLabel(inc.adminEmail)}`);
  }
  // Recovery is driven exclusively by the durable, database-backed sweep.
  return inc;
}

async function _autoIsolate(incidentId) {
  const inc = incidents.get(incidentId);
  if (!inc || inc.manuallyRecovered || inc.manuallyIsolated || !['blocking', 'alerting', 'isolation_deferred'].includes(inc.phase)) return;
  inc.phase = 'isolation_checking';
  _audit('Isolation Check', inc, 'Checking fresh threat, endpoint heartbeat, allow rules and block acknowledgement');
  const decision = await isolationGuard.checkAutoIsolation({ ...inc,
    requireUnconfirmedBlock: !ISOLATE_AFTER_SUCCESSFUL_BLOCK });
  if (incidents.get(incidentId) !== inc || inc.phase !== 'isolation_checking') return inc;
  if (!ISOLATE_AFTER_SUCCESSFUL_BLOCK && (inc.blockStatus === 'success' || inc.agentBlockStatus === 'confirmed')) {
    decision.allowed = false;
    decision.reason = 'source IP block was confirmed before isolation';
  }
  if (!decision.allowed) return _deferIsolation(inc, decision.reason);
  inc.isolationDecision = { ...decision, checkedAt: new Date().toISOString() };
  _audit('Auto Isolation', { ...inc, metadata: decision.autoIsolation }, 'Fresh ongoing threat verified; requesting endpoint isolation');

  // Clear alert timers
  inc.timers.forEach(t => { clearInterval(t); clearTimeout(t); });
  inc.timers = [];

  inc.phase = 'isolation_pending';
  inc.isolationApplied = false;
  let delivery;
  try {
    delivery = await _queueEndpointCommand(inc, 'isolate', `Automatic IPS isolation: ${inc.attackType}`, {
      autoIsolation: decision.autoIsolation,
      automatic: true, threatVerification: decision.threatVerification,
      isStillCurrent: () => incidents.get(incidentId) === inc && inc.phase === 'isolation_pending'
        && !inc.manuallyRecovered && !inc.manuallyIsolated,
    });
  } catch (error) {
    if (inc.phase === 'isolation_pending' && !inc.manuallyRecovered && !inc.manuallyIsolated) {
      return _deferIsolation(inc, `command verification/delivery unavailable: ${error.message}`);
    }
    return inc;
  }
  // Socket ACKs and manual recovery can complete while delivery is awaited.
  if (incidents.get(incidentId) !== inc || inc.phase !== 'isolation_pending' || inc.manuallyRecovered || inc.manuallyIsolated) return inc;
  inc.isolationCommandId = delivery.commandId || null;
  if (delivery.status === 'deferred') return _deferIsolation(inc, delivery.message);
  if (delivery.confirmed) return _confirmIsolation(inc, 'auto');
  if (delivery.status === 'failed' || delivery.status === 'no-target') {
    inc.phase = 'isolation_failed';
    inc.failureReason = delivery.message || 'Endpoint isolation could not be delivered';
    await _notifyCommandFailure(inc, 'isolate', inc.failureReason, delivery.commandId);
    _emitEvent(inc.companyId, 'ips:isolationFailed', {
      incidentId, systemId: inc.systemId, srcIp: inc.srcIp,
      attackType: inc.attackType, reason: inc.failureReason,
    });
    return inc;
  }
  _audit('Isolation Pending', inc, 'Isolation command is queued; waiting for endpoint acknowledgement');
  _emitEvent(inc.companyId, 'ips:isolationPending', {
    incidentId, systemId: inc.systemId, srcIp: inc.srcIp,
    attackType: inc.attackType, commandId: inc.isolationCommandId,
  });
  return inc;
}

function _deferIsolation(inc, reason) {
  inc.timers?.forEach(timer => { clearInterval(timer); clearTimeout(timer); });
  inc.timers = [];
  inc.phase = 'isolation_deferred';
  inc.isolationApplied = false;
  inc.isolationDecision = { allowed: false, reason, checkedAt: new Date().toISOString() };
  _audit('Isolation Deferred', { ...inc, metadata: inc.isolationDecision }, reason);
  _emitEvent(inc.companyId, 'ips:isolationDeferred', { incidentId: inc.incidentId,
    systemId: inc.systemId, srcIp: inc.srcIp, reason });
  return inc;
}

// ── Phase 4: Auto-Recovery after the configured verification window ──────────
async function _confirmRecovery(inc, reason = 'auto', notify = true) {
  if (!inc || inc.recoveryConfirmed === true) return inc;
  inc.timers?.forEach(timer => { clearInterval(timer); clearTimeout(timer); });
  inc.timers = [];
  inc.recoveryConfirmed = true;
  inc.phase = 'recovered';
  inc.recoveredAt = Date.now();
  inc.isolationApplied = false;
  _audit('Server Restored', inc, 'Endpoint agent confirmed removal of network isolation');
  _emitEvent(inc.companyId, 'ips:recovered', {
    incidentId: inc.incidentId, systemId: inc.systemId, srcIp: inc.srcIp,
    attackType: inc.attackType, reason, isolationStatus: 'none',
  });
  if (notify && inc.adminEmail && !inc.recoveryEmailSent) {
    inc.recoveryEmailSent = true;
    const sent = await _sendEmail({ to: inc.adminEmail, ..._recoveredTpl(inc, reason) });
    _audit(sent ? 'Email Sent' : 'Email Failed', inc, `Recovery notification ${sent ? 'sent' : 'failed'} to ${_recipientLabel(inc.adminEmail)}`);
  }
  _audit('Incident Closed', inc, 'Incident closed after confirmed endpoint recovery');
  incidents.delete(inc.incidentId);
  return inc;
}

async function sweepPendingAutoRecoveries(nowValue = new Date()) {
  if (autoRecoverySweepRunning) return { checked: 0, recovered: 0, deferred: 0, pending: 0 };
  autoRecoverySweepRunning = true;
  const now = new Date(nowValue);
  const legacyCutoff = new Date(now.getTime() - AUTO_RECOVER_DELAY_MS);
  const result = { checked: 0, recovered: 0, deferred: 0, pending: 0, failed: 0 };
  try {
    const systems = await System.find({
      isActive: { $ne: false },
      isIsolated: true,
      // A failed reconnect still means the endpoint is isolated. Keep it in
      // the durable recovery loop so a transient agent/firewall failure does
      // not require a manual database repair.
      isolationStatus: { $in: ['isolated', 'failed'] },
      $or: [
        { isolationAutoRecoverAt: { $lte: now } },
        { isolationAutoRecoverAt: null, isolatedAt: { $lte: legacyCutoff } },
        { isolationAutoRecoverAt: { $exists: false }, isolatedAt: { $lte: legacyCutoff } },
      ],
    }).limit(100).lean();

    for (const system of systems) {
      result.checked += 1;
      // No telemetry from an offline agent is not evidence that it is safe.
      const heartbeatAt = new Date(system.lastSeen || 0).getTime();
      if (!Number.isFinite(heartbeatAt) || heartbeatAt < now.getTime() - Math.min(AUTO_RECOVER_DELAY_MS, 120000)) {
        result.deferred += 1;
        continue;
      }
      const baselineValue = system.isolationLastThreatAt || system.isolatedAt || legacyCutoff;
      // Only activity inside the current quiet window should defer recovery.
      // This avoids a stale alert found after a long backend outage causing a
      // misleading deferral to a deadline that is already in the past.
      const baseline = new Date(Math.max(
        new Date(baselineValue).getTime(),
        now.getTime() - AUTO_RECOVER_DELAY_MS,
      ));
      const related = [{ systemId: system._id }];
      if (system.isolationSourceIp) related.push({ srcip: system.isolationSourceIp });
      const latestThreat = await Alert.findOne({
        companyId: system.companyId,
        createdAt: { $gt: baseline, $lte: now },
        severity: { $in: ['high', 'critical', 'HIGH', 'CRITICAL'] },
        isSynthetic: { $ne: true },
        event_category: { $ne: 'ips_action' },
        $or: related,
      }).sort({ createdAt: -1 }).select('createdAt srcip description').lean();

      if (latestThreat) {
        const nextCheck = new Date(new Date(latestThreat.createdAt).getTime() + AUTO_RECOVER_DELAY_MS);
        await System.updateOne({ _id: system._id, isIsolated: true }, {
          $set: { isolationLastThreatAt: latestThreat.createdAt, isolationAutoRecoverAt: nextCheck },
          $inc: { isolationRecoveryAttempts: 1 },
        });
        _audit('Attack Still Active', {
          companyId: system.companyId, systemId: system._id,
          srcIp: system.isolationSourceIp || latestThreat.srcip,
          attackType: system.isolationAttackType || 'Endpoint threat', phase: 'isolated',
        }, `Auto-unisolate deferred until ${nextCheck.toISOString()}; recent high/critical activity remains`);
        const event = { companyId: system.companyId, systemId: system._id,
          srcIp: system.isolationSourceIp || latestThreat.srcip, attackType: system.isolationAttackType || 'Endpoint threat' };
        const recipients = await _resolveAdminRecipients(event);
        const sent = await _sendEmail({ to: recipients,
          subject: `Auto-unisolation deferred: ${system.name || system._id}`,
          html: `<p>Recent high/critical activity remains. Network isolation is retained.</p><p>Next check after ${escapeHtml(nextCheck.toISOString())}.</p>` });
        _audit(sent ? 'Email Sent' : 'Email Failed', event, `Recovery deferral notification ${sent ? 'accepted by SMTP' : 'failed/skipped'} to ${_recipientLabel(recipients)}`);
        result.deferred += 1;
        continue;
      }

      _audit('Recovery Check', {
        companyId: system.companyId, systemId: system._id,
        srcIp: system.isolationSourceIp || system.ip,
        attackType: system.isolationAttackType || 'Endpoint isolation', phase: 'recovery_pending',
      }, 'Durable 20 minute auto-unisolate verification passed');
      const { queueEndpointCommand } = require('./ips.service');
      const delivery = await queueEndpointCommand({
        companyId: system.companyId,
        systemId: system._id,
        command: 'reconnect',
        reason: 'Automatic recovery after 20 minutes without new high/critical activity',
      });
      if (delivery.confirmed) result.recovered += 1;
      else if (delivery.status === 'failed' || delivery.status === 'no-target') result.failed += 1;
      else result.pending += 1;
      if (!delivery.confirmed) _audit(delivery.status === 'failed' ? 'Recovery Failed' : 'Recovery Pending', {
        companyId: system.companyId, systemId: system._id,
        srcIp: system.isolationSourceIp || system.ip,
        attackType: system.isolationAttackType || 'Endpoint isolation',
        phase: delivery.confirmed ? 'recovered' : delivery.status === 'failed' ? 'recovery_failed' : 'recovery_pending',
      }, delivery.confirmed
        ? 'Endpoint agent confirmed automatic network restoration'
        : delivery.message || 'Reconnect command queued for agent acknowledgement');
    }
    return result;
  } finally {
    autoRecoverySweepRunning = false;
  }
}

function startAutoRecoverySweeper(intervalMs = 60 * 1000) {
  if (autoRecoverySweepTimer) return autoRecoverySweepTimer;
  const run = () => sweepPendingAutoRecoveries().catch(error => {
    console.error(`[IPS Engine] Auto-recovery sweep failed: ${error.message}`);
  });
  autoRecoveryStartupTimer = setTimeout(run, 5000);
  autoRecoveryStartupTimer.unref?.();
  autoRecoverySweepTimer = setInterval(run, Math.max(1000, Number(intervalMs) || 60000));
  autoRecoverySweepTimer.unref?.();
  return autoRecoverySweepTimer;
}

function stopAutoRecoverySweeper() {
  if (autoRecoveryStartupTimer) clearTimeout(autoRecoveryStartupTimer);
  autoRecoveryStartupTimer = null;
  if (autoRecoverySweepTimer) clearInterval(autoRecoverySweepTimer);
  autoRecoverySweepTimer = null;
}

// ── Admin: Manual isolation ───────────────────────────────────────────────────
async function manualIsolate({ companyId, srcIp, attackType, adminEmail, systemId = null }) {
  attackType = resolveCanonicalAttackType(attackType);
  const notificationEmails = await _resolveAdminRecipients({ companyId, systemId, fallback: adminEmail });
  const incidentId = _key(companyId, srcIp, attackType, systemId);
  let inc = incidents.get(incidentId);
  _audit('Manual Override Requested', { companyId, incidentId, srcIp, attackType, severity: 'manual', actor: 'Admin' }, 'Administrator requested manual isolation');

  if (!inc) {
    // Create a minimal incident record for tracking
    inc = {
      incidentId, companyId, srcIp, attackType, systemId,
      severity: 'manual', adminEmail: notificationEmails,
      startedAt: Date.now(), lastSeen: Date.now(),
      phase: 'alerting', blockStatus: 'pending',
      isolationApplied: false, manuallyIsolated: false,
      timers: [],
    };
    incidents.set(incidentId, inc);
  }

  // Clear any alert timers
  inc.timers.forEach(t => { clearInterval(t); clearTimeout(t); });
  inc.timers = [];
  inc.manuallyIsolated = true;
  inc.phase = 'isolation_pending';
  inc.isolationApplied = false;
  if (!inc.systemId && systemId) inc.systemId = systemId;
  _audit('Manual Override Approved', inc, 'Manual isolation approved');

  // Block via IPS
  try {
    const blockResult = await _attemptBlock(srcIp, attackType || 'Manual isolation', companyId, 'Manual isolation by admin', 'Manual', systemId);
    inc.blockStatus = blockResult?.whitelisted ? 'skipped' : 'success';
  } catch (e) {
    console.warn(`[IPS Engine] Manual block failed: ${e.message}`);
    inc.blockStatus = 'failed';
  }

  const delivery = await _queueEndpointCommand(inc, 'isolate', `Manual IPS isolation: ${attackType}`);
  inc.isolationCommandId = delivery.commandId || null;
  if (delivery.confirmed) {
    await _confirmIsolation(inc, 'manual');
  } else if (delivery.status === 'failed' || delivery.status === 'no-target') {
    inc.phase = 'isolation_failed';
    inc.failureReason = delivery.message || 'Endpoint isolation could not be delivered';
    await _notifyCommandFailure(inc, 'isolate', inc.failureReason, delivery.commandId);
  } else {
    _audit('Isolation Pending', inc, 'Manual isolation is queued; waiting for endpoint acknowledgement');
  }
  return inc;
}

// ── Admin: Manual recovery ────────────────────────────────────────────────────
async function manualRecover({ companyId, srcIp, attackType, adminEmail, systemId = null }) {
  attackType = resolveCanonicalAttackType(attackType);
  const notificationEmails = await _resolveAdminRecipients({ companyId, systemId, fallback: adminEmail });
  const incidentId = _key(companyId, srcIp, attackType, systemId);
  let inc = incidents.get(incidentId);
  if (!inc) {
    inc = { incidentId, companyId, srcIp, attackType, systemId, adminEmail: notificationEmails,
      startedAt: Date.now(), lastSeen: Date.now(), severity: 'manual', timers: [], phase: 'recovery_pending' };
    incidents.set(incidentId, inc);
  }
  _audit('Manual Override Requested', { companyId, incidentId, srcIp, attackType, severity: 'manual', actor: 'Admin' }, 'Administrator requested manual recovery');

  if (inc) {
    if (!inc.systemId && systemId) inc.systemId = systemId;
    inc.timers.forEach(t => { clearInterval(t); clearTimeout(t); });
    inc.timers = [];
    inc.manuallyRecovered = true;
    inc.phase = 'recovery_pending';
    _audit('Checklist Submitted', inc, 'Manual recovery checklist accepted');
    _audit('Manual Override Approved', inc, 'Manual recovery approved');
  }

  // Unisolation restores endpoint connectivity. IP blocks are removed only
  // through an explicit unblock action or their own TTL lifecycle.

  const recoveryTarget = inc || { companyId, incidentId, srcIp, attackType, systemId, severity: 'manual' };
  const delivery = await _queueEndpointCommand(recoveryTarget, 'reconnect', `Manual IPS recovery: ${attackType}`);
  recoveryTarget.recoveryCommandId = delivery.commandId || null;
  if (inc && delivery.confirmed) {
    await _confirmRecovery(inc, 'manual');
  } else if (inc && (delivery.status === 'failed' || delivery.status === 'no-target')) {
    inc.phase = 'recovery_failed';
    inc.failureReason = delivery.message || 'Endpoint recovery could not be delivered';
    await _notifyCommandFailure(inc, 'reconnect', inc.failureReason, delivery.commandId);
  } else if (inc) {
    _audit('Recovery Pending', inc, 'Manual reconnect queued; waiting for endpoint acknowledgement');
  }
  return inc || { incidentId, companyId, srcIp, attackType, phase: delivery.confirmed ? 'recovered' : 'recovery_pending' };
}

async function _notifyCommandFailure(inc, command, message, commandId) {
  const key = `${command}:${commandId || ''}:${message}`;
  if (inc.failureNotificationKey === key) return;
  inc.failureNotificationKey = key;
  const action = command === 'isolate' ? 'Isolation Failed' : 'Recovery Failed';
  _audit(action, inc, message);
  const recipients = inc.adminEmail || await _resolveAdminRecipients(inc);
  const sent = await _sendEmail({ to: recipients, subject: `${action}: ${inc.systemId || inc.srcIp}`,
    html: `<p>${escapeHtml(message)}</p><p>Endpoint confirmation failed. Review Isolation Flow before retrying.</p>` });
  _audit(sent ? 'Email Sent' : 'Email Failed', inc, `${action} notification ${sent ? 'accepted by SMTP' : 'failed/skipped'} to ${_recipientLabel(recipients)}`);
}

function releaseBlockedIncidents({ companyId, ip }) {
  for (const [id, inc] of incidents) {
    if (String(inc.companyId) === String(companyId) && inc.srcIp === ip && inc.phase === 'blocked') {
      _audit('Incident Closed', inc, 'IP unblock requested; future detections will be evaluated again');
      incidents.delete(id);
    }
  }
}

async function handleAgentCommandResult({ companyId, systemId, commandId, command, ok, message, reason, srcIp, attackType, deferred = false }) {
  const candidates = [...incidents.values()].filter(inc =>
    String(inc.companyId) === String(companyId) && String(inc.systemId || '') === String(systemId || '')
  );
  if (command === 'block_ip') {
    candidates.filter(inc => inc.srcIp === srcIp).forEach(inc => {
      inc.agentBlockStatus = ok ? 'confirmed' : 'failed';
      inc.agentBlockMessage = message || '';
    });
    return;
  }
  if (!['isolate', 'reconnect'].includes(command)) return;
  const mode = /^Automatic /i.test(String(reason || '')) ? 'auto' : 'manual';
  const matching = command === 'reconnect' && ok
    ? candidates // reconnection restores this endpoint, not just one attack incident
    : candidates.filter(item => command === 'isolate'
      ? item.isolationCommandId === commandId || (!item.isolationCommandId && item.phase === 'isolation_pending')
      : item.recoveryCommandId === commandId || (!item.recoveryCommandId && item.phase === 'recovery_pending'));
  if (command === 'isolate' && deferred && !ok) {
    const automaticMatches = matching.filter(inc => !inc.manuallyRecovered && !inc.manuallyIsolated);
    automaticMatches.forEach(inc => _deferIsolation(inc, message));
    if (!automaticMatches.length) _audit('Isolation Deferred', { companyId, systemId, srcIp, attackType,
      metadata: { commandId } }, message);
    return;
  }
  if (!matching.length) {
    // Manual system routes and recovery after restart have no in-memory incident.
    // recordAgentCommandResult durably deduplicates the ACK before reaching here.
    const event = { companyId, systemId, srcIp: srcIp || systemId, attackType: attackType || 'Endpoint isolation',
      severity: ok ? 'info' : 'high', metadata: { commandId, command, mode } };
    const action = command === 'isolate'
      ? (ok ? 'Isolation Completed' : 'Isolation Failed')
      : (ok ? 'Server Restored' : 'Recovery Failed');
    _audit(action, event, message || `Endpoint ${command} ${ok ? 'confirmed' : 'failed'}`);
    const recipients = await _resolveAdminRecipients({ companyId, systemId });
    const template = ok
      ? (command === 'isolate' ? _isolatedTpl(event, mode) : _recoveredTpl(event, mode))
      : { subject: `${action}: ${systemId}`, html: `<p>${escapeHtml(message || action)}</p>` };
    const sent = await _sendEmail({ to: recipients, ...template });
    _audit(sent ? 'Email Sent' : 'Email Failed', event,
      `${action} notification ${sent ? 'accepted by SMTP' : 'failed/skipped'} to ${_recipientLabel(recipients)}`);
    return;
  }
  for (const [index, inc] of matching.entries()) {
    if (command === 'isolate') {
      inc.isolationCommandId = commandId;
      if (ok) await _confirmIsolation(inc, mode);
      else {
        inc.phase = 'isolation_failed';
        inc.failureReason = message || 'Endpoint agent rejected isolation';
        await _notifyCommandFailure(inc, command, inc.failureReason, commandId);
        _emitEvent(inc.companyId, 'ips:isolationFailed', { incidentId: inc.incidentId, systemId,
          srcIp: inc.srcIp, attackType: inc.attackType, reason: inc.failureReason });
      }
    } else {
      inc.recoveryCommandId = commandId;
      if (ok) await _confirmRecovery(inc, mode, index === 0);
      else {
        inc.phase = 'recovery_failed';
        inc.failureReason = message || 'Endpoint agent rejected reconnect';
        await _notifyCommandFailure(inc, command, inc.failureReason, commandId);
      }
    }
  }
}

// ── Event emitter (uses global io set by server.js) ───────────────────────────
function _emitEvent(companyId, event, payload) {
  try {
    const io = global._ipsEngineIO;
    if (io) {
      io.to(`company:${companyId}`).emit(event, payload);
      io.to('superadmin').emit(event, payload);
    }
  } catch {}
}

// ── Attach Socket.IO instance (called once from server.js) ───────────────────
function attachIO(io) {
  global._ipsEngineIO = io;
  console.log('[IPS Engine] Socket.IO attached ✅');
}

// ── List active incidents ─────────────────────────────────────────────────────
function getIncidents(companyId = null) {
  const result = [];
  for (const inc of incidents.values()) {
    if (companyId && inc.companyId !== companyId) continue;
    result.push({
      incidentId:       inc.incidentId,
      companyId:        inc.companyId,
      systemId:         inc.systemId || null,
      srcIp:            inc.srcIp,
      attackType:       inc.attackType,
      severity:         inc.severity,
      phase:            inc.phase,
      blockStatus:      inc.blockStatus,
      blockAttempts:    inc.blockAttempts,
      recoveryAttempts: inc.recoveryAttempts || 0,
      isolationApplied: inc.isolationApplied,
      isolationStatus:  inc.phase === 'isolated' ? 'isolated'
        : inc.phase === 'isolation_pending' ? 'pending'
          : inc.phase === 'isolation_failed' ? 'failed'
            : inc.phase === 'recovery_pending' ? 'reconnecting' : 'none',
      isolationCommandId: inc.isolationCommandId || null,
      isolationDecision: inc.isolationDecision || null,
      recoveryCommandId: inc.recoveryCommandId || null,
      failureReason:     inc.failureReason || null,
      manuallyIsolated: inc.manuallyIsolated,
      startedAt:        new Date(inc.startedAt).toISOString(),
      lastSeen:         new Date(inc.lastSeen).toISOString(),
      elapsedMs:        Date.now() - inc.startedAt,
      autoIsolateRemainingMs: Math.max(0, AUTO_ISOLATE_DELAY_MS - (Date.now() - inc.startedAt)),
    });
  }
  return result;
}

async function getAuditEvents(companyId = null, limit = 300) {
  const safeLimit = Math.min(1000, Math.max(1, Number(limit) || 300));
  try {
    const query = companyId ? { companyId } : {};
    const ipsRows = await IpsAuditEvent.find(query)
      .sort({ ts: -1 })
      .limit(safeLimit)
      .lean();

    const ipsEvents = ipsRows.map(row => ({
      id: row.eventId || row._id.toString(),
      ts: row.ts,
      companyId: row.companyId,
      incidentId: row.incidentId,
      systemId: row.systemId,
      action: row.action,
      severity: row.severity,
      actor: row.actor,
      target: row.target,
      attackType: row.attackType,
      phase: row.phase,
      detail: row.detail,
      metadata: row.metadata,
    }));

    return ipsEvents;
  } catch (error) {
    console.error(`[IPS Audit] Mongo read failed, using memory fallback: ${error.message}`);
    return auditEvents
      .filter(event => !companyId || String(event.companyId || '') === String(companyId))
      .slice(0, safeLimit);
  }
}

async function recordAuditEvent(event = {}) {
  const recorded = _audit(event.action || 'User Actions', {
    companyId: event.companyId,
    incidentId: event.incidentId,
    srcIp: event.srcIp,
    target: event.target,
    severity: event.severity || 'info',
    actor: event.actor || 'Admin',
    attackType: event.attackType,
    phase: event.phase,
    description: event.detail,
    systemId: event.systemId,
    metadata: event.metadata || event.manualOverride,
  }, event.detail || event.action || 'User action', false);
  await _persistAudit(recorded);
  let emailSent = null;
  let emailTo = null;
  if (event.action === 'Manual Override Approved' || event.emailSubject) {
    emailTo = Array.isArray(event.emailTo)
      ? (event.emailTo.length ? event.emailTo : (process.env.SMTP_USER || null))
      : (event.emailTo || process.env.SMTP_USER || null);
    const recipientLabel = Array.isArray(emailTo) ? emailTo.join(', ') : emailTo;
    emailSent = await _sendEmail({
      to: emailTo,
      subject: event.emailSubject || 'Manual Override Approved',
      html: `<pre>${escapeHtml(event.emailMessage || event.detail || 'Administrator approved the requested action. Endpoint confirmation is reported separately.')}</pre>`,
    });
    _audit(
      emailSent ? 'Email Sent' : 'Email Failed',
      {
        companyId: event.companyId,
        incidentId: event.incidentId,
        systemId: event.systemId,
        srcIp: event.srcIp,
        target: recipientLabel || event.target,
        severity: emailSent ? 'info' : 'high',
        actor: 'IPS Engine',
      },
      emailSent
        ? `Manual Override Approved email sent to ${recipientLabel}`
        : `Manual Override Approved email delivery failed for ${recipientLabel || 'admin: no email configured'}`,
    );
  }
  return { ...recorded, emailSent, emailTo };
}

module.exports = {
  handleDetection,
  manualIsolate,
  manualRecover,
  getIncidents,
  getAuditEvents,
  recordAuditEvent,
  handleAgentCommandResult,
  releaseBlockedIncidents,
  resolveAdminRecipients: _resolveAdminRecipients,
  attachIO,
  sweepPendingAutoRecoveries,
  startAutoRecoverySweeper,
  stopAutoRecoverySweeper,
  MAX_RETRIES,
  AUTO_ISOLATE_DELAY_MS,
  AUTO_RECOVER_DELAY_MS,
  resolveCanonicalAttackType,
  CANONICAL_ATTACK_TYPES,
  _test: { isAcceptedBlockResult, incidentKey: _key, resolveAdminRecipients: _resolveAdminRecipients, escapeHtml, autoIsolate: _autoIsolate },
};
