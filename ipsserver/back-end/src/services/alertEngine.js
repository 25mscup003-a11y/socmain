/**
 * Alert & Escalation Engine — SOC4 IPS Server v4.0
 * ==================================================
 * Manages the full lifecycle of a detected attack:
 *
 *  Phase 1 — Alert Loop (0–2 min):
 *    Send email every 20 seconds for 2 minutes (6 alerts max).
 *    Include IP, MAC, attackType, behavior details.
 *
 *  Phase 2 — Auto-Isolation (at 2 min if not stopped):
 *    Send final "isolation imminent" email.
 *    Call /isolate on the affected agent/server.
 *    Record isolation log.
 *
 *  Phase 3 — Auto-Recovery Check (after 15 min):
 *    Re-evaluate attack status.
 *    If safe → unisolate and send recovery email.
 *    If still active → extend isolation and re-alert.
 *
 *  Manual Override:
 *    Admins can unblock/unisolate at any time via a consent-gated action.
 *    Consent form is stored in audit logs.
 */

const nodemailer = require('nodemailer');
const logger = require('../utils/logger');
const mongoService = require('./mongoService');

// ── SMTP Transporter ──────────────────────────────────────────────────────────
function _createTransporter() {
  return nodemailer.createTransport({
    host:   process.env.SMTP_HOST  || 'smtp.gmail.com',
    port:   parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER || '',
      pass: process.env.SMTP_PASS || '',
    },
    tls: { rejectUnauthorized: false },
  });
}

// ── Active incidents tracker ──────────────────────────────────────────────────
// Map key: `${companyId}:${srcIp}` → IncidentState
const activeIncidents = new Map();

/** @typedef {Object} IncidentState */

// ── Constants ─────────────────────────────────────────────────────────────────
const ALERT_INTERVAL_MS   = 20 * 1000;   // 20 seconds between emails
const ALERT_DURATION_MS   = 2 * 60 * 1000; // 2 minutes alert window
const MAX_ALERTS          = 6;            // 2min / 20s = 6 alerts
const AUTO_RECOVERY_MS    = 15 * 60 * 1000; // 15 minutes to auto-recovery check

// ── Helpers ────────────────────────────────────────────────────────────────────
function _incidentKey(companyId, srcIp) {
  return `${companyId}:${srcIp}`;
}

function _formatBehavior(incident) {
  const lines = [];
  if (incident.failedAttempts) lines.push(`• Failed login attempts: ${incident.failedAttempts}`);
  if (incident.requestsPerSecond) lines.push(`• Request rate: ${incident.requestsPerSecond} req/s`);
  if (incident.mac) lines.push(`• MAC Address: ${incident.mac}`);
  if (incident.description) lines.push(`• Details: ${incident.description}`);
  return lines.join('\n') || '• Automated behavioral anomaly detected';
}

async function _sendEmail({ to, subject, html, text }) {
  try {
    if (!process.env.SMTP_USER) {
      logger.warn('[AlertEngine] SMTP_USER not set — email skipped');
      return false;
    }
    const transport = _createTransporter();
    await transport.sendMail({
      from: `"SOC4 Security" <${process.env.SMTP_USER}>`,
      to,
      subject,
      text,
      html,
    });
    logger.info(`[AlertEngine] Email sent → ${to}: ${subject}`);
    return true;
  } catch (err) {
    logger.error(`[AlertEngine] Email failed: ${err.message}`);
    return false;
  }
}

// ── Email Templates ────────────────────────────────────────────────────────────
function _alertEmailHtml(incident, alertNum) {
  const remaining = MAX_ALERTS - alertNum;
  return `
<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px;">
<div style="max-width:600px;margin:auto;background:#1e293b;border-radius:12px;padding:24px;border:1px solid #ef4444;">
  <h2 style="color:#ef4444;margin:0 0 16px;">🚨 SECURITY ALERT #${alertNum} — ${incident.attackType}</h2>
  <p style="opacity:0.8;margin:0 0 20px;">This is automated alert ${alertNum} of ${MAX_ALERTS}. Auto-isolation will occur if the attack is not stopped.</p>
  <table style="width:100%;border-collapse:collapse;">
    <tr><td style="padding:8px;color:#94a3b8;width:140px;">Company ID</td><td style="padding:8px;color:#f1f5f9;font-weight:bold;">${incident.companyId}</td></tr>
    <tr style="background:#0f172a;"><td style="padding:8px;color:#94a3b8;">Source IP</td><td style="padding:8px;color:#f87171;font-weight:bold;font-family:monospace;">${incident.srcIp}</td></tr>
    <tr><td style="padding:8px;color:#94a3b8;">MAC Address</td><td style="padding:8px;color:#fbbf24;font-family:monospace;">${incident.mac || 'N/A'}</td></tr>
    <tr style="background:#0f172a;"><td style="padding:8px;color:#94a3b8;">Attack Type</td><td style="padding:8px;color:#ef4444;font-weight:bold;">${incident.attackType}</td></tr>
    <tr><td style="padding:8px;color:#94a3b8;">Severity</td><td style="padding:8px;color:#f97316;font-weight:bold;">${(incident.severity || 'high').toUpperCase()}</td></tr>
    <tr style="background:#0f172a;"><td style="padding:8px;color:#94a3b8;">Detected At</td><td style="padding:8px;">${new Date(incident.detectedAt).toLocaleString()}</td></tr>
  </table>
  <div style="margin-top:16px;background:#0f172a;padding:12px;border-radius:8px;border-left:3px solid #f59e0b;">
    <p style="margin:0 0 8px;color:#fbbf24;font-weight:bold;">Behavioral Changes:</p>
    <pre style="margin:0;color:#94a3b8;white-space:pre-wrap;">${_formatBehavior(incident)}</pre>
  </div>
  <div style="margin-top:16px;background:rgba(239,68,68,0.1);padding:12px;border-radius:8px;">
    <p style="margin:0;color:#fca5a5;"><strong>⚠️ ${remaining} alert(s) remaining</strong> before automatic system isolation.</p>
    <p style="margin-top:8px;">To prevent isolation, manually block the IP from the SOC4 dashboard immediately.</p>
  </div>
  <p style="margin-top:20px;opacity:0.4;font-size:12px;">SOC4 Automated Security System — ${new Date().toISOString()}</p>
</div></body></html>`;
}

function _isolationEmailHtml(incident) {
  return `
<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px;">
<div style="max-width:600px;margin:auto;background:#1e293b;border-radius:12px;padding:24px;border:2px solid #ef4444;">
  <h2 style="color:#ef4444;margin:0 0 16px;">🔴 CRITICAL: SYSTEM ISOLATION TRIGGERED</h2>
  <p>Attack was not stopped within 2 minutes. The affected system has been <strong style="color:#ef4444;">automatically isolated</strong>.</p>
  <table style="width:100%;border-collapse:collapse;">
    <tr><td style="padding:8px;color:#94a3b8;width:140px;">Company ID</td><td style="padding:8px;font-weight:bold;">${incident.companyId}</td></tr>
    <tr style="background:#0f172a;"><td style="padding:8px;color:#94a3b8;">Source IP</td><td style="padding:8px;color:#f87171;font-family:monospace;">${incident.srcIp}</td></tr>
    <tr><td style="padding:8px;color:#94a3b8;">MAC Address</td><td style="padding:8px;color:#fbbf24;font-family:monospace;">${incident.mac || 'N/A'}</td></tr>
    <tr style="background:#0f172a;"><td style="padding:8px;color:#94a3b8;">Attack Type</td><td style="padding:8px;color:#ef4444;font-weight:bold;">${incident.attackType}</td></tr>
    <tr><td style="padding:8px;color:#94a3b8;">Isolated At</td><td style="padding:8px;">${new Date().toLocaleString()}</td></tr>
  </table>
  <div style="margin-top:16px;background:rgba(239,68,68,0.15);padding:12px;border-radius:8px;">
    <p style="margin:0;color:#fca5a5;"><strong>Auto-recovery check in 15 minutes.</strong></p>
    <p style="margin-top:8px;opacity:0.8;">Admin manual override is available in the SOC4 dashboard. A consent form must be submitted before any override action.</p>
  </div>
</div></body></html>`;
}

function _recoveryEmailHtml(incident) {
  return `
<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#0f172a;color:#e2e8f0;padding:20px;">
<div style="max-width:600px;margin:auto;background:#1e293b;border-radius:12px;padding:24px;border:2px solid #22c55e;">
  <h2 style="color:#22c55e;margin:0 0 16px;">✅ System Auto-Recovery Complete</h2>
  <p>Threat assessment after 15-minute isolation: <strong style="color:#22c55e;">SAFE</strong>. System has been automatically unisolated.</p>
  <table style="width:100%;border-collapse:collapse;">
    <tr><td style="padding:8px;color:#94a3b8;width:140px;">Company ID</td><td style="padding:8px;font-weight:bold;">${incident.companyId}</td></tr>
    <tr style="background:#0f172a;"><td style="padding:8px;color:#94a3b8;">Source IP</td><td style="padding:8px;color:#86efac;font-family:monospace;">${incident.srcIp}</td></tr>
    <tr><td style="padding:8px;color:#94a3b8;">Attack Type</td><td style="padding:8px;">${incident.attackType}</td></tr>
    <tr style="background:#0f172a;"><td style="padding:8px;color:#94a3b8;">Recovery Time</td><td style="padding:8px;">${new Date().toLocaleString()}</td></tr>
  </table>
  <p style="margin-top:16px;opacity:0.7;">The IP remains blocked. Only the system isolation has been lifted. Review logs in SOC4 dashboard.</p>
</div></body></html>`;
}

// ── Phase 1: Start Alert Loop ─────────────────────────────────────────────────
async function startAlertLoop(incidentKey, incident) {
  let alertCount = 0;
  const startTime = Date.now();

  const tick = async () => {
    // If incident was manually resolved, stop
    const current = activeIncidents.get(incidentKey);
    if (!current || current !== incident || current.status !== 'alerting') {
      logger.info(`[AlertEngine] Incident ${incidentKey} resolved — stopping alert loop`);
      return;
    }

    alertCount++;
    const elapsed = Date.now() - startTime;

    // Log alert to DB
    await mongoService.storeLog({
      level: 'ALERT',
      message: `🚨 Alert #${alertCount}: ${incident.attackType} from ${incident.srcIp} (MAC:${incident.mac || 'N/A'})`,
      ip: incident.srcIp,
      mac: incident.mac,
      attackType: incident.attackType,
      alertNum: alertCount,
    }, incident.companyId).catch(() => {});

    // Send email
    if (incident.adminEmail) {
      await _sendEmail({
        to: incident.adminEmail,
        subject: `🚨 SOC4 Security Alert #${alertCount}: ${incident.attackType} from ${incident.srcIp}`,
        html: _alertEmailHtml(incident, alertCount),
        text: `Attack Alert #${alertCount}: ${incident.attackType} from ${incident.srcIp} (${incident.companyId}). Auto-isolation in ${Math.max(0, Math.round((ALERT_DURATION_MS - elapsed) / 1000))}s if not stopped.`,
      });
    }

    if (activeIncidents.get(incidentKey) !== current || current.status !== 'alerting') return;

    // Update alert count
    current.alertCount = alertCount;
    current.lastAlert = new Date();
    activeIncidents.set(incidentKey, current);

    // Check if 2 min window elapsed
    if (elapsed >= ALERT_DURATION_MS || alertCount >= MAX_ALERTS) {
      // Trigger auto-isolation
      await triggerAutoIsolation(incidentKey, incident);
    } else {
      // Schedule next alert in 20s
      setTimeout(tick, ALERT_INTERVAL_MS);
    }
  };

  // Start first tick immediately
  await tick();
}

// ── Phase 2: Auto-Isolation ───────────────────────────────────────────────────
async function triggerAutoIsolation(incidentKey, incident) {
  const current = activeIncidents.get(incidentKey);
  if (!current || current !== incident || current.status !== 'alerting') return;
  // Only the SOC backend owns endpoint commands and agent acknowledgments.
  // An escalation event is not evidence that a machine has been isolated.
  current.status = 'isolation_requested';
  current.isolationRequestedAt = new Date();
  current.isolationConfirmed = false;
  await mongoService.storeLog({
    level: 'ALERT', message: `Isolation requested for ${incident.srcIp}; endpoint enforcement requires the SOC backend`,
    ip: incident.srcIp, phase: 'isolation-requested',
  }, incident.companyId).catch(() => {});
  if (typeof global.emitIPSEvent === 'function') {
    global.emitIPSEvent('isolation-requested', {
      companyId: incident.companyId, srcIp: incident.srcIp,
      enforced: false, status: current.status,
    });
  }
}

// ── Phase 3: Auto-Recovery ────────────────────────────────────────────────────
async function autoRecoveryCheck(incidentKey, incident) {
  const current = activeIncidents.get(incidentKey);
  if (!current) return;
  if (current.status !== 'isolated' || current.isolationConfirmed !== true) return;

  logger.info(`[AlertEngine] Auto-recovery check for ${incidentKey}`);

  // Check if new attacks from same IP in last 15 min
  const recentAttacks = await mongoService.getRecentAttacks(5, { srcIp: incident.srcIp }, incident.companyId).catch(() => []);
  const recentMs = 15 * 60 * 1000;
  const veryRecent = recentAttacks.filter(a => Date.now() - new Date(a.ts).getTime() < recentMs && !a.simulated);

  if (veryRecent.length === 0) {
    // Safe — unisolate
    logger.info(`[AlertEngine] AUTO-RECOVERY: ${incident.srcIp} — no recent attacks — unisolating`);
    current.status = 'recovered';
    current.recoveredAt = new Date();
    activeIncidents.set(incidentKey, current);

    if (incident.adminEmail) {
      await _sendEmail({
        to: incident.adminEmail,
        subject: `✅ SOC4 Auto-Recovery: System Unisolated — ${incident.srcIp}`,
        html: _recoveryEmailHtml(incident),
        text: `Auto-recovery complete: ${incident.srcIp} unisolated after 15-min clean period. IP remains blocked.`,
      });
    }

    await mongoService.storeLog({
      level: 'RECOVERY',
      message: `✅ AUTO-RECOVERED: ${incident.srcIp} [${incident.companyId}] — unisolated after 15min clean`,
      ip: incident.srcIp,
      mac: incident.mac,
      attackType: incident.attackType,
      phase: 'auto-recovery',
    }, incident.companyId).catch(() => {});

    if (typeof global.emitIPSEvent === 'function') {
      global.emitIPSEvent('recovery', {
        companyId: incident.companyId,
        srcIp: incident.srcIp,
        recoveredAt: new Date().toISOString(),
      });
    }
  } else {
    // Still active — extend isolation another 15 min
    logger.warn(`[AlertEngine] Recovery check: ${veryRecent.length} recent attacks — extending isolation for ${incident.srcIp}`);
    current.isolationExtended = (current.isolationExtended || 0) + 1;
    activeIncidents.set(incidentKey, current);

    if (incident.adminEmail) {
      await _sendEmail({
        to: incident.adminEmail,
        subject: `⚠️ SOC4: Isolation Extended — ${incident.srcIp} Still Active`,
        html: `<p>Attack from ${incident.srcIp} still active (${veryRecent.length} events in last 15min). Isolation extended. Manual override required.</p>`,
        text: `Isolation extended for ${incident.srcIp} — ${veryRecent.length} recent events. Manual override required via SOC4 dashboard.`,
      });
    }

    await mongoService.storeLog({
      level: 'ISOLATION',
      message: `⚠️ ISOLATION EXTENDED: ${incident.srcIp} — ${veryRecent.length} recent attacks`,
      ip: incident.srcIp,
      mac: incident.mac,
      attackType: incident.attackType,
      phase: 'isolation-extended',
    }, incident.companyId).catch(() => {});

    // Check again in 15 min
    setTimeout(() => autoRecoveryCheck(incidentKey, incident), AUTO_RECOVERY_MS);
  }
}

// ── Public API: Handle Detection ──────────────────────────────────────────────
/**
 * Entry point when IDS detects an attack.
 * Starts the full alert→isolation→recovery lifecycle.
 */
async function handleDetection({
  companyId,
  srcIp,
  mac = null,
  attackType = 'Unknown',
  severity = 'high',
  adminEmail = null,
  description = '',
  failedAttempts = 0,
  requestsPerSecond = 0,
}) {
  if (!companyId || !srcIp) {
    logger.warn('[AlertEngine] handleDetection requires companyId and srcIp');
    return null;
  }

  const incidentKey = _incidentKey(companyId, srcIp);

  // If incident already active for this IP, update but don't restart
  if (activeIncidents.has(incidentKey)) {
    const existing = activeIncidents.get(incidentKey);
    if (['alerting', 'isolated', 'isolation_requested'].includes(existing.status)) {
      if (!existing.mac && mac) existing.mac = mac;
      logger.info(`[AlertEngine] Incident already active for ${incidentKey} (${existing.status})`);
      return existing;
    }
  }

  // Resolve admin email
  const resolvedEmail = adminEmail || process.env.SMTP_USER;

  const incident = {
    companyId,
    srcIp,
    mac,
    attackType,
    severity,
    adminEmail: resolvedEmail,
    description,
    failedAttempts,
    requestsPerSecond,
    detectedAt: Date.now(),
    status: 'alerting',
    alertCount: 0,
    lastAlert: null,
    isolatedAt: null,
    recoveredAt: null,
    isolationExtended: 0,
  };

  activeIncidents.set(incidentKey, incident);

  logger.info(`[AlertEngine] New incident: ${attackType} from ${srcIp} [company=${companyId}] — starting alert loop`);

  // Start the alert loop asynchronously
  startAlertLoop(incidentKey, incident).catch(err =>
    logger.error(`[AlertEngine] Alert loop error: ${err.message}`)
  );

  return incident;
}

// ── Manual Override: Resolve Incident ─────────────────────────────────────────
function resolveIncident(companyId, srcIp) {
  const incidentKey = _incidentKey(companyId, srcIp);
  const current = activeIncidents.get(incidentKey);
  if (current) {
    current.status = 'manual-override';
    current.resolvedAt = new Date();
    activeIncidents.set(incidentKey, current);
    logger.info(`[AlertEngine] Incident ${incidentKey} manually resolved`);
  }
  return current;
}

// ── Get All Incidents ──────────────────────────────────────────────────────────
function getIncidents(companyId = null) {
  const results = [];
  for (const [key, incident] of activeIncidents.entries()) {
    if (!companyId || incident.companyId === companyId) {
      results.push({ key, ...incident });
    }
  }
  return results.sort((a, b) => b.detectedAt - a.detectedAt);
}

// ── Get Incident by IP ────────────────────────────────────────────────────────
function getIncident(companyId, srcIp) {
  const key = _incidentKey(companyId, srcIp);
  return activeIncidents.get(key) || null;
}

module.exports = {
  handleDetection,
  resolveIncident,
  getIncidents,
  getIncident,
  triggerAutoIsolation,
  autoRecoveryCheck,
};
