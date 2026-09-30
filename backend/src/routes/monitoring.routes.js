const router = require('express').Router();
const Alert = require('../models/Alert.model');
const Log = require('../models/Log.model');
const System = require('../models/System.model');
const User = require('../models/User.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { canonicalCapabilityIds, isSyntheticAlert } = require('../utils/capabilityTelemetry');
const { DESKTOP_CAPABILITIES, capabilityRuntimeState, desktopOs } = require('../utils/desktopCapabilities');

const desktopCapabilityCache = new Map();
// Capability classification walks endpoint alert history; keep the shared
// snapshot long enough to prevent each dashboard/card refresh from rescanning.
const DESKTOP_CAPABILITY_CACHE_MS = 5 * 60 * 1000;

function parseJsonObject(value) {
  if (value && typeof value === 'object') return value;
  if (typeof value !== 'string' || !value.trim()) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function androidTelemetryKind(event = {}) {
  const type = String(event.type || event.ruleId || event._id?.type || '').toLowerCase();
  const category = String(event.eventCategory || event._id?.eventCategory || '').toLowerCase();
  const eventType = String(event.eventType || event._id?.eventType || '').toLowerCase();
  if (type.includes('agent_health') || type.includes('forensic_snapshot')) return 'health';
  if (type.includes('app_') || eventType === 'application') return 'applications';
  if (type.includes('usb') || category === 'usb' || eventType === 'usb') return 'usb';
  if (type.includes('ips') || type.includes('blocked_connection') || eventType === 'blocked_connection') return 'ips';
  if (type.includes('file') || category === 'file' || eventType === 'file') return 'file';
  if (type.includes('process') || eventType === 'process') return 'process';
  if (type.includes('native_')) return 'native';
  if (type.includes('network') || category === 'network' || eventType.includes('network')) return 'network';
  return null;
}

function androidTelemetryEventFilter(key) {
  const filters = {
    health: { type: { $in: ['ANDROID_AGENT_HEALTH', 'android_forensic_snapshot'] } },
    applications: { type: /^ANDROID_APP_/i },
    network: { type: /^ANDROID_NETWORK/i },
    ips: { $or: [{ type: /IPS|BLOCKED_CONNECTION/i }, { eventType: 'blocked_connection' }] },
    file: { $or: [{ type: /FILE/i }, { eventCategory: 'file' }, { eventType: 'file' }] },
    usb: { $or: [{ type: /USB/i }, { eventCategory: 'usb' }, { eventType: 'usb' }] },
    process: { $or: [{ type: /PROCESS/i }, { eventType: 'process' }] },
    native: { type: /^ANDROID_NATIVE_/i },
  };
  return filters[key] || { _id: null };
}

// ═══════════════════════════════════════════════════════════════════════════
// SYSTEM MONITORING DASHBOARD - Real-Time Data Endpoints
// ═══════════════════════════════════════════════════════════════════════════

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/malware
   Returns malware events with severity, quarantine status, VT score, and
   containment status. All counts are consistent with the returned data array.
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/malware', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const malwareAlerts = await Alert.find({
      systemId: req.params.systemId,
      companyId: req.user.companyId,
      eventCategory: 'malware',
    })
      .sort({ createdAt: -1 })
      .limit(Number(limit))
      .lean();

    // ── VT Score — display as "detections/total" ratio, not raw percentage ─
    const vtScored = malwareAlerts.filter(a => a.vtTotal > 0);
    const vtAvgDetections = vtScored.length > 0
      ? Math.round(vtScored.reduce((s, a) => s + (a.vtDetections || 0), 0) / vtScored.length)
      : null;
    const vtAvgTotal = vtScored.length > 0
      ? Math.round(vtScored.reduce((s, a) => s + (a.vtTotal || 0), 0) / vtScored.length)
      : null;
    const vtAvgScore = vtScored.length > 0
      ? Math.round(vtScored.reduce((s, a) => s + (a.vtScore || 0), 0) / vtScored.length)
      : null;

    const counts = {
      total: malwareAlerts.length,
      open: malwareAlerts.filter(a => a.status === 'open').length,
      resolved: malwareAlerts.filter(a => a.status === 'resolved').length,
      critical: malwareAlerts.filter(a => a.severity === 'critical').length,
      high: malwareAlerts.filter(a => a.severity === 'high').length,
      medium: malwareAlerts.filter(a => a.severity === 'medium').length,
      low: malwareAlerts.filter(a => a.severity === 'low').length,

      // ── Containment counts ─────────────────────────────────────────────
      quarantined:       malwareAlerts.filter(a => a.quarantined === true).length,
      containmentStatus: {
        blocked:     malwareAlerts.filter(a => a.containmentStatus === 'blocked').length,
        quarantined: malwareAlerts.filter(a => a.containmentStatus === 'quarantined' || a.quarantined).length,
        isolated:    malwareAlerts.filter(a => a.containmentStatus === 'isolated').length,
        allowed:     malwareAlerts.filter(a => a.containmentStatus === 'allowed').length,
        none:        malwareAlerts.filter(a => !a.containmentStatus && !a.quarantined).length,
      },

      // ── Action Taken ───────────────────────────────────────────────────
      actionTaken: {
        blocked:     malwareAlerts.filter(a => (a.actionTaken || '').toLowerCase() === 'blocked').length,
        quarantined: malwareAlerts.filter(a => (a.actionTaken || '').toLowerCase() === 'quarantined').length,
        allowed:     malwareAlerts.filter(a => (a.actionTaken || '').toLowerCase() === 'allowed').length,
        deleted:     malwareAlerts.filter(a => (a.actionTaken || '').toLowerCase() === 'deleted').length,
        none:        malwareAlerts.filter(a => !a.actionTaken).length,
      },

      // ── By malware type ────────────────────────────────────────────────
      byType: {
        trojan:     malwareAlerts.filter(a => a.malwareType === 'Trojan').length,
        ransomware: malwareAlerts.filter(a => a.malwareType === 'Ransomware').length,
        worm:       malwareAlerts.filter(a => a.malwareType === 'Worm').length,
        miner:      malwareAlerts.filter(a => a.malwareType === 'Miner').length,
        backdoor:   malwareAlerts.filter(a => a.malwareType === 'Backdoor').length,
        other:      malwareAlerts.filter(a => !['Trojan','Ransomware','Worm','Miner','Backdoor'].includes(a.malwareType)).length,
      },

      // ── VirusTotal stats ───────────────────────────────────────────────
      vtScanned:        vtScored.length,
      vtAvgScore,        // null if no VT data (show "No Data" not 0)
      vtAvgDetections,   // average detections count
      vtAvgTotal,        // average total engines
      vtAvgRatio:        (vtAvgDetections !== null && vtAvgTotal)
                           ? `${vtAvgDetections}/${vtAvgTotal}` : null,
      vtMalicious:       malwareAlerts.filter(a => a.vtVerdict === 'malicious').length,
      vtSuspicious:      malwareAlerts.filter(a => a.vtVerdict === 'suspicious').length,
      vtClean:           malwareAlerts.filter(a => a.vtVerdict === 'clean').length,
      vtNotFound:        malwareAlerts.filter(a => a.vtVerdict === 'not_found' || a.vtIntelMissing).length,
      underObservation:  malwareAlerts.filter(a => a.underObservation).length,

      // ── Timeline ──────────────────────────────────────────────────────
      firstSeen: malwareAlerts.length > 0
        ? malwareAlerts[malwareAlerts.length - 1].createdAt : null,
      lastSeen: malwareAlerts.length > 0
        ? malwareAlerts[0].createdAt : null,
    };

    res.json({ data: malwareAlerts, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/network
   Returns network events and logs
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/network', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const [alerts, logs] = await Promise.all([
      Alert.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        eventCategory: 'network',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
      Log.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        logType: 'network',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
    ]);

    const counts = {
      total: alerts.length + logs.length,
      alerts: alerts.length,
      logs: logs.length,
      critical: alerts.filter(a => a.severity === 'critical').length,
      inbound: alerts.filter(a => a.direction === 'inbound').length,
      outbound: alerts.filter(a => a.direction === 'outbound').length,
      blocked: alerts.filter(a => a.blocked).length,
      suspicious: alerts.filter(a => a.severity === 'high').length,
    };

    res.json({ alerts, logs, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/file-activity
   Returns file monitoring events
   FIX: total is always = created + modified + deleted + renamed + accessed
        so the breakdown numbers always add up exactly to the total.
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/file-activity', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const [logs, alerts] = await Promise.all([
      Log.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        logType: 'file',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
      Alert.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        eventCategory: 'file',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
    ]);

    // ── DATA CONSISTENCY RULE: total MUST equal sum of action breakdown ──────
    // Only count logs that have a known fileAction so the breakdown is accurate.
    // Logs without a fileAction are not counted in the breakdown.
    const created  = logs.filter(l => l.fields?.fileAction === 'created').length;
    const modified = logs.filter(l => l.fields?.fileAction === 'modified').length;
    const deleted  = logs.filter(l => l.fields?.fileAction === 'deleted').length;
    const renamed  = logs.filter(l => l.fields?.fileAction === 'renamed').length;
    const accessed = logs.filter(l => l.fields?.fileAction === 'accessed').length;
    const unknown  = logs.filter(l => !l.fields?.fileAction).length; // logs missing action
    // Total = sum of all typed actions + unknowns (so total always ≥ breakdown)
    const totalLogs = created + modified + deleted + renamed + accessed + unknown;

    const counts = {
      total: totalLogs + alerts.length,
      created,
      modified,
      deleted,
      renamed,
      accessed,
      noAction: unknown,  // logs without a fileAction field (shown as "Unknown")
      suspicious: alerts.filter(a => a.severity === 'high').length,
      alerts: alerts.length,
    };

    res.json({ logs, alerts, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/logs
   Returns system logs with statistics
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/logs', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const logs = await Log.find({
      systemId: req.params.systemId,
      companyId: req.user.companyId,
    })
      .sort({ createdAt: -1 })
      .limit(Number(limit))
      .lean();

    const lastHour = new Date(Date.now() - 60 * 60 * 1000);
    const logsLast1h = logs.filter(l => new Date(l.createdAt) > lastHour);

    const counts = {
      total: logs.length,
      errors: logs.filter(l => l.level === 'error').length,
      warnings: logs.filter(l => l.level === 'warning').length,
      info: logs.filter(l => l.level === 'info').length,
      critical: logs.filter(l => l.level === 'critical').length,
      last1h: {
        errors: logsLast1h.filter(l => l.level === 'error').length,
        warnings: logsLast1h.filter(l => l.level === 'warning').length,
        total: logsLast1h.length,
      },
    };

    res.json({ logs, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/edr
   Returns EDR and authentication events
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/edr', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const [alerts, loginActivity] = await Promise.all([
      Alert.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        eventCategory: 'edr',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
      Log.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        logType: 'login',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
    ]);

    const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const loginLast24h = loginActivity.filter(l => new Date(l.createdAt) > last24h);

    const counts = {
      total: alerts.length + loginActivity.length,
      edrAlerts: alerts.length,
      suspiciousLogins: loginActivity.filter(l => !l.success).length,
      failedLogins: loginLast24h.filter(l => !l.success).length,
      successfulLogins: loginActivity.filter(l => l.success).length,
      privilegeEscalation: alerts.filter(a => a.userAction === 'privilege_escalation').length,
      suspiciousCommands: alerts.filter(a => a.userAction === 'suspicious_cmd').length,
    };

    res.json({ alerts, loginActivity, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/usb
   Returns USB device events
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/usb', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const logs = await Log.find({
      systemId: req.params.systemId,
      companyId: req.user.companyId,
      logType: 'usb',
    })
      .sort({ createdAt: -1 })
      .limit(Number(limit))
      .lean();

    const counts = {
      total: logs.length,
      connected: logs.filter(l => l.message?.match(/connect/i) && !l.message?.match(/disconnect/i)).length,
      disconnected: logs.filter(l => l.message?.match(/disconnect/i)).length,
      blocked: logs.filter(l => l.fields?.blocked).length,
      suspicious: logs.filter(l => l.level === 'warning' || l.level === 'critical').length,
    };

    res.json({ logs, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/threats
   Returns VirusTotal and threat intelligence data
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/threats', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const alerts = await Alert.find({
      systemId: req.params.systemId,
      companyId: req.user.companyId,
      $or: [
        { vtScore: { $gt: 0 } },
        { vtVerdict: { $exists: true, $ne: null } },
      ],
    })
      .sort({ createdAt: -1 })
      .limit(Number(limit))
      .lean();

    const counts = {
      total: alerts.length,
      malicious: alerts.filter(a => a.vtVerdict === 'malicious').length,
      suspicious: alerts.filter(a => a.vtVerdict === 'suspicious').length,
      undetected: alerts.filter(a => a.vtVerdict === 'undetected').length,
      highScore: alerts.filter(a => a.vtScore && a.vtScore > 0.7).length,
      avgScore: alerts.filter(a => a.vtScore > 0).length > 0
        ? Math.round(alerts.filter(a => a.vtScore > 0).reduce((sum, a) => sum + a.vtScore, 0) / alerts.filter(a => a.vtScore > 0).length * 100) / 100
        : 0,
    };

    res.json({ alerts, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/active-telemetry
   Returns only telemetry collectors that are actually enabled by the Android
   runtime. Counts and recent events come from persisted agent telemetry.
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/active-telemetry', authenticate, requireAnalyst, async (req, res) => {
  try {
    const system = await System.findOne({
      _id: req.params.systemId,
      companyId: req.user.companyId,
    }).lean();
    if (!system) return res.status(404).json({ message: 'System not found' });

    const hours = Math.max(1, Math.min(168, Number(req.query.hours) || 24));
    const eventLimit = Math.max(1, Math.min(50, Number(req.query.limit) || 25));
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    const androidMatch = {
      systemId: system._id,
      companyId: system.companyId,
      $or: [
        { source: 'android-agent' },
        { type: /^android_/i },
        { ruleId: /^android_/i },
      ],
    };

    const [latestHealth, latestSnapshot, grouped] = await Promise.all([
      Alert.findOne({ ...androidMatch, type: 'ANDROID_AGENT_HEALTH' })
        .sort({ eventTimestamp: -1, createdAt: -1 })
        .select('full_log rawEvent createdAt eventTimestamp agentVersion')
        .lean(),
      Alert.findOne({ ...androidMatch, type: 'android_forensic_snapshot' })
        .sort({ eventTimestamp: -1, createdAt: -1 })
        .select('full_log rawEvent createdAt eventTimestamp agentVersion')
        .lean(),
      Alert.aggregate([
        { $match: androidMatch },
        {
          $group: {
            _id: { type: '$type', eventCategory: '$eventCategory', eventType: '$eventType' },
            totalCount: { $sum: 1 },
            count24h: { $sum: { $cond: [{ $gte: ['$createdAt', since] }, 1, 0] } },
            lastEventAt: { $max: '$createdAt' },
          },
        },
      ]),
    ]);

    const healthEnvelope = latestHealth?.rawEvent?.payload || latestHealth?.rawEvent || parseJsonObject(latestHealth?.full_log);
    const snapshotEnvelope = latestSnapshot?.rawEvent?.payload || latestSnapshot?.rawEvent || parseJsonObject(latestSnapshot?.full_log);
    const runtime = healthEnvelope.capability || snapshotEnvelope.capabilities?.runtime_detection || {};
    const snapshotCapabilities = snapshotEnvelope.capabilities || {};
    const queue = healthEnvelope.queue || snapshotEnvelope.device_health?.telemetry_queue || {};
    const fileWatchRoots = Number(healthEnvelope.file_watch_roots || 0);

    const totals = {};
    for (const row of grouped) {
      const key = androidTelemetryKind(row);
      if (!key) continue;
      if (!totals[key]) totals[key] = { totalCount: 0, count24h: 0, lastEventAt: null };
      totals[key].totalCount += Number(row.totalCount || 0);
      totals[key].count24h += Number(row.count24h || 0);
      if (!totals[key].lastEventAt || new Date(row.lastEventAt) > new Date(totals[key].lastEventAt)) {
        totals[key].lastEventAt = row.lastEventAt;
      }
    }

    const definitions = [
      {
        key: 'health', title: 'Agent & Device Health', icon: '💚',
        enabled: true,
        description: 'Heartbeat, Android device state, collector health and persistent queue status',
      },
      {
        key: 'applications', title: 'Application Inventory', icon: '📦',
        enabled: system.edrEnabled !== false,
        description: 'Installed application inventory and install, update or removal changes',
      },
      {
        key: 'network', title: 'Network Status', icon: '🌐',
        enabled: system.networkMonitorEnabled !== false,
        description: 'Connectivity changes, active network type and supported connection metadata',
      },
      {
        key: 'ips', title: 'VPN Firewall / IPS', icon: '🛡️',
        enabled: system.ipsEnabled === true || system.firewallEnabled === true,
        description: 'User-approved VPN firewall enforcement and blocked connection events',
      },
      {
        key: 'file', title: 'Visible File Activity', icon: '📁',
        enabled: fileWatchRoots > 0,
        description: `FileObserver is listening on ${fileWatchRoots} app-visible storage root${fileWatchRoots === 1 ? '' : 's'}`,
      },
      {
        key: 'usb', title: 'USB Device Activity', icon: '🔌',
        enabled: system.usbMonitorEnabled === true && snapshotCapabilities.usb_telemetry !== false,
        description: 'Android USB attach and detach broadcasts with exposed device metadata',
      },
      {
        key: 'process', title: 'Process / App Usage', icon: '⚙️',
        enabled: system.processMonitorEnabled === true,
        description: 'Usage-access or approved native process start and exit telemetry',
      },
      {
        key: 'native', title: 'Native AOSP Telemetry', icon: '🧩',
        enabled: runtime.native_daemon === true,
        description: 'SELinux-confined AJNAT daemon and supported kernel/platform telemetry',
      },
    ];

    const activeDefinitions = definitions.filter(item => item.enabled);
    const recentByCard = await Promise.all(activeDefinitions.map(item => Alert.find({
      $and: [androidMatch, androidTelemetryEventFilter(item.key)],
    })
      .sort({ createdAt: -1 })
      .limit(eventLimit)
      .select('_id type ruleId eventCategory eventType severity description createdAt eventTimestamp agentVersion filePath fileAction device deviceVendor usbVendorId usbProductId srcip destip sourcePort destPort protocol blocked')
      .lean()));

    const queueRetrying = queue.connection_state === 'retrying' || Boolean(queue.last_transport_error);
    const cards = activeDefinitions.map((item, index) => {
      const stats = totals[item.key] || { totalCount: 0, count24h: 0, lastEventAt: null };
      return {
        key: item.key,
        title: item.title,
        icon: item.icon,
        description: item.description,
        status: item.key === 'health' && queueRetrying
          ? 'degraded'
          : (stats.count24h > 0 ? 'streaming' : 'listening'),
        count24h: stats.count24h,
        totalCount: stats.totalCount,
        lastEventAt: stats.lastEventAt,
        events: recentByCard[index],
      };
    });

    return res.json({
      generatedAt: new Date(),
      windowHours: hours,
      system: {
        id: system._id,
        name: system.name,
        agentVersion: system.agentVersion,
        lastSeen: system.lastSeen,
        online: Boolean(system.lastSeen && Date.now() - new Date(system.lastSeen).getTime() < 10 * 60 * 1000),
      },
      runtime: {
        capabilityMode: runtime.mode || snapshotCapabilities.capability_mode || 'STANDARD_ANDROID',
        nativeDaemon: runtime.native_daemon === true,
        queueDepth: Number(queue.queue_depth || 0),
        droppedEvents: Number(queue.queue_dropped_events || 0),
        connectionState: queue.connection_state || 'unknown',
        lastTransportError: String(queue.last_transport_error || ''),
        healthReportedAt: latestHealth?.eventTimestamp || latestHealth?.createdAt || null,
      },
      cards,
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/capability-telemetry
   Canonical 31-card Linux/Windows capability matrix. Normalized capability
   tags are authoritative; rule/category inference is used only for legacy
   untagged events so a single record cannot inflate unrelated cards.
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/capability-telemetry', authenticate, requireAnalyst, async (req, res) => {
  try {
    const system = await System.findOne({
      _id: req.params.systemId,
      companyId: req.user.companyId,
    }).lean();
    if (!system) return res.status(404).json({ message: 'System not found' });

    const os = desktopOs(system);
    if (!['linux', 'windows', 'darwin'].includes(os)) {
      return res.status(400).json({ message: 'Desktop capability telemetry is only available for desktop agents' });
    }

    const hours = Math.max(1, Math.min(168, Number(req.query.hours) || 24));
    const eventLimit = Math.max(1, Math.min(50, Number(req.query.limit) || 25));
    const summaryOnly = ['1', 'true'].includes(String(req.query.summaryOnly || '').toLowerCase());
    const cacheKey = `${system._id}:${hours}:${eventLimit}:${summaryOnly ? 'summary' : 'full'}`;
    const cached = desktopCapabilityCache.get(cacheKey);
    if (cached && Date.now() - cached.createdAt < DESKTOP_CAPABILITY_CACHE_MS) {
      return res.json(cached.payload);
    }

    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    const stats = new Map(DESKTOP_CAPABILITIES.map(item => [item.id, {
      count24h: 0,
      totalCount: 0,
      highCritical24h: 0,
      lastEventAt: null,
      events: [],
    }]));
    const projection = [
      '_id', 'ruleId', 'type', 'description', 'full_log', 'source', 'eventCategory',
      'category', 'subCategory', 'eventType', 'userAction', 'attackType',
      'signatureName', 'detectionSource', 'processName', 'processCmdline', 'pid',
      'parentPid', 'processCount', 'processMemoryPercent', 'filePath', 'fileAction',
      'fileHash', 'fileHashMd5', 'oldHash', 'newHash', 'yaraRules', 'domain',
      'queryType', 'responseCode', 'sinkholeIp', 'srcip', 'destip', 'sourcePort',
      'destPort', 'protocol', 'direction', 'blocked', 'device', 'deviceVendor',
      'usbVendorId', 'usbProductId', 'username', 'severity', 'actionTaken',
      'containmentStatus', 'quarantined', 'isolated', 'tiEnriched', 'tiConfidence',
      'tiDomain', 'tiSummary', 'tiFeeds', 'capabilityId', 'capabilityIds',
      'isSynthetic', 'dataOrigin', 'agentVersion', 'createdAt', 'eventTimestamp',
      'rawEvent.ruleId', 'rawEvent.rule_id', 'rawEvent.type', 'rawEvent.category',
      'rawEvent.eventType', 'rawEvent.event_type', 'rawEvent.source',
      'rawEvent.log_source', 'rawEvent.description', 'rawEvent.capabilityId',
      'rawEvent.capability_id', 'rawEvent.capabilityIds', 'rawEvent.capability_ids',
    ].join(' ');

    const cursor = Alert.find({
      systemId: system._id,
      companyId: system.companyId,
      archivedAt: null,
    })
      .sort({ createdAt: -1 })
      .select(projection)
      .lean()
      .cursor({ batchSize: 1000 });

    for await (const event of cursor) {
      if (isSyntheticAlert(event)) continue;
      const eventTime = new Date(event.createdAt || event.eventTimestamp || 0);
      const inWindow = !Number.isNaN(eventTime.getTime()) && eventTime >= since;
      for (const id of canonicalCapabilityIds(event)) {
        const item = stats.get(id);
        if (!item) continue;
        item.totalCount += 1;
        if (!item.lastEventAt || eventTime > item.lastEventAt) item.lastEventAt = eventTime;
        if (!inWindow) continue;
        item.count24h += 1;
        if (['critical', 'high'].includes(String(event.severity || '').toLowerCase())) item.highCritical24h += 1;
        if (item.events.length < eventLimit) {
          item.events.push({
            _id: event._id,
            ruleId: event.ruleId,
            type: event.type,
            eventCategory: event.eventCategory,
            eventType: event.eventType,
            severity: event.severity,
            description: event.description,
            createdAt: event.createdAt,
            eventTimestamp: event.eventTimestamp,
            agentVersion: event.agentVersion,
            processName: event.processName,
            pid: event.pid,
            filePath: event.filePath,
            fileAction: event.fileAction,
            srcip: event.srcip,
            destip: event.destip,
            sourcePort: event.sourcePort,
            destPort: event.destPort,
            protocol: event.protocol,
            domain: event.domain,
            username: event.username,
            device: event.device,
            blocked: event.blocked,
          });
        }
      }
    }

    const cards = DESKTOP_CAPABILITIES.map(definition => {
      const item = stats.get(definition.id);
      const runtime = capabilityRuntimeState(system, definition, item.count24h, item.totalCount);
      return {
        capabilityId: definition.id,
        status: runtime.status,
        configured: runtime.configured,
        support: definition.support,
        reason: runtime.reason,
        count24h: item.count24h,
        totalCount: item.totalCount,
        highCritical24h: item.highCritical24h,
        lastEventAt: item.lastEventAt,
        events: item.events,
      };
    });
    const responseCards = summaryOnly
      ? cards.map(({ events, ...card }) => card)
      : cards;
    const payload = {
      generatedAt: new Date(),
      windowHours: hours,
      system: {
        id: system._id,
        name: system.name,
        os,
        osDisplay: system.os || system.osType,
        agentVersion: system.agentVersion,
        lastSeen: system.lastSeen,
        online: Boolean(system.lastSeen && Date.now() - new Date(system.lastSeen).getTime() < 10 * 60 * 1000),
      },
      summary: {
        totalCapabilities: cards.length,
        reporting: cards.filter(card => card.status === 'reporting').length,
        stale: cards.filter(card => card.status === 'stale').length,
        enabledNoTelemetry: cards.filter(card => card.status === 'enabled_no_telemetry').length,
        dependencyRequired: cards.filter(card => card.status === 'dependency_required').length,
        disabled: cards.filter(card => card.status === 'disabled').length,
      },
      cards: responseCards,
    };
    desktopCapabilityCache.set(cacheKey, { createdAt: Date.now(), payload });
    if (desktopCapabilityCache.size > 200) desktopCapabilityCache.clear();
    return res.json(payload);
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/health
   Returns overall system health metrics
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/health', authenticate, requireAnalyst, async (req, res) => {
  try {
    const system = await System.findById(req.params.systemId).lean();
    if (!system) return res.status(404).json({ message: 'System not found' });

    const [alerts, logs] = await Promise.all([
      Alert.find({ systemId: req.params.systemId, companyId: req.user.companyId, status: 'open' })
        .countDocuments(),
      Log.find({ systemId: req.params.systemId, companyId: req.user.companyId, level: 'error' })
        .countDocuments(),
    ]);

    const isOnline = system.lastSeen && (Date.now() - new Date(system.lastSeen).getTime()) < 10 * 60 * 1000;

    // Calculate health score (0-100)
    let healthScore = 100;
    healthScore -= Math.min(alerts * 2, 40); // Max -40 for alerts
    healthScore -= Math.min(logs * 1, 30);   // Max -30 for errors
    healthScore = Math.max(healthScore, 10); // Min 10

    const status = {
      isOnline,
      lastSeen: system.lastSeen,
      healthScore: Math.round(healthScore),
      openAlerts: alerts,
      errorLogs: logs,
      services: {
        edr: system.edrEnabled ? 'active' : 'inactive',
        ips: system.ipsEnabled ? 'active' : 'inactive',
        firewall: system.firewallEnabled ? 'active' : 'inactive',
        ids: system.idsEnabled ? 'active' : 'inactive',
        usbMonitor: system.usbMonitorEnabled ? 'active' : 'inactive',
        networkMonitor: system.networkMonitorEnabled ? 'active' : 'inactive',
      },
    };

    res.json(status);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/timeline
   Returns chronological event timeline (alerts + logs combined)
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/timeline', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 50 } = req.query;
    const [alerts, logs, loginActivity] = await Promise.all([
      Alert.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
      Log.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
      Log.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        logType: 'login',
      })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean(),
    ]);

    // Combine and sort
    const timeline = [
      ...alerts.map(a => ({
        id: a._id,
        time: a.createdAt,
        type: 'alert',
        severity: a.severity,
        category: a.eventCategory,
        message: a.description || a.ruleId,
        data: a,
      })),
      ...logs.map(l => ({
        id: l._id,
        time: l.createdAt,
        type: 'log',
        severity: l.level,
        category: l.logType,
        message: l.message,
        data: l,
      })),
      ...loginActivity.map(la => ({
        id: la._id,
        time: la.createdAt,
        type: 'login',
        severity: la.success ? 'info' : 'warning',
        category: 'login',
        message: `${la.action || 'login'} - ${la.email || 'unknown'}`,
        data: la,
      })),
    ]
      .sort((a, b) => new Date(b.time) - new Date(a.time))
      .slice(0, Number(limit));

    res.json({ timeline, total: timeline.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/network-activity
   Returns network activity graph data (24-hour rolling window)
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/network-activity', authenticate, requireAnalyst, async (req, res) => {
  try {
    const systemId = req.params.systemId;
    const now = Date.now();

    // Network snapshots are persisted as Alerts by the agent ingestion path.
    // Older/manual network records may still exist as Log documents, so keep
    // those as a backwards-compatible source as well.
    const windowHours = 24;
    const since = new Date(now - windowHours * 60 * 60 * 1000);
    const [snapshots, logs] = await Promise.all([
      Alert.find({
        systemId,
        companyId: req.user.companyId,
        ruleId: 'NET_CONNECTION_SUMMARY',
        createdAt: { $gte: since },
      })
        .select('createdAt connectionCount bytesSent bytesReceived rawEvent')
        .sort({ createdAt: 1 })
        .lean(),
      Log.find({
        systemId,
        companyId: req.user.companyId,
        logType: 'network',
        createdAt: { $gte: since },
      })
        .select('createdAt fields')
        .sort({ createdAt: 1 })
        .lean(),
    ]);

    const numberOrZero = value => Number.isFinite(Number(value)) ? Number(value) : 0;
    const snapshotMetrics = snapshots.map(snapshot => {
      const rawEvent = parseJsonObject(snapshot.rawEvent);
      const raw = parseJsonObject(rawEvent.raw);
      const adapterDelta = parseJsonObject(rawEvent.adapter_delta || raw.adapter_delta);
      const connectionCount = numberOrZero(
        snapshot.connectionCount
          ?? rawEvent.connection_count
          ?? raw.connection_count
          ?? rawEvent.established_count
          ?? raw.established_count,
      );
      const bytes = numberOrZero(snapshot.bytesSent) + numberOrZero(snapshot.bytesReceived)
        || numberOrZero(adapterDelta.bytes_sent) + numberOrZero(adapterDelta.bytes_received);
      const intervalSeconds = Math.max(1, numberOrZero(adapterDelta.interval_seconds));
      return {
        createdAt: snapshot.createdAt,
        connectionCount,
        mbps: bytes > 0 ? (bytes * 8) / intervalSeconds / 1_000_000 : 0,
      };
    });
    const legacyMetrics = logs.map(log => ({
      createdAt: log.createdAt,
      connectionCount: numberOrZero(log.fields?.connectionCount || log.fields?.connection_count) || 1,
      mbps: 0,
    }));
    const events = [...snapshotMetrics, ...legacyMetrics].sort(
      (a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime(),
    );

    // Aggregate by hour
    const hourly = Array(windowHours)
      .fill(0)
      .map((_, i) => {
        const hourStart = now - (windowHours - i - 1) * 60 * 60 * 1000;
        const hourEnd = hourStart + 60 * 60 * 1000;
        const hourEvents = events.filter(l => {
          const time = new Date(l.createdAt).getTime();
          return time >= hourStart && time < hourEnd;
        });

        const totalBytesPerSecond = hourEvents.reduce((sum, event) => sum + (event.mbps || 0), 0);
        return {
          hour: i,
          timestamp: new Date(hourStart).toISOString(),
          mbps: hourEvents.length ? Math.round(totalBytesPerSecond / hourEvents.length) : 0,
          connectionCount: hourEvents.reduce((sum, event) => sum + event.connectionCount, 0),
        };
      });

    const stats = {
      avgMbps: Math.round(hourly.reduce((sum, h) => sum + h.mbps, 0) / windowHours),
      peakMbps: Math.max(...hourly.map(h => h.mbps)),
      totalConnections: hourly.reduce((sum, h) => sum + h.connectionCount, 0),
      telemetrySnapshots: snapshots.length,
    };

    res.json({ hourly, stats });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/summary
   Returns comprehensive system monitoring summary
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/summary', authenticate, requireAnalyst, async (req, res) => {
  try {
    const systemId = req.params.systemId;

    const [system, malwareCount, networkCount, fileCount, logCount, edrCount, usbCount, threatCount] = await Promise.all([
      System.findById(systemId).lean(),
      Alert.countDocuments({ systemId, eventCategory: 'malware', status: 'open' }),
      Alert.countDocuments({ systemId, eventCategory: 'network', status: 'open' }),
      Alert.countDocuments({ systemId, eventCategory: 'file', severity: 'high' }),
      Log.countDocuments({ systemId, level: 'error' }),
      Alert.countDocuments({ systemId, eventCategory: 'edr', status: 'open' }),
      Log.countDocuments({ systemId, logType: 'usb' }),
      Alert.countDocuments({
        systemId,
        $or: [{ vtScore: { $gt: 0 } }, { vtVerdict: 'malicious' }],
      }),
    ]);

    if (!system) return res.status(404).json({ message: 'System not found' });

    const isOnline = system.lastSeen && (Date.now() - new Date(system.lastSeen).getTime()) < 10 * 60 * 1000;

    res.json({
      system: {
        id: system._id,
        name: system.name,
        hostname: system.hostname,
        ip: system.ip,
        os: system.os || system.osType,
        isOnline,
        lastSeen: system.lastSeen,
        agentVersion: system.agentVersion,
      },
      threats: {
        malware: malwareCount,
        network: networkCount,
        file: fileCount,
        edr: edrCount,
        usb: usbCount,
        threats: threatCount,
      },
      logs: {
        errors: logCount,
      },
      services: {
        edr: system.edrEnabled,
        ips: system.ipsEnabled,
        firewall: system.firewallEnabled,
        ids: system.idsEnabled,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/firewall
   Returns firewall events and statistics
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/firewall', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const [logs, alerts] = await Promise.all([
      Log.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        logType: 'firewall',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
      Alert.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        eventCategory: 'network',
        source: 'firewall',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
    ]);

    const counts = {
      total: alerts.length + logs.length,
      alerts: alerts.length,
      logs: logs.length,
      blocked: alerts.filter(a => a.blocked).length + logs.filter(l => l.fields?.blocked).length,
      inbound: alerts.filter(a => a.direction === 'inbound').length,
      outbound: alerts.filter(a => a.direction === 'outbound').length,
      critical: alerts.filter(a => a.severity === 'critical').length,
      high: alerts.filter(a => a.severity === 'high').length,
    };

    res.json({ logs, alerts, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/ips-ids
   Returns IPS/IDS events (Suricata and Zeek)
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/ips-ids', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const [logs, alerts] = await Promise.all([
      Log.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        logType: 'ids',
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
      Alert.find({
        systemId: req.params.systemId,
        companyId: req.user.companyId,
        source: { $in: ['suricata', 'zeek', 'ids', 'ips'] },
      })
        .sort({ createdAt: -1 })
        .limit(Number(limit))
        .lean(),
    ]);

    const counts = {
      total: alerts.length + logs.length,
      alerts: alerts.length,
      logs: logs.length,
      critical: alerts.filter(a => a.severity === 'critical').length,
      high: alerts.filter(a => a.severity === 'high').length,
      medium: alerts.filter(a => a.severity === 'medium').length,
      blocked: alerts.filter(a => a.blocked).length + logs.filter(l => l.fields?.blocked).length,
      detections: logs.filter(l => l.program === 'suricata' || l.program === 'zeek').length,
    };

    res.json({ logs, alerts, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ─────────────────────────────────────────────────────────────────────────
   GET /api/monitoring/system/:systemId/login-activity
   Returns login events and failed login attempts.
   
   FIX: LoginActivity.model.js does NOT have a systemId field — it tracks
   dashboard user logins (admin/analyst auth), not endpoint system logins.
   
   For system-level login events (SSH, local logins on the endpoint) we use
   the Log collection with logType = 'login' | 'auth', which DOES have systemId.
   
   Additionally we return company-wide LoginActivity (dashboard logins)
   separately so the UI can show both if needed.
───────────────────────────────────────────────────────────────────────────── */
router.get('/system/:systemId/login-activity', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { limit = 100 } = req.query;
    const LoginActivity = require('../models/LoginActivity.model');

    // ① System-level login events from the Log collection (has systemId)
    // These are SSH / PAM / Windows Event Log logins on the endpoint itself
    const systemLoginLogs = await Log.find({
      systemId: req.params.systemId,
      companyId: req.user.companyId,
      logType: { $in: ['login', 'auth'] },
    })
      .sort({ createdAt: -1 })
      .limit(Number(limit))
      .lean();

    // ② Alert-level auth events (privilege_escalation, suspicious_cmd classified as edr)
    const authAlerts = await Alert.find({
      systemId: req.params.systemId,
      companyId: req.user.companyId,
      $or: [
        { eventCategory: 'edr', userAction: { $in: ['login', 'logout', 'privilege_escalation'] } },
        { ruleId: { $regex: /auth|login|brute|ssh/i } },
      ],
    })
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    // ③ Combine and normalize so the UI gets a unified list
    const logins = [
      ...systemLoginLogs.map(l => ({
        _id: l._id,
        createdAt: l.createdAt,
        email: l.fields?.user || l.fields?.username || 'unknown',
        action: l.fields?.event || (l.message?.match(/failed/i) ? 'login_failed' : 'login_success'),
        success: !(l.fields?.failed || l.message?.match(/fail|invalid|denied/i)),
        ip: l.fields?.sourceIp || l.ipAddress || '—',
        source: 'system_log',
        raw: l,
      })),
      ...authAlerts.map(a => ({
        _id: a._id,
        createdAt: a.createdAt,
        email: a.username || 'unknown',
        action: a.userAction || 'login',
        success: a.severity === 'low' || a.status === 'resolved',
        ip: a.srcip || '—',
        source: 'alert',
        raw: a,
      })),
    ].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, Number(limit));

    const now = Date.now();
    const last24h = new Date(now - 24 * 60 * 60 * 1000);

    const successful = logins.filter(l => l.success === true).length;
    const failed     = logins.filter(l => l.success === false).length;
    const logouts    = logins.filter(l => l.action === 'logout').length;

    // ── SUSPICIOUS LOGIN DETECTION ──────────────────────────────────────────
    // Flag IPs with > 3 failed logins as suspicious
    const failedByIp = {};
    for (const l of logins) {
      if (!l.success && l.ip && l.ip !== '—') {
        failedByIp[l.ip] = (failedByIp[l.ip] || 0) + 1;
      }
    }
    const suspiciousIPs = Object.keys(failedByIp).filter(ip => failedByIp[ip] > 3);

    // Off-hours detection: logins between 22:00 and 06:00 local
    const offHoursLogins = logins.filter(l => {
      const hr = new Date(l.createdAt).getHours();
      return hr >= 22 || hr < 6;
    });

    const counts = {
      total: logins.length,
      successful,
      failed,
      logouts,
      totalAttempts: successful + failed,  // excludes logouts
      last24h: logins.filter(l => new Date(l.createdAt) > last24h).length,
      uniqueUsers: new Set(logins.map(l => l.email)).size,
      suspiciousIPCount: suspiciousIPs.length,
      suspiciousIPs,
      offHoursCount: offHoursLogins.length,
    };

    res.json({ logins, counts });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
