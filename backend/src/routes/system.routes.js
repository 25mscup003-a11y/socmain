const { emitCompanyPartnerUpdate } = require('../utils/partnerRealtime');
const router = require('express').Router();
const mongoose = require('mongoose');
const System = require('../models/System.model');
const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const AddSystemSubscription = require('../models/AddSystemSubscription.model');
const { authenticate, requireCompanyAdmin, requireManager, requireAnalyst } = require('../middleware/auth.middleware');
const { verifySignedAgentRequest } = require('../utils/agentRequestAuth');
const { identityMismatch, normalizeMac } = require('../utils/agentIdentity');
const { resolveScope } = require('../utils/tenantScope');
const { isBasePlanActive } = require('../utils/subscriptionEntitlement');
const { getCompanyIngestionStatus } = require('../utils/agentEntitlement');
const { resolvePackageForSystem } = require('../utils/agentPackageProfile');
const { isSystemOnline } = require('../utils/systemPresence');

// ── POST /api/system/heartbeat — NO JWT, agent uses agentKey ──────────────────
// Now accepts: hostname, os, osType, osVersion, arch, agentVersion,
//              ip, macAddress, agentId, edrEnabled, idsEnabled, ipsEnabled
router.post('/heartbeat', async (req, res) => {
  const {
    agentKey,
    hostname,
    os, osType,
    osVersion,
    // Accept snake_case alias from older agent versions
    os_version,
    arch,
    agentVersion,
    ip,
    macAddress,
    agentId,
    edrEnabled,
    idsEnabled,
    ipsEnabled,
    firewallEnabled,
    yaraEnabled,
    wafEnabled,
    networkMonitorEnabled,
    usbMonitorEnabled,
    processMonitorEnabled,
    responseEnabled,
    geoEnrichmentEnabled,
    velociraptor_client_id,
    velociraptorClientId,
    client_id,
  } = req.body;

  if (!agentKey) return res.status(400).json({ message: 'agentKey required' });

  try {
    const auth = await verifySignedAgentRequest(req, { agentKey });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message, stop_monitoring: true });

    // Find the current system by signed agentKey
    const existing = await System.findById(auth.system._id);
    const normalizedHeartbeatMac = normalizeMac(macAddress);

    const mismatchReason = identityMismatch(existing, { agentId, macAddress, hostname, osType, os });
    if (mismatchReason) {
      console.warn(`[heartbeat] duplicate install blocked: system=${existing._id} reason=${mismatchReason}`);
      return res.status(409).json({
        ok: false,
        stop_monitoring: true,
        code: 'AGENT_ALREADY_INSTALLED',
        message: `This agent is already installed on another system. ${mismatchReason}. Create a new system and download its own agent.`,
      });
    }

    const scope = await resolveScope({ system: existing, body: req.body, requireSystem: true });
    const ingestionStatus = await getCompanyIngestionStatus(scope.companyId);
    if (!ingestionStatus.allowed) {
      await System.findByIdAndUpdate(existing._id, {
        lastSeen: new Date(),
        status: 'inactive',
        isActive: false,
      });
      return res.json({
        ok: false,
        active: false,
        stop_monitoring: true,
        code: ingestionStatus.code,
        message: ingestionStatus.message,
        system_id: existing._id,
        plan_expires_at: ingestionStatus.expiresAt || null,
      });
    }

    // ── Cross-record endpoint identity enforcement ────────────────────────────
    // Inactive/expired records stay reserved so a second key cannot take over the
    // same physical endpoint while its original subscription is being renewed.
    let identityOwner = null;
    const incomingAgentId = String(agentId || '').trim();
    const duplicateIdentityChecks = [];
    if (incomingAgentId) duplicateIdentityChecks.push({ agentId: incomingAgentId });
    if (normalizedHeartbeatMac) duplicateIdentityChecks.push({ macAddress: normalizedHeartbeatMac });
    if (duplicateIdentityChecks.length) {
      identityOwner = await System.findOne({
        companyId: existing.companyId,
        $or: duplicateIdentityChecks,
      })
        .sort({ lastSeen: -1, installDate: -1, createdAt: 1 })
        .select('_id name agentId macAddress isActive lastSeen installDate createdAt')
        .lean();
    }
    if (identityOwner && String(identityOwner._id) !== String(existing._id)) {
      console.warn(`[heartbeat] cross-record endpoint duplicate blocked: incoming=${existing._id} owner=${identityOwner._id}`);
      return res.status(409).json({
        ok: false,
        active: false,
        stop_monitoring: true,
        code: 'DUPLICATE_ENDPOINT_IDENTITY',
        message: `This endpoint is already registered as ${identityOwner.name || 'another system'}. Recharge or reactivate its original agent instead of installing a second agent key.`,
        system_id: existing._id,
      });
    }

    // ── Duplicate detection by MAC address ────────────────────────────────────
    let macDuplicateWarning = null;
    if (normalizedHeartbeatMac) {
      const duplicate = await System.findOne({
        companyId: existing.companyId,
        macAddress: normalizedHeartbeatMac,
        agentKey: { $ne: agentKey },
        isActive: true,
      });
      if (duplicate) {
        console.warn(`[heartbeat] MAC duplicate detected: ${macAddress} – system ${existing._id} vs ${duplicate._id}`);
        macDuplicateWarning = `MAC ${macAddress} already registered on another system (${duplicate.name || duplicate._id})`;
      }
    }

    // Resolve OS version from both aliases
    const resolvedOsVersion = osVersion || os_version;

    // Auto-generate agentId (UUID) on first heartbeat if not provided
    const resolvedAgentId = agentId || existing.agentId ||
      require('crypto').randomUUID();

    const now = new Date();
    const sysUpdate = {
      lastSeen: now,
      status: 'active',
      isActive: true,
      tenantId: scope.tenantId,
      partnerId: scope.partnerId,
      ...(hostname && { hostname }),
      ...(ip && { ip }),
      ...(normalizedHeartbeatMac && { macAddress: normalizedHeartbeatMac }),
      ...(resolvedAgentId && { agentId: resolvedAgentId }),
      ...(os && { os }),
      ...(osType && { osType }),
      ...(resolvedOsVersion && { osVersion: resolvedOsVersion }),
      ...(arch && { arch }),
      ...(agentVersion && { agentVersion }),
      ...((velociraptor_client_id || velociraptorClientId || client_id)
        && (!existing.velociraptorClientId || existing.velociraptorClientId === (velociraptor_client_id || velociraptorClientId || client_id)) && {
        velociraptorClientId: velociraptor_client_id || velociraptorClientId || client_id,
      }),
    };

    if (typeof edrEnabled === 'boolean') sysUpdate.edrEnabled = edrEnabled;
    if (typeof idsEnabled === 'boolean') sysUpdate.idsEnabled = idsEnabled;
    if (typeof ipsEnabled === 'boolean') sysUpdate.ipsEnabled = ipsEnabled;
    if (typeof firewallEnabled === 'boolean') sysUpdate.firewallEnabled = firewallEnabled;
    if (typeof yaraEnabled === 'boolean') sysUpdate.yaraEnabled = yaraEnabled;
    if (typeof wafEnabled === 'boolean') sysUpdate.wafEnabled = wafEnabled;
    if (typeof networkMonitorEnabled === 'boolean') sysUpdate.networkMonitorEnabled = networkMonitorEnabled;
    if (typeof usbMonitorEnabled === 'boolean') sysUpdate.usbMonitorEnabled = usbMonitorEnabled;
    if (typeof processMonitorEnabled === 'boolean') sysUpdate.processMonitorEnabled = processMonitorEnabled;
    if (typeof responseEnabled === 'boolean') sysUpdate.responseEnabled = responseEnabled;
    if (typeof geoEnrichmentEnabled === 'boolean') sysUpdate.geoEnrichmentEnabled = geoEnrichmentEnabled;

    // Set installDate on first activation
    if (!existing.installDate) sysUpdate.installDate = now;
    if (!existing.fimStartAt) sysUpdate.fimStartAt = existing.installDate || sysUpdate.installDate || existing.createdAt || now;

    const system = await System.findByIdAndUpdate(existing._id, sysUpdate, { new: true });
    if (existing.status !== system.status || !existing.agentVersion) {
      void emitCompanyPartnerUpdate(req.app?.get?.('io'), system.companyId, 'agent_status');
    }
    const commandClaim = await System.findByIdAndUpdate(
      existing._id,
      // Security actions and OTA updates are acknowledged on the primary
      // heartbeat. A fallback delivery must not erase their durable record.
      { $pull: { pendingCommands: {
        auditId: { $exists: false },
        command: { $nin: ['update', 'security-policy-sync', 'verify-integrity', 'security-force-recovery', 'security-lockdown', 'security-unlock',
          'isolate', 'reconnect', 'block_ip', 'unblock_ip', 'block_domain', 'unblock_domain', 'block_application', 'unblock_application',
          'block_port', 'close_port', 'unblock_port', 'block_protocol', 'unblock_protocol', 'ips_whitelist_add', 'ips_whitelist_remove'] },
      } } },
      { new: false },
    ).select('pendingCommands');
    const pendingCommands = await require('../services/ipsIsolationGuard.service').filterDeliverableCommands({
      companyId: system.companyId, systemId: system._id,
      commands: (commandClaim?.pendingCommands || []).filter(command => command.command !== 'update'
        || !['downloading', 'installing'].includes(system.updateStatus)),
    });
    const fimStartAt = system.fimStartAt || system.installDate || now;

    // Emit real-time status update to monitoring dashboards
    const io = req.app?.get?.('io');
    if (io && system.companyId) {
      io.to(`company:${system.companyId}`).emit('system:status_changed', {
        systemId: system._id,
        name: system.name,
        status: 'active',
        lastSeen: system.lastSeen,
        ip: system.ip,
        hostname: system.hostname,
      });
    }

    res.json({
      ok: true,
      systemId: system._id,
      systemName: system.name,
      commands: pendingCommands,
      is_isolated: system.isIsolated === true,
      config_update: {
        fim_start_at: fimStartAt.toISOString(),
        file_monitor_start_at: fimStartAt.toISOString(),
        yara_enabled: true,
        lolbins_poll_interval: 30,
        process_poll_interval_seconds: 30,
        process_inventory_interval_seconds: 60,
        send_ids_routine_telemetry: false,
        ids_detection_window_seconds: 60,
        ids_alert_cooldown_seconds: 900,
        ids_sensor_dedupe_seconds: 900,
        ids_port_scan_threshold: 15,
        ids_brute_force_threshold: 10,
      },
      ...(macDuplicateWarning && { warning: macDuplicateWarning }),
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// All routes below require JWT
router.use(authenticate);

// ── POST /api/system — Create a new system ────────────────────────────────────
router.post('/', requireCompanyAdmin, async (req, res) => {
  const { name, departmentId } = req.body;
  const agentType = ['system', 'server', 'phone'].includes(req.body.agentType)
    ? req.body.agentType
    : 'system';
  const allowedOsTypes = ['Linux', 'Darwin', 'Windows', 'Solaris', 'Android', 'iOS'];
  const osType = allowedOsTypes.includes(req.body.osType) ? req.body.osType : undefined;
  const os = typeof req.body.os === 'string' && req.body.os.trim()
    ? req.body.os.trim()
    : undefined;
  const preferredPackageType = typeof req.body.preferredPackageType === 'string'
    ? req.body.preferredPackageType.trim().toLowerCase()
    : undefined;
  if (!name || !departmentId)
    return res.status(400).json({ message: 'name and departmentId are required' });
  try {
    const packageProfile = resolvePackageForSystem(
      { agentType, os, osType, preferredPackageType },
      preferredPackageType || 'auto',
    );
    const activeTypeFilter = agentType === 'system'
      ? { $or: [{ agentType: 'system' }, { agentType: { $exists: false } }] }
      : { agentType };

    const [company, activeCount] = await Promise.all([
      Company.findById(req.user.companyId),
      System.countDocuments({ companyId: req.user.companyId, isActive: true, ...activeTypeFilter }),
    ]);
    if (!company) return res.status(404).json({ message: 'Company not found' });

    // ✅ REAL-TIME LIMIT: computed fresh from DB every request
    // effectiveLimit = baseSystems (from registration) + addedSystems (active batches)
    // This NEVER trusts stale plan.systemCount — reads source of truth directly.
    const companyOid = new mongoose.Types.ObjectId(req.user.companyId.toString());
    const now = new Date();

    // Expire stale add-system batches
    await AddSystemSubscription.updateMany(
      { companyId: companyOid, status: 'active', endDate: { $lt: now } },
      { $set: { status: 'expired' } }
    );

    // Sum active add-system batches (added AFTER registration)
    const batchAgg = await AddSystemSubscription.aggregate([
      { $match: { companyId: companyOid, status: 'active' } },
      {
        $group: {
          _id: null,
          totalSys: { $sum: '$addedSystemCount' },
          totalSrv: { $sum: '$addedServerCount' },
          totalPhn: { $sum: '$addedPhoneCount' },
        },
      },
    ]);
    const addedSystems = batchAgg[0]?.totalSys || 0;
    const addedServers = batchAgg[0]?.totalSrv || 0;
    const addedPhones = batchAgg[0]?.totalPhn || 0;

    const hasPaidBasePlan = isBasePlanActive(company.plan, now);
    const typeCfg = {
      system: { label: 'systems', baseKey: 'baseSystemCount', totalKey: 'systemCount', added: addedSystems },
      server: { label: 'servers', baseKey: 'baseServerCount', totalKey: 'serverCount', added: addedServers },
      phone: { label: 'phones', baseKey: 'basePhoneCount', totalKey: 'phoneCount', added: addedPhones },
    }[agentType];
    const storedBaseCount = Number(company.plan?.[typeCfg.baseKey]) || 0;
    const currentTotalCount = Number(company.plan?.[typeCfg.totalKey]) || 0;
    const registrationCount = hasPaidBasePlan
      ? (storedBaseCount > 0 ? storedBaseCount : Math.max(0, currentTotalCount - typeCfg.added))
      : 0;

    const effectiveLimit = registrationCount + typeCfg.added;

    console.log(`[system/create] type=${agentType} | base=${registrationCount} | batches=${typeCfg.added} | limit=${effectiveLimit} | active=${activeCount}`);

    if (effectiveLimit === 0)
      return res.status(403).json({
        message: `No ${typeCfg.label} in your plan. Purchase ${typeCfg.label} from Payments.`,
        limit: 0, current: activeCount,
      });
    if (activeCount >= effectiveLimit)
      return res.status(403).json({
        message: `Plan limit reached for ${typeCfg.label}. You have ${registrationCount} base + ${typeCfg.added} added = ${effectiveLimit} total (${activeCount} used).`,
        limit: effectiveLimit, baseCount: registrationCount, addedCount: typeCfg.added, current: activeCount,
      });

    const dept = await Department.findOne({ _id: departmentId, companyId: req.user.companyId });
    if (!dept) return res.status(404).json({ message: 'Department not found' });

    const deptLimitByType = {
      system: Number(dept.assignedSystemCount) || 0,
      server: Number(dept.assignedServerCount) || 0,
      phone: Number(dept.assignedPhoneCount) || 0,
    };
    const deptTypeFilter = agentType === 'system'
      ? { $or: [{ agentType: 'system' }, { agentType: { $exists: false } }] }
      : { agentType };
    const deptUsed = await System.countDocuments({
      companyId: req.user.companyId,
      departmentId,
      isActive: true,
      ...deptTypeFilter,
    });
    const deptLimit = deptLimitByType[agentType] || 0;
    if (deptLimit === 0) {
      return res.status(403).json({
        message: `No ${typeCfg.label} assigned to department "${dept.name}". Edit allocation in Departments first.`,
        limit: 0,
        current: deptUsed,
      });
    }
    if (deptUsed >= deptLimit) {
      return res.status(403).json({
        message: `Department "${dept.name}" ${typeCfg.label} allocation reached (${deptUsed}/${deptLimit}). Edit allocation in Departments first.`,
        limit: deptLimit,
        current: deptUsed,
      });
    }

    const system = await System.create({
      name: name.trim(),
      tenantId: company.tenantId || null,
      partnerId: company.partnerId || null,
      companyId: req.user.companyId,
      departmentId,
      agentType,
      ...(os && { os }),
      ...(osType && { osType }),
      preferredPackageType: packageProfile.type,
    });
    await Department.findByIdAndUpdate(departmentId, { $inc: { systemCount: 1 } });
    void emitCompanyPartnerUpdate(req.app?.get?.('io'), system.companyId, 'agent_created');
    res.status(201).json(system);
  } catch (err) { res.status(400).json({ message: err.message }); }
});


// ── GET /api/system — List systems with online/offline status ─────────────────
router.get('/', requireAnalyst, async (req, res) => {
  try {
    const Company = require('../models/Company.model');
    const Department = require('../models/Department.model');

    let companyId = req.user.companyId;
    if (!companyId && (req.user.role === 'superadmin' || req.user.role === 'company_admin' || req.user.role === 'partner_admin')) {
      const firstCo = await Company.findOne().sort({ createdAt: 1 }).lean();
      if (firstCo) companyId = firstCo._id;
    }

    const filter = {};
    if (companyId) filter.companyId = companyId;
    if (req.user.role === 'department_admin' && req.user.departmentId) filter.departmentId = req.user.departmentId;
    if (req.query.departmentId) filter.departmentId = req.query.departmentId;

    const systems = await System.find(filter)
      .populate('departmentId', 'name')
      .sort({ lastSeen: -1, createdAt: -1 });

    const now = Date.now();
    const enriched = systems.map(s => {
      const obj = s.toObject();
      obj.isOnline = isSystemOnline(s, now);
      return obj;
    });

    res.json(enriched);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── GET /api/system/:id ───────────────────────────────────────────────────────
router.get('/:id', requireAnalyst, async (req, res) => {
  try {
    const system = await System.findOne({ _id: req.params.id, companyId: req.user.companyId })
      .populate('departmentId', 'name');
    if (!system) return res.status(404).json({ message: 'System not found' });
    const obj = system.toObject();
    obj.isOnline = isSystemOnline(system);
    res.json(obj);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── PATCH /api/system/:id — Update system ────────────────────────────────────
router.patch('/:id', requireCompanyAdmin, async (req, res) => {
  try {
    const ALLOWED = [
      'name', 'edrEnabled', 'idsEnabled', 'ipsEnabled', 'firewallEnabled', 'yaraEnabled',
      'geoEnrichmentEnabled', 'geoFenceEnabled', 'geoFenceLat', 'geoFenceLon',
      'geoFenceRadiusMeters', 'geoFenceLockOnViolation',
    ];
    const update = {};
    ALLOWED.forEach(k => { if (req.body[k] !== undefined) update[k] = req.body[k]; });
    const packageFieldsRequested = ['os', 'osType', 'preferredPackageType']
      .some(key => req.body[key] !== undefined);
    if (packageFieldsRequested) {
      const existing = await System.findOne({ _id: req.params.id, companyId: req.user.companyId });
      if (!existing) return res.status(404).json({ message: 'System not found' });
      if (existing.agentVersion) {
        return res.status(409).json({
          message: 'Installed agent OS/package profile cannot be changed. Use its existing update format.',
          code: 'AGENT_PROFILE_LOCKED',
        });
      }
      const candidate = {
        agentType: existing.agentType,
        os: req.body.os ?? existing.os,
        osType: req.body.osType ?? existing.osType,
        preferredPackageType: req.body.preferredPackageType ?? existing.preferredPackageType,
      };
      const packageProfile = resolvePackageForSystem(candidate, candidate.preferredPackageType || 'auto');
      update.os = candidate.os;
      update.osType = candidate.osType;
      update.preferredPackageType = packageProfile.type;
    }
    const system = await System.findOneAndUpdate(
      { _id: req.params.id, companyId: req.user.companyId },
      update, { new: true }
    );
    if (!system) return res.status(404).json({ message: 'System not found' });
    res.json(system);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// ── DELETE /api/system/:id ───────────────────────────────────────────────────
router.delete('/:id', requireCompanyAdmin, async (req, res) => {
  try {
    const system = await System.findOneAndUpdate(
      { _id: req.params.id, companyId: req.user.companyId },
      { isActive: false, status: 'inactive' }, { new: true }
    );
    if (!system) return res.status(404).json({ message: 'System not found' });
    await Department.findByIdAndUpdate(system.departmentId, { $inc: { systemCount: -1 } });
    res.json({ message: 'System removed' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── POST /api/system/:id/offline — Agent notifies server before uninstalling ──────────────────
router.post('/:id/offline', async (req, res) => {
  try {
    const system = await System.findByIdAndUpdate(
      req.params.id,
      {
        status: 'disconnected',
        isActive: true,
        lastSeen: new Date(),
        agentVersion: null,
        installDate: null,
        fimStartAt: null,
      },
      { new: true }
    );
    if (!system) return res.status(404).json({ message: 'System not found' });
    console.log(`[System] ${system.hostname} marked OFFLINE by uninstall script`);
    void emitCompanyPartnerUpdate(req.app?.get?.('io'), system.companyId, 'agent_status');
    res.json({ message: 'System marked offline', system });
  } catch (err) {
    console.error('[System /offline]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/system/:id/isolate — Isolate a system from the network ──────────
router.post('/:id/isolate', requireManager, async (req, res) => {
  try {
    const { reason } = req.body;
    const system = await System.findOne({ _id: req.params.id, companyId: req.user.companyId, isActive: true });
    if (!system) return res.status(404).json({ message: 'System not found' });
    const { queueEndpointCommand } = require('../services/ips.service');
    const delivery = await queueEndpointCommand({
      companyId: req.user.companyId,
      systemId: system._id,
      command: 'isolate',
      reason: reason || 'Manually isolated from dashboard',
    });
    const updated = await System.findById(system._id);
    console.log(`[System] ${system.name} isolation ${delivery.confirmed ? 'confirmed' : 'queued'} — ${reason || 'manual dashboard action'}`);
    const failed = delivery.status === 'failed' || delivery.status === 'no-target';
    res.status(delivery.confirmed ? 200 : failed ? 502 : 202).json({
      ok: delivery.confirmed === true,
      message: delivery.confirmed ? 'System isolation confirmed by endpoint' : failed ? (delivery.message || 'System isolation failed') : 'System isolation queued; waiting for endpoint acknowledgement',
      delivery,
      system: updated,
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── DELETE /api/system/:id/isolate — Reconnect a system (lift isolation) ──────
router.delete('/:id/isolate', requireManager, async (req, res) => {
  try {
    const system = await System.findOne({ _id: req.params.id, companyId: req.user.companyId, isActive: true });
    if (!system) return res.status(404).json({ message: 'System not found' });
    const { queueEndpointCommand } = require('../services/ips.service');
    const delivery = await queueEndpointCommand({
      companyId: req.user.companyId,
      systemId: system._id,
      command: 'reconnect',
      reason: 'Manual reconnect from dashboard',
    });
    const updated = await System.findById(system._id);
    console.log(`[System] ${system.name} reconnect ${delivery.confirmed ? 'confirmed' : 'queued'}`);
    const failed = delivery.status === 'failed' || delivery.status === 'no-target';
    res.status(delivery.confirmed ? 200 : failed ? 502 : 202).json({
      ok: delivery.confirmed === true,
      message: delivery.confirmed ? 'System reconnection confirmed by endpoint' : failed ? (delivery.message || 'System reconnection failed') : 'System reconnection queued; waiting for endpoint acknowledgement',
      delivery,
      system: updated,
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
