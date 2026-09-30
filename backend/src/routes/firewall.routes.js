const express = require('express');
const router = express.Router();
const Firewall = require('../models/Firewall.model');
const System = require('../models/System.model');
const Department = require('../models/Department.model');
const Company = require('../models/Company.model');
const User = require('../models/User.model');
const { authenticate, requireCompanyAdmin, requireManager } = require('../middleware/auth.middleware');
const { verifySignedAgentRequest } = require('../utils/agentRequestAuth');

// ── Helper: Apply rule to nftables (Linux) via agent command ─────────────────
async function applyNftablesRule(rule, action = 'block') {
  // nftables rules are applied on the endpoint via the SOC agent (Socket.IO).
  // This function logs intent — actual enforcement is via broadcastRuleToAgents.
  const c = rule.conditions || {};
  const ip = c.ipAddress || '';
  const port = c.port || '';
  const protocol = (c.protocol && c.protocol !== 'all') ? c.protocol : 'tcp';
  const nftCmd = action === 'block'
    ? `nft add rule inet filter input${ip ? ` ip saddr ${ip}` : ''}${port ? ` ${protocol} dport ${port}` : ''} drop`
    : `nft delete rule inet filter input handle <handle>`;
  console.log(`[nftables] Rule "${rule.ruleName}" (${action}): ${nftCmd}`);
}

// ── Helper: Apply rule to Windows Defender Firewall via agent command ─────────
async function applyWindowsDefenderRule(rule, action = 'block') {
  // Windows Defender Firewall rules are applied on the endpoint via the SOC agent.
  // This function logs intent — actual enforcement is via broadcastRuleToAgents.
  const c = rule.conditions || {};
  const ip = c.ipAddress || '';
  const port = c.port || '';
  const wfCmd = action === 'block'
    ? `netsh advfirewall firewall add rule name="SOC: ${rule.ruleName}" dir=in action=block${ip ? ` remoteip=${ip}` : ''}${port ? ` localport=${port} protocol=tcp` : ''}`
    : `netsh advfirewall firewall delete rule name="SOC: ${rule.ruleName}"`;
  console.log(`[WindowsDefender] Rule "${rule.ruleName}" (${action}): ${wfCmd}`);
}

// ── Helper: Broadcast firewall rule to agents ──────────────────────────────
async function broadcastRuleToAgents(io, rule) {
  try {
    const ft = (rule.firewallType || '').toLowerCase();

    // nftables (Linux) → log the nft command intent, agents apply via Socket.IO
    if (ft === 'nftables') {
      await applyNftablesRule(rule, rule.action);
    }
    // Windows Defender Firewall → log the netsh command intent, agents apply via Socket.IO
    if (ft === 'windows_defender') {
      await applyWindowsDefenderRule(rule, rule.action);
    }

    // nftables / Windows Defender → send to agent(s) via Socket.IO
    const targetRooms = [];
    const rulePayload = {
      ruleId:       rule._id,
      ruleName:     rule.ruleName,
      action:       rule.action,
      direction:    rule.direction || 'both',   // ← FIXED: always include direction
      conditions:   rule.conditions,
      level:        rule.level,
      firewallType: rule.firewallType,
      priority:     rule.priority,
    };

    if (rule.level === 'global') {
      io.emit('firewall:rule_applied', rulePayload);
      console.log('[Firewall] Broadcasted GLOBAL rule to all agents:', rule.ruleName);
    } else if (rule.level === 'company') {
      if (rule.companyId) {
        io.to(`company:${rule.companyId}`).emit('firewall:rule_applied', rulePayload);
        console.log(`[Firewall] Broadcasted company rule "${rule.ruleName}" to company:${rule.companyId}`);
      }
    } else if (rule.level === 'department') {
      const systems = await System.find({
        departmentId: { $in: rule.departmentIds },
        isActive: true,
      });
      for (const system of systems) targetRooms.push(`system_${system._id}`);
    } else if (rule.level === 'system') {
      targetRooms.push(`system_${rule.systemId}`);
    }

    for (const room of targetRooms) {
      io.to(room).emit('firewall:rule_applied', rulePayload);
    }
    if (targetRooms.length > 0) {
      console.log(`[Firewall] Broadcasted rule "${rule.ruleName}" to ${targetRooms.length} system(s):`, targetRooms);
    }
  } catch (err) {
    console.error('[Firewall] Failed to broadcast rule:', err.message);
  }
}

// ── Helper: Send domain block to IPS Server dashboard ─────────────────────────
function getIpsSyncFailure(response, action) {
  const status = response?.status;
  const data = response?.data || {};
  const operation = action === 'unblock' ? 'unenforcement' : 'enforcement';
  const fallback = `IPS ${operation} failed (HTTP ${status ?? 'unknown'})`;

  if (status < 200 || status >= 300 || data.ok === false) {
    return data.error || data.message || fallback;
  }

  // In endpoint-agent mode the IPS server accepts and persists the request,
  // while the enrolled endpoint performs the OS-firewall operation. This is a
  // valid handoff, not a central-firewall enforcement failure.
  const delegatedToEndpoint = data.delegated === true && data.method === 'endpoint-agent';
  if (data.method === 'log-only') {
    return data.error || data.message || `${fallback}: IPS server is in log-only mode`;
  }
  if (data.enforced === false && !delegatedToEndpoint) {
    return data.error || data.message || fallback;
  }

  return null;
}

async function syncDomainBlockToIPS(rule) {
  const axios = require('axios');
  try {
    const IPS_WEBHOOK_URL = process.env.IPS_WEBHOOK_URL || '';
    const IPS_WEBHOOK_SECRET = process.env.IPS_WEBHOOK_SECRET || '';
    
    if (!IPS_WEBHOOK_URL) return; // IPS not configured
    
    // Sync all block types (not just domain/IP)
    if (rule.action !== 'block') {
      return;
    }
    
    // Check if there's any blockable condition
    const c = rule.conditions;
    if (!c.domain && !c.ipAddress && !c.port && !c.application && !c.blockProtocol) {
      return;
    }
    
    const companyIds = rule.companyId
      ? [String(rule.companyId)]
      : (await Company.find({ status: 'active' }).select('_id').lean()).map(company => String(company._id));
    if (!companyIds.length) return;
    const results = await Promise.allSettled(companyIds.map(async companyId => {
      const blockData = {
        company_id: companyId,
        rule_id: String(rule._id),
        action: 'block',
        ip: rule.conditions.ipAddress || undefined,
        domain: rule.conditions.domain || rule.conditions.host || undefined,
        port: rule.conditions.port || undefined,
        application: rule.conditions.application || undefined,
        protocol: rule.conditions.blockProtocol || (rule.conditions.protocol !== 'all' ? rule.conditions.protocol : undefined),
        direction: rule.direction || 'both',
        reason: `[${rule.level}] ${rule.ruleName}: ${rule.description || ''}`,
      };
      const response = await axios.post(IPS_WEBHOOK_URL + '/webhook', blockData, {
        headers: {
          'Content-Type': 'application/json',
          'x-webhook-secret': IPS_WEBHOOK_SECRET,
          'X-Company-ID': companyId,
        },
        timeout: 5000,
        validateStatus: () => true,
      });
      const failure = getIpsSyncFailure(response, 'block');
      if (failure) throw new Error(failure);
    }));
    const failures = results.filter(result => result.status === 'rejected');
    if (failures.length) throw new Error(`${failures.length}/${companyIds.length} tenant sync(s) failed: ${failures[0].reason.message}`);
    console.log(`[IPS Sync] Block synced for ${companyIds.length} compan${companyIds.length === 1 ? 'y' : 'ies'}: ${rule.ruleName}`);
  } catch (err) {
    // Non-fatal error - still create rule even if IPS sync fails
    console.warn(`[IPS Sync] Failed to sync block to IPS Server: ${err.message}`);
  }
}

// ── Helper: Send domain unblock to IPS Server dashboard ────────────────────────
async function syncDomainUnblockToIPS(rule) {
  const axios = require('axios');
  try {
    const IPS_WEBHOOK_URL = process.env.IPS_WEBHOOK_URL || '';
    const IPS_WEBHOOK_SECRET = process.env.IPS_WEBHOOK_SECRET || '';
    
    if (!IPS_WEBHOOK_URL) return; // IPS not configured
    
    // Only sync if there's something to unblock
    const c = rule.conditions;
    if (!c.domain && !c.ipAddress && !c.port && !c.application && !c.blockProtocol) {
      return;
    }
    
    const companyIds = rule.companyId
      ? [String(rule.companyId)]
      : (await Company.find({ status: 'active' }).select('_id').lean()).map(company => String(company._id));
    if (!companyIds.length) return;
    const results = await Promise.allSettled(companyIds.map(async companyId => {
      const unblockData = {
        company_id: companyId,
        rule_id: String(rule._id),
        action: 'unblock',
        ip: rule.conditions.ipAddress || undefined,
        domain: rule.conditions.domain || rule.conditions.host || undefined,
        port: rule.conditions.port || undefined,
        application: rule.conditions.application || undefined,
        protocol: rule.conditions.blockProtocol || (rule.conditions.protocol !== 'all' ? rule.conditions.protocol : undefined),
        direction: rule.direction || 'both',
        reason: `Unblocked: ${rule.ruleName}`,
      };
      const response = await axios.post(IPS_WEBHOOK_URL + '/webhook', unblockData, {
        headers: {
          'Content-Type': 'application/json',
          'x-webhook-secret': IPS_WEBHOOK_SECRET,
          'X-Company-ID': companyId,
        },
        timeout: 5000,
        validateStatus: () => true,
      });
      const failure = getIpsSyncFailure(response, 'unblock');
      if (failure) throw new Error(failure);
    }));
    const failures = results.filter(result => result.status === 'rejected');
    if (failures.length) throw new Error(`${failures.length}/${companyIds.length} tenant sync(s) failed: ${failures[0].reason.message}`);
    console.log(`[IPS Sync] Unblock synced for ${companyIds.length} compan${companyIds.length === 1 ? 'y' : 'ies'}: ${rule.ruleName}`);
  } catch (err) {
    // Non-fatal error - still delete rule even if IPS sync fails
    console.warn(`[IPS Sync] Failed to sync unblock to IPS Server: ${err.message}`);
  }
}

// An allow rule is a security boundary, not merely a UI preference.  Remove a
// matching IPS block immediately and distribute the unblock to installed agents.
async function enforceAllowRulePrecedence(rule) {
  if (rule.action !== 'allow' || !rule.enabled || !rule.companyId) return;
  const ip = rule.conditions?.ipAddress;
  if (!ip || String(ip).includes('/')) return; // CIDR is enforced during future IPS decisions.
  await require('../services/ips.service').unblockIP({
    ip,
    companyId: rule.companyId,
    reason: `Firewall allow rule takes precedence: ${rule.ruleName}`,
  });
}

// ── Middleware ─────────────────────────────────────────────────────────────────
const companyAuth = authenticate;

function buildApplicableRulesQuery(system, now = new Date()) {
  return {
    enabled: true,
    $and: [
      { $or: [
        { expiresAt: { $exists: false } },
        { expiresAt: null },
        { expiresAt: { $gt: now } },
      ] },
      { $or: [
        { level: 'global' },
        { companyId: system.companyId, level: 'company' },
        { companyId: system.companyId, level: 'department', departmentIds: system.departmentId },
        { companyId: system.companyId, level: 'system', systemId: system._id },
      ] },
    ],
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────────
async function validateCompanyAccess(req, companyId) {
  if (req.user?.role === 'superadmin') return true;
  if (!companyId) return false;
  const company = await Company.findById(companyId);
  if (!company) return false;
  return company._id.toString() === req.user.companyId?.toString();
}

async function departmentFirewallScope(req) {
  if (req.user?.role !== 'department_admin') return null;
  if (!req.user.departmentId || !req.user.companyId) return { departmentId: null, systemIds: [] };
  const systemIds = await System.find({
    companyId: req.user.companyId,
    departmentId: req.user.departmentId,
  }).distinct('_id');
  return { departmentId: req.user.departmentId, systemIds };
}

async function canManageFirewallRule(req, rule) {
  if (req.user?.role !== 'department_admin') return true;
  if (!rule || !req.user.departmentId) return false;
  if (rule.level === 'department') {
    return (rule.departmentIds || []).some(id => String(id) === String(req.user.departmentId));
  }
  if (rule.level === 'system' && rule.systemId) {
    return Boolean(await System.exists({
      _id: rule.systemId,
      companyId: req.user.companyId,
      departmentId: req.user.departmentId,
    }));
  }
  return false;
}

// ── GET /api/firewall/rules?level=company|department|system|global&systemId=xxx ──────
router.get('/rules', companyAuth, async (req, res) => {
  try {
    const { level, systemId, departmentId, companyId: queryCompanyId } = req.query;
    
    // Handle global rules (no companyId needed)
    if (level === 'global') {
      if (req.user.role === 'department_admin') {
        return res.status(403).json({ message: 'Department admins can access department and system rules only' });
      }
      const rules = await Firewall.find({ level: 'global' })
        .sort({ priority: 1, createdAt: -1 })
        .populate('createdBy', 'name email')
        .populate('updatedBy', 'name email')
        .lean();
      return res.json({ rules, count: rules.length });
    }
    
    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const query = { companyId };
    const departmentScope = await departmentFirewallScope(req);

    if (departmentScope) {
      if (!departmentScope.departmentId || level === 'company') {
        if (level === 'company') return res.status(403).json({ message: 'Company-level firewall access denied' });
        return res.json({ rules: [], count: 0 });
      }
      if (departmentId && String(departmentId) !== String(departmentScope.departmentId)) {
        return res.status(403).json({ message: 'Department firewall access denied' });
      }
      if (systemId && !departmentScope.systemIds.some(id => String(id) === String(systemId))) {
        return res.status(403).json({ message: 'System firewall access denied' });
      }
      query.$or = level === 'department'
        ? [{ level: 'department', departmentIds: departmentScope.departmentId }]
        : level === 'system'
          ? [{ level: 'system', systemId: { $in: systemId ? [systemId] : departmentScope.systemIds } }]
          : [
              { level: 'department', departmentIds: departmentScope.departmentId },
              { level: 'system', systemId: { $in: departmentScope.systemIds } },
            ];
    } else {
      if (level) query.level = level;
      if (systemId) query.systemId = systemId;
      if (departmentId) query.departmentIds = departmentId;
    }

    const rules = await Firewall.find(query)
      .sort({ priority: 1, createdAt: -1 })
      .populate('createdBy', 'name email')
      .populate('updatedBy', 'name email')
      .lean();

    res.json({ rules, count: rules.length });
  } catch (err) {
    console.error('[firewall/rules]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/firewall/company-rules ────────────────────────────────────────────
router.get('/company-rules', companyAuth, async (req, res) => {
  try {
    if (req.user.role === 'department_admin') {
      return res.status(403).json({ message: 'Company-level firewall access denied' });
    }
    const { companyId: queryCompanyId } = req.query;
    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const rules = await Firewall.find({ companyId, level: 'company', enabled: true })
      .sort({ priority: 1, createdAt: -1 })
      .lean();

    res.json({ rules, count: rules.length });
  } catch (err) {
    console.error('[firewall/company-rules]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/firewall/department-rules?departmentId=xxx ────────────────────────
router.get('/department-rules', companyAuth, async (req, res) => {
  try {
    const { departmentId, companyId: queryCompanyId } = req.query;
    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const query = { companyId, level: 'department', enabled: true };
    if (req.user.role === 'department_admin') {
      if (!req.user.departmentId) return res.json({ rules: [], count: 0 });
      if (departmentId && String(departmentId) !== String(req.user.departmentId)) {
        return res.status(403).json({ message: 'Department firewall access denied' });
      }
      query.departmentIds = req.user.departmentId;
    } else if (departmentId) query.departmentIds = departmentId;

    const rules = await Firewall.find(query)
      .sort({ priority: 1, createdAt: -1 })
      .lean();

    res.json({ rules, count: rules.length });
  } catch (err) {
    console.error('[firewall/department-rules]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/firewall/system-rules?systemId=xxx ────────────────────────────────
router.get('/system-rules', companyAuth, async (req, res) => {
  try {
    const { systemId, companyId: queryCompanyId } = req.query;
    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    if (!systemId) return res.status(400).json({ message: 'systemId required' });

    if (req.user.role === 'department_admin') {
      const inScope = await System.exists({
        _id: systemId,
        companyId,
        departmentId: req.user.departmentId,
      });
      if (!inScope) return res.status(403).json({ message: 'System firewall access denied' });
    }

    const rules = await Firewall.find({
      companyId,
      systemId,
      level: 'system',
      enabled: true,
    })
      .sort({ priority: 1, createdAt: -1 })
      .lean();

    res.json({ rules, count: rules.length });
  } catch (err) {
    console.error('[firewall/system-rules]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/firewall/rules ───────────────────────────────────────────────────
router.post('/rules', companyAuth, requireManager, async (req, res) => {
  try {
    const { companyId: queryCompanyId } = req.query;
    const { level } = req.body;

    // Handle global rules (super admin only)
    if (level === 'global') {
      if (req.user.role !== 'superadmin') {
        return res.status(403).json({ message: 'Only super admin can create global rules' });
      }
      
      const {
        firewallType,
        ruleName,
        description,
        action,
        direction,
        conditions,
        priority,
        logTraffic,
        notifyOnBlock,
        ttlDays,
      } = req.body;

      if (!firewallType) return res.status(400).json({ message: 'firewallType required' });
      if (!ruleName) return res.status(400).json({ message: 'ruleName required' });
      if (!conditions || Object.keys(conditions).length === 0) {
        return res.status(400).json({ message: 'At least one condition required' });
      }
      // Ensure there is a real blocking condition (not just protocol: 'all')
      const hasRealCondition = conditions.ipAddress || conditions.host || conditions.domain ||
        conditions.application || conditions.blockProtocol || conditions.port;
      if (!hasRealCondition) {
        return res.status(400).json({ message: 'At least one blocking condition (IP, domain, port, application, or protocol) required' });
      }

      const rule = new Firewall({
        firewallType,
        level: 'global',
        ruleName,
        description,
        action: action || 'block',
        direction: direction || 'both',
        conditions: {
          ipAddress: conditions.ipAddress,
          host: conditions.host,
          domain: conditions.domain,
          application: conditions.application,
          protocol: conditions.protocol || 'all',
          blockProtocol: conditions.blockProtocol,
          port: conditions.port,
        },
        priority: priority || 100,
        logTraffic: logTraffic !== false,
        notifyOnBlock: notifyOnBlock !== false,
        ttlDays,
        expiresAt: ttlDays ? new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000) : null,
        createdBy: req.user.id,
      });

      await rule.save();

      await enforceAllowRulePrecedence(rule);

      const io = req.app.get('io');
      if (io) await broadcastRuleToAgents(io, rule);
      
      // ── Sync all block types to IPS Server dashboard ──
      if (rule.action === 'block') {
        await syncDomainBlockToIPS(rule);
      }
      
      res.status(201).json({ rule, message: 'Global rule created' });
      return;
    }

    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const {
      firewallType,
      ruleName,
      description,
      action,
      direction,
      conditions,
      departmentIds,
      systemId,
      priority,
      logTraffic,
      notifyOnBlock,
      ttlDays,
    } = req.body;

    // Validation
    if (!level || !['company', 'department', 'system'].includes(level)) {
      return res.status(400).json({ message: 'Invalid level' });
    }
    if (!firewallType) return res.status(400).json({ message: 'firewallType required' });
    if (!ruleName) return res.status(400).json({ message: 'ruleName required' });
    if (!conditions || Object.keys(conditions).length === 0) {
      return res.status(400).json({ message: 'At least one condition required' });
    }
    // Ensure there is a real blocking condition (not just protocol: 'all')
    const hasRealCondition2 = conditions.ipAddress || conditions.host || conditions.domain ||
      conditions.application || conditions.blockProtocol || conditions.port;
    if (!hasRealCondition2) {
      return res.status(400).json({ message: 'At least one blocking condition (IP, domain, port, application, or protocol) required' });
    }

    // Level-specific validation
    if (level === 'department' && (!departmentIds || departmentIds.length === 0)) {
      return res.status(400).json({ message: 'departmentIds required for department rules' });
    }
    if (level === 'system' && !systemId) {
      return res.status(400).json({ message: 'systemId required for system rules' });
    }

    if (req.user.role === 'department_admin') {
      if (!req.user.departmentId || !['department', 'system'].includes(level)) {
        return res.status(403).json({ message: 'Department admins can create department and system rules only' });
      }
      if (level === 'department') {
        const requestedDepartments = (departmentIds || []).map(String);
        if (requestedDepartments.length !== 1 || requestedDepartments[0] !== String(req.user.departmentId)) {
          return res.status(403).json({ message: 'Department firewall access denied' });
        }
      }
      if (level === 'system') {
        const inScope = await System.exists({ _id: systemId, companyId, departmentId: req.user.departmentId });
        if (!inScope) return res.status(403).json({ message: 'System firewall access denied' });
      }
    }

    const rule = new Firewall({
      companyId,
      firewallType,
      level,
      ruleName,
      description,
      action: action || 'block',
      direction: direction || 'both',
      conditions: {
        ipAddress: conditions.ipAddress,
        host: conditions.host,
        domain: conditions.domain,
        application: conditions.application,
        protocol: conditions.protocol || 'all',
        blockProtocol: conditions.blockProtocol,
        port: conditions.port,
      },
      departmentIds: level === 'department' ? departmentIds : [],
      systemId: level === 'system' ? systemId : null,
      priority: priority || 100,
      logTraffic: logTraffic !== false,
      notifyOnBlock: notifyOnBlock !== false,
      ttlDays,
      expiresAt: ttlDays ? new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000) : null,
      createdBy: req.user.id,
    });

    await rule.save();
    await rule.populate('createdBy', 'name email');
    await enforceAllowRulePrecedence(rule);
    
    // ── Broadcast rule to target agents ──
    const io = req.app.get('io');
    if (io) {
      await broadcastRuleToAgents(io, rule);
    }
    
    // ── Sync all block types to IPS Server dashboard ──
    if (rule.action === 'block') {
      await syncDomainBlockToIPS(rule);
    }

    res.status(201).json({ rule, message: 'Rule created and sent to agents' });
  } catch (err) {
    console.error('[firewall/rules POST]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── PUT /api/firewall/rules/:ruleId ────────────────────────────────────────────
router.put('/rules/:ruleId', companyAuth, requireManager, async (req, res) => {
  try {
    const { ruleId } = req.params;
    const { companyId: queryCompanyId } = req.query;
    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const rule = await Firewall.findOne({ _id: ruleId, companyId });
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    if (!await canManageFirewallRule(req, rule)) {
      return res.status(403).json({ message: 'Firewall rule is outside your department scope' });
    }

    const previousRule = rule.toObject();
    const updates = Object.keys(req.body).filter(
      k => ['ruleName', 'description', 'action', 'direction', 'conditions', 'priority', 'enabled', 'logTraffic', 'notifyOnBlock', 'ttlDays'].includes(k)
    );

    updates.forEach(key => {
      if (key === 'conditions') {
        rule.conditions = { ...rule.conditions, ...req.body[key] };
      } else {
        rule[key] = req.body[key];
      }
    });

    rule.updatedBy = req.user.id;
    rule.updatedAt = new Date();
    rule.deploymentStatus = 'pending';
    rule.deploymentAcks = [];

    await rule.save();
    await rule.populate('updatedBy', 'name email');
    await enforceAllowRulePrecedence(rule);

    const io = req.app.get('io');
    if (io) {
      await broadcastRuleToAgents(io, { ...previousRule, action: 'allow' });
      if (rule.enabled) await broadcastRuleToAgents(io, rule);
    }

    res.json({ rule, message: 'Rule updated and redeployed to agents' });
  } catch (err) {
    console.error('[firewall/rules/:ruleId PUT]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── DELETE /api/firewall/rules/:ruleId ─────────────────────────────────────────
router.delete('/rules/:ruleId', companyAuth, requireManager, async (req, res) => {
  try {
    const { ruleId } = req.params;
    const { companyId: queryCompanyId } = req.query;

    // Check if it's a global rule
    const rule = await Firewall.findById(ruleId);
    if (req.user.role === 'department_admin' && rule && !await canManageFirewallRule(req, rule)) {
      return res.status(403).json({ message: 'Firewall rule is outside your department scope' });
    }
    if (rule && rule.level === 'global') {
      // Only super admin can delete global rules
      if (req.user.role !== 'superadmin') {
        return res.status(403).json({ message: 'Only super admin can delete global rules' });
      }
      
      // IMPORTANT: Send unblock commands to ALL agents before deleting
      const io = req.app.get('io');
      if (io && rule.conditions) {
        const c = rule.conditions;
        console.log('[Firewall] Sending GLOBAL unblock commands for rule:', rule.ruleName);
        
        // Send to all agents (global broadcast)
        if (c.ipAddress) {
          io.emit('agent:command', { command: 'unblock_ip', ip: c.ipAddress });
        }
        if (c.port) {
          io.emit('agent:command', { command: 'open_port', port: c.port, protocol: c.protocol || 'tcp' });
        }
        if (c.domain || c.host) {
          io.emit('agent:command', { command: 'unblock_domain', domain: c.domain || c.host });
        }
        if (c.application) {
          io.emit('agent:command', { command: 'unblock_application', application: c.application });
        }
      }
      
      await Firewall.findByIdAndDelete(ruleId);
      
      // ── Sync unblock to IPS Server dashboard ──
      if (rule.action === 'block') {
        await syncDomainUnblockToIPS(rule);
      }
      
      return res.json({ message: 'Global rule deleted & unblocked on all agents', rule });
    }

    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const deletedRule = await Firewall.findOneAndDelete({ _id: ruleId, companyId });
    if (!deletedRule) return res.status(404).json({ message: 'Rule not found' });

    // Send unblock command to agents so the rule is actually removed from iptables/hosts/etc
    const io = req.app.get('io');
    if (io && deletedRule.conditions) {
      const unblockPayload = {
        ruleId: deletedRule._id,
        ruleName: deletedRule.ruleName,
        action: 'allow',  // reverse the block
        direction: deletedRule.direction || 'both',
        conditions: deletedRule.conditions,
        level: deletedRule.level,
        priority: deletedRule.priority,
      };

      // Determine target rooms based on rule level
      let targetRooms = [];
      if (deletedRule.level === 'global') {
        // For global rules, broadcast to all agents
        io.emit('agent:command', { command: 'unblock_domain', domain: deletedRule.conditions.domain || deletedRule.conditions.host });
        io.emit('agent:command', { command: 'unblock_ip', ip: deletedRule.conditions.ipAddress });
        console.log(`[Firewall] Sent GLOBAL unblock commands for rule: ${deletedRule.ruleName}`);
      } else if (deletedRule.level === 'system' && deletedRule.systemId) {
        targetRooms.push(`system_${deletedRule.systemId}`);
      } else if (deletedRule.level === 'department' && deletedRule.departmentIds && deletedRule.departmentIds.length > 0) {
        // For department rules, target systems in those departments
        const systems = await System.find({
          departmentId: { $in: deletedRule.departmentIds },
          isActive: true,
        });
        for (const system of systems) {
          targetRooms.push(`system_${system._id}`);
        }
      } else if (deletedRule.level === 'company' && deletedRule.companyId) {
        targetRooms.push(`company:${deletedRule.companyId}`);
      }

      console.log(`[Firewall] Sending unblock for "${deletedRule.ruleName}" to rooms:`, targetRooms);

      // Send firewall:rule_applied with action 'allow' to all target rooms
      for (const room of targetRooms) {
        io.to(room).emit('firewall:rule_applied', unblockPayload);
      }

      // Also send specific unblock commands to all target rooms
      const c = deletedRule.conditions;
      for (const targetRoom of targetRooms) {
        // Send firewall:rule_applied with action 'allow' first
        io.to(targetRoom).emit('firewall:rule_applied', unblockPayload);
        
        // Then send specific unblock commands for agent-level processing
        if (c.ipAddress) {
          io.to(targetRoom).emit('agent:command', { command: 'unblock_ip', ip: c.ipAddress });
        }
        if (c.port) {
          io.to(targetRoom).emit('agent:command', { command: 'open_port', port: c.port, protocol: c.protocol || 'tcp' });
        }
        if (c.domain || c.host) {
          io.to(targetRoom).emit('agent:command', { command: 'unblock_domain', domain: c.domain || c.host });
        }
        if (c.application) {
          io.to(targetRoom).emit('agent:command', { command: 'unblock_application', application: c.application });
        }
        if (c.blockProtocol) {
          io.to(targetRoom).emit('agent:command', { command: 'unblock_protocol', protocol: c.blockProtocol });
        }
      }
    }
    
    // ── Sync unblock to IPS Server dashboard ──
    if (deletedRule.action === 'block') {
      await syncDomainUnblockToIPS(deletedRule);
    }

    res.json({ message: 'Rule deleted and unblocked on agents', rule: deletedRule });
  } catch (err) {
    console.error('[firewall/rules/:ruleId DELETE]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/firewall/rules/:ruleId/toggle ────────────────────────────────────
router.post('/rules/:ruleId/toggle', companyAuth, requireManager, async (req, res) => {
  try {
    const { ruleId } = req.params;
    const { companyId: queryCompanyId } = req.query;
    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const rule = await Firewall.findOne({ _id: ruleId, companyId });
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    if (!await canManageFirewallRule(req, rule)) {
      return res.status(403).json({ message: 'Firewall rule is outside your department scope' });
    }

    rule.enabled = !rule.enabled;
    rule.updatedBy = req.user.id;
    rule.updatedAt = new Date();
    rule.deploymentStatus = 'pending';
    rule.deploymentAcks = [];

    await rule.save();

    // ── Propagate to agents: disabled → unblock, enabled → reapply ──
    const io = req.app.get('io');
    if (io) {
      const rulePayload = {
        ruleId: rule._id,
        ruleName: rule.ruleName,
        action: rule.enabled ? rule.action : 'allow', // disabled = reverse the action
        direction: rule.direction,
        conditions: rule.conditions,
        level: rule.level,
        priority: rule.priority,
      };

      if (rule.enabled) {
        // Re-apply: broadcast as new rule
        await broadcastRuleToAgents(io, rule);
      } else {
        // Disable: send unblock/allow to reverse
        if (rule.systemId) {
          io.to(`system_${rule.systemId}`).emit('firewall:rule_applied', rulePayload);
        }
        if (rule.companyId) {
          io.to(`company:${rule.companyId}`).emit('firewall:rule_applied', rulePayload);
        }

        // Send specific unblock commands
        const c = rule.conditions || {};
        const targetRoom = rule.systemId
          ? `system_${rule.systemId}`
          : `company:${rule.companyId}`;

        if (c.ipAddress) {
          io.to(targetRoom).emit('agent:command', { command: 'unblock_ip', ip: c.ipAddress });
        }
        if (c.port) {
          io.to(targetRoom).emit('agent:command', { command: 'open_port', port: c.port, protocol: c.protocol || 'tcp' });
        }
      }

      console.log(`[Firewall] Rule "${rule.ruleName}" ${rule.enabled ? 'enabled → reapplied' : 'disabled → unblocked'} on agents`);
    }

    res.json({ rule, message: `Rule ${rule.enabled ? 'enabled' : 'disabled'}` });
  } catch (err) {
    console.error('[firewall/rules/:ruleId/toggle]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/firewall/stats ────────────────────────────────────────────────────
router.get('/stats', companyAuth, async (req, res) => {
  try {
    const { companyId: queryCompanyId } = req.query;
    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    const departmentScope = await departmentFirewallScope(req);
    if (departmentScope && !departmentScope.departmentId) {
      return res.json({ totalRules: 0, enabledRules: 0, pendingRules: 0, failedRules: 0, partialRules: 0, companyRules: 0, departmentRules: 0, systemRules: 0, blockRules: 0 });
    }
    const scopeQuery = departmentScope
      ? { companyId, $or: [
          { level: 'department', departmentIds: departmentScope.departmentId },
          { level: 'system', systemId: { $in: departmentScope.systemIds } },
        ] }
      : { companyId };
    if (req.query.systemId && mongoose.Types.ObjectId.isValid(String(req.query.systemId))) {
      scopeQuery.systemId = new mongoose.Types.ObjectId(String(req.query.systemId));
    }

    const [totalRules, enabledRules, companyRules, departmentRules, systemRules, blockRules] =
      await Promise.all([
        Firewall.countDocuments(scopeQuery),
        Firewall.countDocuments({ ...scopeQuery, enabled: true, deploymentStatus: 'deployed' }),
        departmentScope ? 0 : Firewall.countDocuments({ companyId, level: 'company' }),
        Firewall.countDocuments({ ...scopeQuery, level: 'department' }),
        Firewall.countDocuments({ ...scopeQuery, level: 'system' }),
        Firewall.countDocuments({ ...scopeQuery, action: 'block' }),
      ]);

    const [pendingRules, failedRules, partialRules] = await Promise.all([
      Firewall.countDocuments({ ...scopeQuery, enabled: true, deploymentStatus: 'pending' }),
      Firewall.countDocuments({ ...scopeQuery, enabled: true, deploymentStatus: 'failed' }),
      Firewall.countDocuments({ ...scopeQuery, enabled: true, deploymentStatus: 'partial' }),
    ]);
    res.json({ totalRules, enabledRules, pendingRules, failedRules, partialRules, companyRules, departmentRules, systemRules, blockRules });
  } catch (err) {
    console.error('[firewall/stats]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/firewall/unblock ─────────────────────────────────────────────────
// Unblock an IP/domain by:
// 1. Deleting the block rules
// 2. Creating temporary "allow" rules for agents to fetch via polling
// 3. Broadcasting Socket.IO unblock commands (fallback for real-time agents)
router.post('/unblock', companyAuth, requireManager, async (req, res) => {
  try {
    if (req.user.role === 'department_admin') {
      return res.status(403).json({ message: 'Use a department or system rule to unblock within your scope' });
    }
    const { ipAddress } = req.body;
    const { companyId: queryCompanyId } = req.query;
    const companyId = queryCompanyId || req.user.companyId;

    if (!await validateCompanyAccess(req, companyId)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    if (!ipAddress || ipAddress.trim() === '') {
      return res.status(400).json({ message: 'IP address or domain required' });
    }

    // Find blocking rules BEFORE deleting (to know what to send to agents)
    const searchConditions = [
      { 'conditions.ipAddress': ipAddress },
      { 'conditions.host': ipAddress },
      { 'conditions.domain': ipAddress },
      { 'conditions.application': ipAddress },
      { 'conditions.port': ipAddress },
      { 'conditions.blockProtocol': ipAddress },
    ];

    const rulesToDelete = await Firewall.find({
      companyId,
      action: 'block',
      $or: searchConditions,
    }).lean();

    // Delete block rules from DB
    const result = await Firewall.deleteMany({
      companyId,
      action: 'block',
      $or: searchConditions,
    });

    // ── CREATE ALLOW RULES FOR AGENT POLLING ──
    // For each deleted rule, create a temporary allow rule that:
    // 1. Agent will fetch via GET /api/firewall/pending-rules polling
    // 2. Agent will apply with action='allow' to unblock
    // 3. Will be auto-deleted after 5 minutes (cleanup)
    const allowRules = [];
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // Expires in 5 minutes

    for (const rule of rulesToDelete) {
      const allowRule = new Firewall({
        companyId,
        systemId: rule.systemId || undefined,
        departmentIds: rule.departmentIds || [],
        level: rule.level || 'company',
        ruleName: `[UNBLOCK] ${rule.ruleName || ipAddress}`,
        action: 'allow',
        direction: rule.direction || 'both',
        priority: rule.priority,
        conditions: rule.conditions,
        enabled: true,
        expiresAt,
        createdAt: new Date(),
      });
      await allowRule.save();
      allowRules.push(allowRule);
    }

    // ── BROADCAST SOCKET.IO COMMANDS (FALLBACK) ──
    const io = req.app.get('io');
    if (io) {
      io.to(`company:${companyId}`).emit('agent:command', { 
        command: 'unblock_ip', 
        ip: ipAddress 
      });
      
      for (const rule of rulesToDelete) {
        const c = rule.conditions || {};
        const targetRoom = rule.systemId
          ? `system_${rule.systemId}`
          : `company:${companyId}`;

        if (c.domain || c.host) {
          io.to(targetRoom).emit('agent:command', { 
            command: 'unblock_domain', 
            domain: c.domain || c.host 
          });
        }
        if (c.ipAddress) {
          io.to(targetRoom).emit('agent:command', { 
            command: 'unblock_ip', 
            ip: c.ipAddress 
          });
        }
        if (c.port) {
          io.to(targetRoom).emit('agent:command', { 
            command: 'open_port', 
            port: c.port, 
            protocol: c.protocol || 'tcp' 
          });
        }
      }

      console.log(`[Firewall] Sent unblock for "${ipAddress}" to company ${companyId} agents (${rulesToDelete.length} rules)`);
    }

    if (result.deletedCount === 0 && allowRules.length === 0) {
      return res.json({ 
        success: true,
        message: `Unblock command sent for ${ipAddress} (no rules found)`,
        deletedCount: 0 
      });
    }

    res.json({ 
      success: true,
      message: `Successfully unblocked ${ipAddress}. Block rules removed, allow rules sent to agents.`,
      deletedCount: result.deletedCount,
      allowRulesCreated: allowRules.length
    });
  } catch (err) {
    console.error('[firewall/unblock]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/firewall/pending-rules/:agentKey — agent startup sync (no JWT) ──
// Agent calls this on startup and periodically via polling to get:
// 1. All enabled BLOCK rules (what to block)
// 2. All enabled ALLOW rules (temporary rules from unblock, agent should apply then forget)
// Uses integration secret for auth (same as heartbeat).
router.post('/rule-ack/:agentKey', async (req, res) => {
  try {
    const auth = await verifySignedAgentRequest(req, { agentKey: req.params.agentKey });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message });
    const ruleId = String(req.body.ruleId || '');
    if (!ruleId) return res.status(400).json({ message: 'ruleId required' });
    const system = auth.system;
    const ok = req.body.ok === true;
    const ack = {
      systemId: system._id,
      agentId: system.agentId || '',
      hostname: system.hostname || system.name || '',
      ok,
      result: String(req.body.result || '').slice(0, 1000),
      appliedAt: new Date(),
    };
    const rule = await Firewall.findOneAndUpdate(
      { _id: ruleId, $or: [{ level: 'global' }, { companyId: system.companyId }] },
      {
        $pull: { deploymentAcks: { systemId: system._id } },
        $set: { updatedAt: new Date() },
      },
      { new: true },
    );
    if (!rule) return res.status(404).json({ message: 'Rule not found for this agent' });
    rule.deploymentAcks.push(ack);
    const hasSuccess = rule.deploymentAcks.some(item => item.ok === true);
    const hasFailure = rule.deploymentAcks.some(item => item.ok === false);
    rule.deploymentStatus = hasSuccess && hasFailure ? 'partial' : hasSuccess ? 'deployed' : 'failed';
    if (!ok) rule.deploymentErrors = { ...(rule.deploymentErrors?.toObject?.() || rule.deploymentErrors || {}), agent: ack.result };
    await rule.save();
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

router.get('/pending-rules/:agentKey', async (req, res) => {
  try {
    const { agentKey } = req.params;
    const auth = await verifySignedAgentRequest(req, { agentKey });
    if (!auth.ok) return res.status(auth.status).json({ message: auth.message });
    const system = await System.findById(auth.system._id).lean();
    if (!system) return res.status(404).json({ message: 'System not found' });

    // Fetch all applicable rules for this system (both block and allow):
    // 1. System-level rules for this system
    // 2. Department-level rules for this system's department
    // 3. Company-level rules for this system's company
    // 4. Global rules
    // Include both enabled=true and not expired
    const rules = await Firewall.find(buildApplicableRulesQuery(system)).sort({ priority: 1 }).lean();

    const formatted = rules.map(r => ({
      ruleId: r._id,
      ruleName: r.ruleName,
      action: r.action,             // 'block' or 'allow'
      direction: r.direction,
      conditions: r.conditions,
      level: r.level,
      priority: r.priority,
    }));

    // Clean up expired allow rules (ones that have passed their expiresAt date)
    await Firewall.deleteMany({
      enabled: true,
      action: 'allow',
      expiresAt: { $exists: true, $lt: new Date() },
    });

    res.json({ rules: formatted, count: formatted.length, systemId: system._id });
  } catch (err) {
    console.error('[firewall/pending-rules]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/firewall/sync-agent-rules — sync persisted rules from agent JSON to DB ──
// Admin can call this to sync rules from /etc/soc-agent/firewall_rules.json to MongoDB
router.post('/sync-agent-rules', companyAuth, async (req, res) => {
  try {
    const companyId = req.user.companyId;
    const fs = require('fs');
    
    // Only company admin or analyst can sync
    if (!['company_admin', 'analyst'].includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Get the rules from request body (passed by the sync script)
    const { persistedRules } = req.body;
    if (!persistedRules || !Array.isArray(persistedRules)) {
      return res.status(400).json({ message: 'persistedRules array required' });
    }

    let created = 0;
    let skipped = 0;

    for (const rule of persistedRules) {
      try {
        // Skip if already exists
        const actionStr = rule.action;
        const conditionKey = rule.domain || rule.ip || rule.port || rule.protocol;
        
        const existingRule = await Firewall.findOne({
          companyId,
          $or: [
            { 'conditions.domain': rule.domain },
            { 'conditions.ipAddress': rule.ip },
            { 'conditions.port': rule.port },
            { 'conditions.blockProtocol': rule.protocol },
          ]
        });

        if (existingRule) {
          skipped++;
          continue;
        }

        // Create new rule based on action type
        let ruleName = '';
        let action = 'block';
        let conditions = {};

        if (rule.action === 'block_domain' && rule.domain) {
          ruleName = `Block ${rule.domain}`;
          conditions = { domain: rule.domain };
        } else if (rule.action === 'block_ip' && rule.ip) {
          ruleName = `Block IP ${rule.ip}`;
          conditions = { ipAddress: rule.ip };
        } else if (rule.action === 'close_port' && rule.port) {
          ruleName = `Close Port ${rule.port}/${rule.protocol || 'tcp'}`;
          conditions = { port: rule.port, protocol: rule.protocol || 'tcp' };
        } else if (rule.action === 'block_protocol' && rule.protocol) {
          ruleName = `Block Protocol ${rule.protocol.toUpperCase()}`;
          conditions = { blockProtocol: rule.protocol };
        } else {
          continue;
        }

        const newRule = new Firewall({
          companyId,
          firewallType: 'iptables',
          level: 'company',
          ruleName,
          description: `Auto-synced from agent (${rule.reason || 'unknown'})`,
          action,
          direction: rule.dir || 'both',
          conditions,
          priority: 50,
          enabled: true,
          logTraffic: true,
          notifyOnBlock: true,
        });

        await newRule.save();
        created++;

      } catch (e) {
        console.error('[sync] Error creating rule:', e.message);
      }
    }

    res.json({ 
      created, 
      skipped, 
      message: `Synced ${created} new rules (${skipped} already existed)` 
    });

  } catch (err) {
    console.error('[firewall/sync-agent-rules]', err.message);
    res.status(500).json({ message: err.message });
  }
});

router._test = { buildApplicableRulesQuery, getIpsSyncFailure };
module.exports = router;
