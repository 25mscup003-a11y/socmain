/**
 * Firewall Service — SOC4 IPS Server v4.0
 * ==========================================
 * SUPPORTED FIREWALLS:
 *   - Linux nftables
 *   - Windows Defender Firewall
 *
 * Block targets: IP, Port, Domain, Application, Protocol
 * Direction: inbound | outbound | both
 *
 */

const logger = require('../utils/logger');
const { getDB } = require('../db/mongodb');
const https = require('https');
const net = require('net');
const { execFile } = require('child_process');

// ── In-memory cache (tenant-scoped: "company:$id|$blockKey") ─────────────────
const blocklistCache = new Map();
const expiryTimers = new Map();
const FIREWALL_MODE = String(process.env.IPS_FIREWALL_MODE || 'auto').toLowerCase();

function _execFile(command, args = [], options = {}) {
  return new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 10000, ...options }, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

async function _tryExec(command, args = [], options = {}) {
  try {
    return await _execFile(command, args, options);
  } catch (err) {
    return { error: err, stdout: err.stdout || '', stderr: err.stderr || err.message };
  }
}

// ── Direction helpers ─────────────────────────────────────────────────────────
function normalizeDirection(dir = 'both') {
  const d = (dir || 'both').toLowerCase().trim();
  if (d === 'inbound' || d === 'in') return 'inbound';
  if (d === 'outbound' || d === 'out') return 'outbound';
  return 'both';
}

function scopedKey(blockKey, company) {
  return company ? `company:${company}|${blockKey}` : blockKey;
}

function _clearExpiry(cacheKey) {
  const timer = expiryTimers.get(cacheKey);
  if (timer) clearTimeout(timer);
  expiryTimers.delete(cacheKey);
}

function _scheduleExpiry(blockEntry) {
  if (!blockEntry?.blockKey || !blockEntry?.expiresAt) return;
  const cacheKey = scopedKey(blockEntry.blockKey, blockEntry.company);
  _clearExpiry(cacheKey);

  const delay = new Date(blockEntry.expiresAt).getTime() - Date.now();
  if (!Number.isFinite(delay)) return;

  const expire = async () => {
    expiryTimers.delete(cacheKey);
    try {
      await unblockTarget({
        ip: blockEntry.ip,
        port: blockEntry.port,
        domain: blockEntry.domain,
        application: blockEntry.application,
        protocol: blockEntry.protocol,
        direction: blockEntry.direction,
        rawBlockKey: blockEntry.blockKey,
        company: blockEntry.company,
      });
      logger.info(`⏱️ TTL expired — automatically unblocked ${blockEntry.blockKey}`);
      if (typeof global.emitIPSEvent === 'function') {
        global.emitIPSEvent('unblock', {
          action: 'unblock',
          reason: 'Block TTL expired',
          blockKey: blockEntry.blockKey,
          ip: blockEntry.ip,
          domain: blockEntry.domain,
          company: blockEntry.company,
          ts: new Date().toISOString(),
        });
      }
    } catch (err) {
      logger.error(`TTL auto-unblock failed for ${blockEntry.blockKey}: ${err.message}`);
    }
  };

  const timer = setTimeout(expire, Math.max(0, delay));
  if (typeof timer.unref === 'function') timer.unref();
  expiryTimers.set(cacheKey, timer);
}

function _isExpired(blockEntry = {}, now = Date.now()) {
  if (!blockEntry.expiresAt) return false;
  const time = new Date(blockEntry.expiresAt).getTime();
  return Number.isFinite(time) && time <= now;
}

// ── pfSense API Helper ────────────────────────────────────────────────────────
async function _pfSenseAPICall(method, endpoint, body = null) {
  const host     = process.env.PFSENSE_HOST;
  const apiKey   = process.env.PFSENSE_API_KEY;
  const apiSecret= process.env.PFSENSE_API_SECRET;

  if (!host || !apiKey) {
    logger.info('[pfSense] Host/API key not configured — log-only mode');
    return { success: true, mode: 'log-only' };
  }

  const url = `https://${host}/api/v1${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `${apiKey} ${apiSecret || ''}`.trim(),
  };

  return new Promise((resolve, reject) => {
    const options = {
      method,
      headers,
      rejectUnauthorized: false, // pfSense often uses self-signed cert
    };

    const req = https.request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ success: res.statusCode < 400, raw: data }); }
      });
    });

    req.on('error', (err) => {
      logger.warn(`[pfSense] API call failed: ${err.message}`);
      resolve({ success: true, mode: 'log-only', error: err.message });
    });

    req.setTimeout(8000, () => {
      req.destroy();
      logger.warn('[pfSense] API timeout — log-only');
      resolve({ success: true, mode: 'log-only', error: 'timeout' });
    });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── OPNsense API Helper ───────────────────────────────────────────────────────
async function _opnsenseAPICall(method, endpoint, body = null) {
  const host   = process.env.OPNSENSE_HOST;
  const apiKey = process.env.OPNSENSE_API_KEY;
  const apiSec = process.env.OPNSENSE_API_SECRET;

  if (!host || !apiKey) {
    logger.info('[OPNsense] Host/API key not configured — log-only mode');
    return { success: true, mode: 'log-only' };
  }

  const url = `https://${host}/api/${endpoint}`;
  const auth = Buffer.from(`${apiKey}:${apiSec || ''}`).toString('base64');

  return new Promise((resolve, reject) => {
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Basic ${auth}`,
      },
      rejectUnauthorized: false,
    };

    const req = https.request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ success: res.statusCode < 400, raw: data }); }
      });
    });

    req.on('error', (err) => {
      logger.warn(`[OPNsense] API call failed: ${err.message}`);
      resolve({ success: true, mode: 'log-only', error: err.message });
    });

    req.setTimeout(8000, () => {
      req.destroy();
      resolve({ success: true, mode: 'log-only', error: 'timeout' });
    });

    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── Detect active firewall ────────────────────────────────────────────────────
function _getFirewallType() {
  if (FIREWALL_MODE === 'endpoint-agent') return 'endpoint-agent';
  if (FIREWALL_MODE === 'log-only') return 'log-only';
  if (FIREWALL_MODE === 'nftables') return 'nftables';
  if (FIREWALL_MODE === 'windows-defender' || FIREWALL_MODE === 'windows') return 'windows-defender';
  if (process.platform === 'win32') return 'windows-defender';
  // The IPS API normally runs as an unprivileged service account. In auto
  // mode it must delegate to the enrolled root/system agent instead of
  // repeatedly attempting netlink operations it cannot perform.
  if (process.platform === 'linux') {
    return typeof process.geteuid === 'function' && process.geteuid() === 0
      ? 'nftables'
      : 'endpoint-agent';
  }
  return 'log-only';
}

async function _nftExists() {
  const result = await _tryExec('nft', ['--version']);
  return !result.error;
}

async function _ensureNftables() {
  if (typeof process.geteuid === 'function' && process.geteuid() !== 0) {
    return { success: false, error: 'nftables enforcement requires a root service; use endpoint-agent mode' };
  }
  if (!(await _nftExists())) {
    return { success: false, mode: 'log-only', error: 'nft command not available' };
  }

  await _tryExec('nft', ['add', 'table', 'inet', 'soc4']);
  await _tryExec('nft', ['add', 'set', 'inet', 'soc4', 'blocked_ipv4', '{', 'type', 'ipv4_addr;', 'flags', 'interval;', '}']);
  await _tryExec('nft', ['add', 'set', 'inet', 'soc4', 'blocked_ipv6', '{', 'type', 'ipv6_addr;', 'flags', 'interval;', '}']);
  await _tryExec('nft', ['add', 'chain', 'inet', 'soc4', 'input', '{', 'type', 'filter', 'hook', 'input', 'priority', '-100;', 'policy', 'accept;', '}']);
  await _tryExec('nft', ['add', 'chain', 'inet', 'soc4', 'output', '{', 'type', 'filter', 'hook', 'output', 'priority', '-100;', 'policy', 'accept;', '}']);

  const input = await _tryExec('nft', ['list', 'chain', 'inet', 'soc4', 'input']);
  const output = await _tryExec('nft', ['list', 'chain', 'inet', 'soc4', 'output']);
  if (!String(input.stdout || '').includes('@blocked_ipv4')) {
    await _tryExec('nft', ['add', 'rule', 'inet', 'soc4', 'input', 'ip', 'saddr', '@blocked_ipv4', 'drop', 'comment', 'SOC4_BLOCKLIST_IPV4_IN']);
    await _tryExec('nft', ['add', 'rule', 'inet', 'soc4', 'input', 'ip6', 'saddr', '@blocked_ipv6', 'drop', 'comment', 'SOC4_BLOCKLIST_IPV6_IN']);
  }
  if (!String(output.stdout || '').includes('@blocked_ipv4')) {
    await _tryExec('nft', ['add', 'rule', 'inet', 'soc4', 'output', 'ip', 'daddr', '@blocked_ipv4', 'drop', 'comment', 'SOC4_BLOCKLIST_IPV4_OUT']);
    await _tryExec('nft', ['add', 'rule', 'inet', 'soc4', 'output', 'ip6', 'daddr', '@blocked_ipv6', 'drop', 'comment', 'SOC4_BLOCKLIST_IPV6_OUT']);
  }

  return { success: true };
}

async function _applyNftablesBlock(criteria) {
  const { ip } = criteria;
  if (!ip || !net.isIP(ip)) return { success: false, error: 'nftables currently requires an IP target' };
  const ready = await _ensureNftables();
  if (!ready.success) return ready;
  const setName = net.isIP(ip) === 6 ? 'blocked_ipv6' : 'blocked_ipv4';
  const result = await _tryExec('nft', ['add', 'element', 'inet', 'soc4', setName, '{', ip, '}']);
  if (result.error && !/File exists|exists/i.test(String(result.stderr || result.error.message))) {
    return { success: false, error: result.stderr || result.error.message };
  }
  logger.block(`[nftables] Block applied for ${ip}`);
  return { success: true, method: 'nftables' };
}

async function _removeNftablesBlock(entry) {
  const { ip } = entry;
  if (!ip || !net.isIP(ip)) return { success: false, error: 'nftables unblock requires an IP target' };
  const setName = net.isIP(ip) === 6 ? 'blocked_ipv6' : 'blocked_ipv4';
  const result = await _tryExec('nft', ['delete', 'element', 'inet', 'soc4', setName, '{', ip, '}']);
  if (result.error && !/No such file|not found|does not exist/i.test(String(result.stderr || result.error.message))) {
    return { success: false, error: result.stderr || result.error.message };
  }
  logger.info(`[nftables] Block removed for ${ip}`);
  return { success: true, method: 'nftables' };
}

function _windowsRuleName(ip, direction) {
  return `SOC4 Block ${direction} ${ip}`;
}

async function _applyWindowsDefenderBlock(criteria) {
  const { ip, direction } = criteria;
  if (!ip || !net.isIP(ip)) return { success: false, error: 'Windows Defender Firewall requires an IP target' };
  const dirs = direction === 'outbound' ? ['Outbound'] : direction === 'inbound' ? ['Inbound'] : ['Inbound', 'Outbound'];
  for (const dir of dirs) {
    const displayName = _windowsRuleName(ip, dir);
    await _tryExec('powershell.exe', [
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-Command',
      `if (-not (Get-NetFirewallRule -DisplayName '${displayName}' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '${displayName}' -Direction ${dir} -Action Block -RemoteAddress '${ip}' -Profile Any | Out-Null }`,
    ]);
  }
  logger.block(`[Windows Defender Firewall] Block applied for ${ip}`);
  return { success: true, method: 'windows-defender' };
}

async function _removeWindowsDefenderBlock(entry) {
  const { ip } = entry;
  if (!ip || !net.isIP(ip)) return { success: false, error: 'Windows Defender Firewall unblock requires an IP target' };
  const result = await _tryExec('powershell.exe', [
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-Command',
    `Get-NetFirewallRule -DisplayName 'SOC4 Block * ${ip}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule`,
  ]);
  if (result.error) return { success: false, error: result.stderr || result.error.message };
  logger.info(`[Windows Defender Firewall] Block removed for ${ip}`);
  return { success: true, method: 'windows-defender' };
}

// ── Apply Block via pfSense ───────────────────────────────────────────────────
async function _applyPfSenseBlock(criteria) {
  const { ip, port, domain, protocol, direction } = criteria;

  const aliasName = ip
    ? `SOC4_BLOCK_${ip.replace(/[./]/g, '_')}`
    : domain
    ? `SOC4_DOMAIN_${domain.replace(/[./]/g, '_')}`
    : `SOC4_BLOCK_${Date.now()}`;

  // Add to pfSense alias (Firewall > Aliases)
  await _pfSenseAPICall('POST', '/firewall/alias/entry', {
    name:    aliasName,
    type:    ip ? 'host' : 'url_ports',
    address: ip || domain || '',
    descr:   `SOC4 Auto-block | ${criteria.reason || 'blocked'}`,
  });

  // Create firewall rule referencing the alias
  const ruleBody = {
    type:      'block',
    interface: direction === 'outbound' ? 'wan' : 'lan',
    ipprotocol:'inet',
    protocol:  port ? (protocol || 'tcp') : 'any',
    src:       direction === 'outbound' ? 'any' : aliasName,
    dst:       direction === 'outbound' ? aliasName : 'any',
    dstport:   port ? String(port) : 'any',
    descr:     `SOC4 Block: ${criteria.reason || 'blocked'} | ${new Date().toISOString()}`,
    enabled:   true,
  };

  const result = await _pfSenseAPICall('POST', '/firewall/rule', ruleBody);
  logger.block(`[pfSense] Rule applied for ${ip || domain || 'target'} — ${result.mode || 'applied'}`);
  return result;
}

// ── Apply Block via OPNsense ─────────────────────────────────────────────────
async function _applyOPNsenseBlock(criteria) {
  const { ip, port, domain, protocol, direction } = criteria;

  const aliasUUID = `soc4_${Date.now()}`;

  // Add alias
  await _opnsenseAPICall('POST', 'firewall/alias/addItem', {
    name:     `SOC4_${ip ? ip.replace(/[./]/g, '_') : 'block'}_${Date.now()}`,
    type:     ip ? 'host' : 'url',
    content:  ip || domain || '',
    description: `SOC4 block: ${criteria.reason || 'blocked'}`,
    enabled:  '1',
  });

  // Add firewall rule
  const result = await _opnsenseAPICall('POST', 'firewall/filter/addRule', {
    enabled:   '1',
    action:    'block',
    interface: direction === 'outbound' ? 'wan' : 'lan',
    protocol:  port ? (protocol || 'tcp') : 'any',
    source:    { network: direction === 'outbound' ? 'any' : (ip || 'any') },
    destination: { network: direction === 'outbound' ? (ip || 'any') : 'any', port: port ? String(port) : '' },
    description: `SOC4: ${criteria.reason || 'blocked'} | ${new Date().toISOString()}`,
  });

  logger.block(`[OPNsense] Rule applied for ${ip || domain || 'target'} — ${result.mode || 'applied'}`);
  return result;
}

// ── Remove Block via pfSense ──────────────────────────────────────────────────
async function _removePfSenseBlock(entry) {
  const { ip, domain, ruleId } = entry;
  if (ruleId) {
    await _pfSenseAPICall('DELETE', `/firewall/rule/${ruleId}`, null);
  }
  const safeName = (ip || domain || '').replace(/[./]/g, '_');
  await _pfSenseAPICall('DELETE', `/firewall/alias/entry/SOC4_BLOCK_${safeName}`, null);
  logger.info(`[pfSense] Rule removed for ${ip || domain}`);
}

// ── Remove Block via OPNsense ─────────────────────────────────────────────────
async function _removeOPNsenseBlock(entry) {
  const { ip, domain, ruleId } = entry;
  if (ruleId) {
    await _opnsenseAPICall('POST', `firewall/filter/delRule/${ruleId}`, null);
  }
  logger.info(`[OPNsense] Rule removed for ${ip || domain}`);
}

// ── Parse port field ──────────────────────────────────────────────────────────
function _parsePort(portField) {
  if (!portField) return { port: null, portEnd: null };
  const str = String(portField).trim();
  if (str.includes('-')) {
    const [p, e] = str.split('-').map(Number);
    return { port: isNaN(p) ? null : p, portEnd: isNaN(e) ? null : e };
  }
  const p = parseInt(str, 10);
  return { port: isNaN(p) ? null : p, portEnd: null };
}

// ── Public: Block Target ──────────────────────────────────────────────────────
async function blockTarget(options = {}) {
  const {
    ip, domain, application,
    protocol, direction = 'both',
    reason = 'Blocked via IPS', company,
    source = 'Auto', attackType, mac,
    systemId, departmentId, agentId, agentName, agentHostname, agentIp,
    ttlHours = process.env.IPS_BLOCK_TTL_HOURS || 24,
  } = options;

  const { port, portEnd } = _parsePort(options.port);
  const dir = normalizeDirection(direction);

  if (!ip && !domain && !application && !port && (!protocol || protocol === 'all')) {
    throw new Error('At least one of: ip, domain, application, port, or protocol is required');
  }
  if (ip && !isValidIP(ip)) throw new Error(`Invalid IP address: ${ip}`);
  if (port && (port < 1 || port > 65535)) throw new Error(`Invalid port: ${port}`);

  const blockKey = generateBlockKey({ ip, port, portEnd, domain, application, protocol, direction: dir });
  const cacheKey = scopedKey(blockKey, company);

  if (blocklistCache.has(cacheKey)) {
    const now = new Date();
    const existing = blocklistCache.get(cacheKey) || {};
    const refreshed = {
      ...existing,
      reason: reason || existing.reason,
      source: source || existing.source || 'Auto',
      attackType: attackType || existing.attackType,
      mac: mac || existing.mac || null,
      systemId: systemId || existing.systemId,
      departmentId: departmentId || existing.departmentId,
      agentId: agentId || existing.agentId,
      agentName: agentName || existing.agentName,
      agentHostname: agentHostname || existing.agentHostname,
      agentIp: agentIp || existing.agentIp,
      ttlHours: Math.max(0, Number(ttlHours) || Number(existing.ttlHours) || 0),
      ts: now,
      updatedAt: now,
      status: 'blocked',
      company: company || existing.company,
    };
    refreshed.expiresAt = refreshed.ttlHours > 0
      ? new Date(Date.now() + (refreshed.ttlHours * 60 * 60 * 1000))
      : null;
    blocklistCache.set(cacheKey, refreshed);
    _scheduleExpiry(refreshed);

    try {
      const db = getDB();
      if (db) {
        await db.collection('firewall_blocks').updateOne(
          { blockKey, ...(company && { company }) },
          { $set: refreshed },
          { upsert: true }
        );
      }
    } catch (err) {
      logger.error(`Failed to refresh existing block timestamp: ${err.message}`);
    }

    logger.warn(`Target already blocked, timestamp refreshed: ${blockKey}`);
    return {
      action: 'block',
      blockKey,
      note: 'already blocked - timestamp refreshed',
      refreshed: true,
      ts: refreshed.ts,
      expiresAt: refreshed.expiresAt,
      ttlHours: refreshed.ttlHours,
    };
  }

  const description = formatBlockDescription({ ip, port, portEnd, domain, application, protocol, direction: dir });
  const fwType = _getFirewallType();
  const delegated = fwType === 'endpoint-agent';
  let method = delegated ? 'endpoint-agent' : 'log-only';
  let ruleId = null;

  try {
    if (fwType === 'nftables') {
      const result = await _applyNftablesBlock({ ip, port, portEnd, domain, application, protocol, direction: dir, reason });
      if (!result.success) throw new Error(result.error || 'nftables did not confirm block enforcement');
      method = 'nftables';
    } else if (fwType === 'windows-defender') {
      const result = await _applyWindowsDefenderBlock({ ip, port, portEnd, domain, application, protocol, direction: dir, reason });
      if (!result.success) throw new Error(result.error || 'Windows Defender did not confirm block enforcement');
      method = 'windows-defender';
    } else if (delegated) {
      logger.info(`[ENDPOINT-AGENT] Delegated block for ${description}`);
    } else {
      method = 'log-only';
      logger.block(`📝 [LOG-ONLY] Would block ${description} — no host firewall enforcement configured`);
    }
  } catch (err) {
    logger.error(`Firewall block failed for ${description}: ${err.message}`);
    throw new Error(`Firewall block failed for ${description}: ${err.message}`);
  }

  const blockEntry = {
    blockKey,
    type: ip ? 'ip' : domain ? 'domain' : application ? 'application' : protocol ? 'protocol' : 'port',
    ip, port, portEnd, domain, application, protocol,
    mac: mac || null,
    direction: dir,
    reason, ts: new Date(), method, status: 'blocked',
    source: source || 'Auto',
    attackType: attackType || undefined,
    systemId: systemId || undefined,
    departmentId: departmentId || undefined,
    agentId: agentId || undefined,
    agentName: agentName || undefined,
    agentHostname: agentHostname || undefined,
    agentIp: agentIp || undefined,
    ttlHours: Math.max(0, Number(ttlHours) || 0),
    expiresAt: Number(ttlHours) > 0
      ? new Date(Date.now() + (Number(ttlHours) * 60 * 60 * 1000))
      : null,
    company: company || undefined,
    ruleId,
  };

  blocklistCache.set(cacheKey, blockEntry);
  _scheduleExpiry(blockEntry);

  try {
    const db = getDB();
    if (db) {
      await db.collection('firewall_blocks').updateOne({ blockKey, ...(company && { company }) }, { $set: blockEntry }, { upsert: true });
    }
  } catch (err) {
    logger.error(`Failed to persist block: ${err.message}`);
  }

  return {
    action: 'block',
    blockKey,
    description,
    method,
    direction: dir,
    reason,
    firewallType: fwType,
    enforced: !delegated && method !== 'log-only',
    delegated,
    ttlHours: blockEntry.ttlHours,
    expiresAt: blockEntry.expiresAt,
  };
}

// ── Legacy IP-only  ────────────────────────────────────────────────────────────
async function blockIP(ip, reason = 'Blocked via webhook') {
  return blockTarget({ ip, reason });
}

// ── Public: Unblock Target ────────────────────────────────────────────────────
async function unblockTarget(options = {}) {
  const { ip, domain, application, protocol, direction = 'both', rawBlockKey, company } = options;
  const { port, portEnd } = _parsePort(options.port);
  const dir = normalizeDirection(direction);

  if (!ip && !domain && !application && !port && (!protocol || protocol === 'all')) {
    throw new Error('At least one of: ip, domain, application, port, or protocol is required');
  }

  const generatedKey = generateBlockKey({ ip, port, portEnd, domain, application, protocol, direction: dir });
  const cacheKey     = scopedKey(generatedKey, company);
  let rawCacheKey    = rawBlockKey ? scopedKey(rawBlockKey, company) : null;

  let entry     = blocklistCache.get(cacheKey);
  let resolvedKey = cacheKey;

  if (!entry && rawCacheKey) {
    entry = blocklistCache.get(rawCacheKey);
    if (entry) resolvedKey = rawCacheKey;
  }

  if (!entry && (ip || domain)) {
    for (const [k, v] of blocklistCache.entries()) {
      if ((ip && v.ip === ip) || (domain && v.domain === domain)) {
        entry = v; resolvedKey = k; break;
      }
    }
  }

  const fallbackEntry = entry || { ip, port, portEnd, domain, application, protocol, direction: dir };

  let enforcement;
  try {
    const fwType = _getFirewallType();
    if (fwType === 'nftables') {
      enforcement = await _removeNftablesBlock(fallbackEntry);
    } else if (fwType === 'windows-defender') {
      enforcement = await _removeWindowsDefenderBlock(fallbackEntry);
    } else if (fwType === 'endpoint-agent') {
      logger.info(`[ENDPOINT-AGENT] Delegated unblock for ${resolvedKey}`);
      enforcement = { success: true, enforced: false, delegated: true, method: 'endpoint-agent' };
    } else {
      logger.info(`📝 [LOG-ONLY] Would unblock ${resolvedKey}`);
      enforcement = { success: true, enforced: false, method: 'log-only' };
    }
    if (!enforcement?.success) throw new Error(enforcement?.error || 'firewall did not confirm unblock');
  } catch (err) {
    logger.error(`Firewall unblock failed for ${resolvedKey}: ${err.message}`);
    throw new Error(`Firewall unblock failed for ${resolvedKey}: ${err.message}`);
  }

  blocklistCache.delete(cacheKey);
  _clearExpiry(cacheKey);
  if (rawCacheKey && rawCacheKey !== cacheKey) blocklistCache.delete(rawCacheKey);
  if (rawCacheKey && rawCacheKey !== cacheKey) _clearExpiry(rawCacheKey);
  if (resolvedKey !== cacheKey && resolvedKey !== rawCacheKey) blocklistCache.delete(resolvedKey);
  if (resolvedKey !== cacheKey && resolvedKey !== rawCacheKey) _clearExpiry(resolvedKey);

  try {
    const db = getDB();
    if (db) {
      const orFilter = [{ blockKey: generatedKey }];
      if (rawBlockKey) orFilter.push({ blockKey: rawBlockKey });
      if (ip) orFilter.push({ ip });
      if (domain) orFilter.push({ domain });
      await db.collection('firewall_blocks').deleteMany({
        $or: orFilter,
        ...(company && { company }),
      });
    }
  } catch (err) {
    logger.error(`Failed to remove block from DB: ${err.message}`);
  }

  return {
    action: 'unblock',
    blockKey: resolvedKey,
    enforced: enforcement.enforced !== false,
    method: enforcement.method || 'unknown',
    delegated: enforcement.delegated === true,
  };
}

async function unblockIP(ip) { return unblockTarget({ ip }); }

// ── Blocklist Access (tenant-scoped) ─────────────────────────────────────────
function getBlocklist(company) {
  const prefix = company ? `company:${company}|` : '';
  const list = [];
  const now = Date.now();
  blocklistCache.forEach((value, key) => {
    if (_isExpired(value, now)) {
      blocklistCache.delete(key);
      _clearExpiry(key);
      unblockTarget({
        ip: value.ip,
        port: value.port,
        domain: value.domain,
        application: value.application,
        protocol: value.protocol,
        direction: value.direction,
        rawBlockKey: value.blockKey,
        company: value.company,
      }).catch(err => logger.warn(`Expired block cleanup failed for ${value.blockKey || key}: ${err.message}`));
      return;
    }
    if (!company) {
      list.push({ blockKey: value.blockKey || key, ...value });
      return;
    }
    const keyMatch = key.startsWith(prefix);
    const valMatch = value.company && (
      value.company === company || String(value.company) === String(company)
    );
    if (keyMatch || valMatch) {
      list.push({ blockKey: value.blockKey || key, ...value });
    }
  });
  return list.sort((a, b) => {
    const aTime = new Date(a.updatedAt || a.ts || a.blockedAt || a.createdAt || 0).getTime();
    const bTime = new Date(b.updatedAt || b.ts || b.blockedAt || b.createdAt || 0).getTime();
    return (Number.isFinite(bTime) ? bTime : 0) - (Number.isFinite(aTime) ? aTime : 0);
  });
}

function getBlocklistStatus(company) {
  const list = getBlocklist(company);
  return { count: list.length, list };
}

async function loadPersistedBlocks() {
  try {
    const db = getDB();
    if (!db) { logger.warn('⚠️  MongoDB not available — skipping block persistence'); return 0; }
    const collection = db.collection('firewall_blocks');
    await Promise.all([
      collection.createIndex({ company: 1, status: 1 }),
      collection.createIndex({ company: 1, blockKey: 1 }),
      collection.createIndex({ expiresAt: 1 }),
    ]);
    await sweepExpiredBlocks();
    const blocks = await collection.find({
      status: 'blocked',
      $or: [
        { expiresAt: { $exists: false } },
        { expiresAt: null },
        { expiresAt: { $gt: new Date() } },
      ],
    }).toArray();
    for (const block of blocks) {
      const key = scopedKey(block.blockKey, block.company);
      blocklistCache.set(key, block);
      _scheduleExpiry(block);
    }
    logger.info(`✅ Loaded ${blocks.length} persisted firewall blocks from MongoDB`);
    return blocks.length;
  } catch (err) {
    logger.error(`Failed to load persisted blocks: ${err.message}`);
    return 0;
  }
}

async function sweepExpiredBlocks() {
  try {
    const db = getDB();
    if (!db) return 0;
    const now = new Date();
    const expired = await db.collection('firewall_blocks').find({
      status: 'blocked',
      expiresAt: { $lte: now },
      $or: [
        { cleanupRetryAt: { $exists: false } },
        { cleanupRetryAt: null },
        { cleanupRetryAt: { $lte: now } },
      ],
    }).toArray();
    if (!expired.length) return 0;

    let removed = 0;
    let failed = 0;
    for (const block of expired) {
      try {
        await unblockTarget({
        ip: block.ip,
        port: block.port,
        domain: block.domain,
        application: block.application,
        protocol: block.protocol,
        direction: block.direction,
        rawBlockKey: block.blockKey,
        company: block.company,
        });
        removed += 1;
      } catch (err) {
        failed += 1;
        logger.warn(`TTL cleanup unblock failed for ${block.blockKey}: ${err.message}`);
        await db.collection('firewall_blocks').updateOne(
          { _id: block._id },
          { $set: { cleanupStatus: 'retry', cleanupError: String(err.message || err).slice(0, 1000), cleanupRetryAt: new Date(Date.now() + 5 * 60 * 1000) } },
        ).catch(updateErr => logger.warn(`TTL cleanup retry state failed for ${block.blockKey}: ${updateErr.message}`));
      }
    }
    logger.info(`⏱️ TTL cleanup removed ${removed} expired firewall block(s)${failed ? `; ${failed} pending retry` : ''}`);
    return removed;
  } catch (err) {
    logger.error(`Failed to sweep expired firewall blocks: ${err.message}`);
    return 0;
  }
}

async function clearBlockEntry(blockKey) {
  blocklistCache.delete(blockKey);
  _clearExpiry(blockKey);
  try {
    const db = getDB();
    if (db) await db.collection('firewall_blocks').deleteOne({ blockKey });
  } catch (err) {
    logger.error(`Failed to clear block: ${err.message}`);
  }
}

async function clearAllBlocks() {
  for (const timer of expiryTimers.values()) clearTimeout(timer);
  expiryTimers.clear();
  blocklistCache.clear();
  try {
    const db = getDB();
    if (db) await db.collection('firewall_blocks').deleteMany({});
  } catch (err) {
    logger.error(`Failed to clear all blocks: ${err.message}`);
  }
}

// ── Validators / Formatters ───────────────────────────────────────────────────
function isValidIP(ip) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const ipv6 = /^([a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}$/i;
  if (ipv4.test(ip)) {
    const base = ip.split('/')[0];
    return base.split('.').every(p => { const n = parseInt(p, 10); return n >= 0 && n <= 255; });
  }
  return ipv6.test(ip);
}

function isNonRoutableIP(ip) {
  const value = String(ip || '').split('/')[0].toLowerCase();
  const version = net.isIP(value);
  if (version === 4) {
    const [a, b] = value.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0)
      || (a === 198 && (b === 18 || b === 19));
  }
  if (version === 6) {
    return value === '::' || value === '::1'
      || value.startsWith('fe8') || value.startsWith('fe9')
      || value.startsWith('fea') || value.startsWith('feb')
      || value.startsWith('fc') || value.startsWith('fd')
      || value.startsWith('ff');
  }
  return true;
}

function generateBlockKey(c) {
  const parts = [];
  if (c.ip)          parts.push(`ip:${c.ip}`);
  if (c.port)        parts.push(`port:${c.port}${c.portEnd ? `-${c.portEnd}` : ''}`);
  if (c.domain)      parts.push(`domain:${c.domain}`);
  if (c.application) parts.push(`app:${c.application}`);
  if (c.protocol && c.protocol !== 'all') parts.push(`proto:${c.protocol}`);
  if (c.direction && c.direction !== 'both') parts.push(`dir:${c.direction}`);
  return parts.join('|');
}

function formatBlockDescription(c) {
  const parts = [];
  if (c.ip)          parts.push(`IP:${c.ip}`);
  if (c.port)        parts.push(`Port:${c.port}${c.portEnd ? `-${c.portEnd}` : ''}`);
  if (c.domain)      parts.push(`Domain:${c.domain}`);
  if (c.application) parts.push(`App:${c.application}`);
  if (c.protocol && c.protocol !== 'all') parts.push(`Proto:${c.protocol.toUpperCase()}`);
  if (c.direction)   parts.push(`[${c.direction.toUpperCase()}]`);
  return parts.join(', ');
}

// ── WAF NAT Port Forward — pfSense ────────────────────────────────────────────
async function createNATPortForwardPfSense(agentIP, originalPort, wafPort, reason) {
  const result = await _pfSenseAPICall('POST', '/firewall/nat/port_forward', {
    interface:  'wan',
    protocol:   'tcp',
    src:        'any',
    src_port:   null,
    dst:        'any',
    dst_port:   String(originalPort),
    target:     agentIP,
    local_port: String(wafPort),
    descr:      `SOC4 WAF: ${agentIP}:${originalPort}→${wafPort} | ${reason || 'WAF redirect'}`,
    enabled:    true,
  });
  logger.info(`[pfSense] NAT port forward created: WAN:${originalPort} → ${agentIP}:${wafPort}`);
  return result;
}

async function removeNATPortForwardPfSense(ruleId) {
  if (!ruleId) return;
  const result = await _pfSenseAPICall('DELETE', `/firewall/nat/port_forward/${ruleId}`, null);
  logger.info(`[pfSense] NAT port forward removed: rule ${ruleId}`);
  return result;
}

// ── WAF NAT Port Forward — OPNsense ──────────────────────────────────────────
async function createNATPortForwardOPNsense(agentIP, originalPort, wafPort, reason) {
  const result = await _opnsenseAPICall('POST', 'firewall/nat/addRule', {
    rule: {
      interface:   'wan',
      protocol:    'TCP',
      src:         'any',
      srcport:     '',
      dst:         'any',
      dstport:     String(originalPort),
      target:      agentIP,
      localport:   String(wafPort),
      description: `SOC4 WAF: ${agentIP}:${originalPort}→${wafPort} | ${reason || 'WAF redirect'}`,
      enabled:     '1',
    },
  });
  logger.info(`[OPNsense] NAT port forward created: WAN:${originalPort} → ${agentIP}:${wafPort}`);
  return result;
}

async function removeNATPortForwardOPNsense(uuid) {
  if (!uuid) return;
  const result = await _opnsenseAPICall('POST', `firewall/nat/delRule/${uuid}`, null);
  logger.info(`[OPNsense] NAT port forward removed: uuid ${uuid}`);
  return result;
}

// ── Public: Create WAF NAT Port Forward (auto-detects firewall type) ──────────
async function createWAFNATRule(agentIP, originalPort, wafPort, reason = 'SOC4 WAF') {
  const fwType = _getFirewallType();
  try {
    if (fwType === 'pfsense') {
      const r = await createNATPortForwardPfSense(agentIP, originalPort, wafPort, reason);
      return { success: true, firewall: 'pfsense', ruleId: r?.data?.id || r?.id || null };
    } else if (fwType === 'opnsense') {
      const r = await createNATPortForwardOPNsense(agentIP, originalPort, wafPort, reason);
      return { success: true, firewall: 'opnsense', ruleId: r?.uuid || r?.result || null };
    } else {
      logger.info(`[WAF NAT] Log-only mode — would redirect WAN:${originalPort} → ${agentIP}:${wafPort}`);
      return { success: true, firewall: 'log-only', ruleId: null };
    }
  } catch (err) {
    logger.error(`[WAF NAT] createWAFNATRule failed: ${err.message}`);
    return { success: false, error: err.message };
  }
}

// ── Public: Remove WAF NAT Port Forward ──────────────────────────────────────
async function removeWAFNATRule(ruleId, firewall) {
  if (!ruleId) return;
  try {
    if (firewall === 'pfsense')   await removeNATPortForwardPfSense(ruleId);
    if (firewall === 'opnsense')  await removeNATPortForwardOPNsense(ruleId);
  } catch (err) {
    logger.error(`[WAF NAT] removeWAFNATRule failed: ${err.message}`);
  }
}

module.exports = {
  blockTarget, unblockTarget, blockIP, unblockIP,
  getBlocklist, getBlocklistStatus,
  loadPersistedBlocks, sweepExpiredBlocks, clearBlockEntry, clearAllBlocks,
  isValidIP, generateBlockKey, formatBlockDescription, normalizeDirection,
  isNonRoutableIP,
  // WAF NAT Port Forward
  createWAFNATRule, removeWAFNATRule,
  // Exported so webhookController can call directly
  _getFirewallType,
};
