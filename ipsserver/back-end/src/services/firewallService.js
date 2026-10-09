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
const targetOperations = new Map();
const MAX_TIMER_DELAY = 2 ** 31 - 1;

// Shared host firewall rules need serialized updates, even across tenants.
function withTargetLock(options, operation) {
  const entry = options.rawBlockKey && blocklistCache.get(scopedKey(options.rawBlockKey, options.company));
  const key = options.ip || entry?.ip || options.domain || entry?.domain || options.rawBlockKey || generateBlockKey(options);
  const previous = targetOperations.get(key) || Promise.resolve();
  const current = previous.catch(() => {}).then(operation);
  targetOperations.set(key, current);
  const cleanup = () => { if (targetOperations.get(key) === current) targetOperations.delete(key); };
  current.then(cleanup, cleanup);
  return current;
}

function ttlValue(value) {
  if (!['number', 'string'].includes(typeof value) || String(value).trim() === '') {
    throw new Error('ttlHours must be a finite, non-negative number');
  }
  const ttl = Number(value);
  if (!Number.isFinite(ttl) || ttl < 0 || !Number.isFinite(new Date(Date.now() + ttl * 3600000).getTime())) {
    throw new Error('ttlHours must be a finite, non-negative number');
  }
  return ttl;
}

function normalizeOptions(options) {
  const normalized = { ...options };
  if (net.isIP(normalized.ip) === 6 && !normalized.ip.includes('%')) {
    normalized.ip = new URL(`http://[${normalized.ip}]/`).hostname.slice(1, -1);
  }
  return normalized;
}
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
  if (typeof dir !== 'string') throw new Error('Invalid direction');
  const d = (dir || 'both').toLowerCase().trim();
  if (d === 'inbound' || d === 'in') return 'inbound';
  if (d === 'outbound' || d === 'out') return 'outbound';
  if (d === 'both') return 'both';
  throw new Error('Invalid direction');
}

function scopedKey(blockKey, company) {
  return company ? `company:${company}|${blockKey}` : blockKey;
}

function _clearExpiry(cacheKey) {
  const timer = expiryTimers.get(cacheKey);
  if (timer) clearTimeout(timer);
  expiryTimers.delete(cacheKey);
}

function _scheduleExpiry(blockEntry, retryDelay = 0) {
  if (!blockEntry?.blockKey) return;
  const cacheKey = scopedKey(blockEntry.blockKey, blockEntry.company);
  _clearExpiry(cacheKey);
  if (!blockEntry.expiresAt) return;
  const delay = new Date(blockEntry.expiresAt).getTime() - Date.now();
  if (!Number.isFinite(delay)) return;

  const expire = async () => {
    expiryTimers.delete(cacheKey);
    if (blocklistCache.get(cacheKey) !== blockEntry) return;
    // Long TTLs are rearmed, never passed to setTimeout above its 32-bit limit.
    if (!_isExpired(blockEntry)) return _scheduleExpiry(blockEntry);
    try {
      const result = await unblockTarget({
        ...blockEntry,
        port: blockEntry.portEnd ? `${blockEntry.port}-${blockEntry.portEnd}` : blockEntry.port,
        rawBlockKey: blockEntry.blockKey,
        expectedEntry: blockEntry,
      });
      if (result.skipped) return;
      logger.info(`TTL expired — automatically unblocked ${blockEntry.blockKey}`);
      if (typeof global.emitIPSEvent === 'function') {
        global.emitIPSEvent('unblock', {
          action: 'unblock', reason: 'Block TTL expired', blockKey: blockEntry.blockKey,
          ip: blockEntry.ip, domain: blockEntry.domain, company: blockEntry.company,
          ts: new Date().toISOString(),
        });
      }
    } catch (err) {
      logger.error(`TTL auto-unblock failed for ${blockEntry.blockKey}: ${err.message}`);
      if (blocklistCache.get(cacheKey) === blockEntry) _scheduleExpiry(blockEntry, 5 * 60 * 1000);
    }
  };
  const timer = setTimeout(expire, Math.min(MAX_TIMER_DELAY, Math.max(0, delay, retryDelay)));
  timer.unref?.();
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
  if (!(await _nftExists())) return { success: false, error: 'nft command not available' };
  const run = async (args, allowExisting = false) => {
    const result = await _tryExec('nft', args);
    if (result.error && !(allowExisting && /File exists/i.test(result.stderr))) {
      throw new Error(result.stderr || result.error.message);
    }
    return result;
  };
  try {
    await run(['add', 'table', 'inet', 'soc4'], true);
    for (const [name, type] of [['blocked_ipv4', 'ipv4_addr;'], ['blocked_ipv6', 'ipv6_addr;']]) {
      await run(['add', 'set', 'inet', 'soc4', name, '{', 'type', type, 'flags', 'interval;', '}'], true);
    }
    for (const [chain, address, suffix] of [['input', 'saddr', 'IN'], ['output', 'daddr', 'OUT']]) {
      await run(['add', 'chain', 'inet', 'soc4', chain, '{', 'type', 'filter', 'hook', chain, 'priority', '-100;', 'policy', 'accept;', '}'], true);
      const listed = await run(['list', 'chain', 'inet', 'soc4', chain]);
      for (const [family, set, label] of [['ip', 'blocked_ipv4', 'IPV4'], ['ip6', 'blocked_ipv6', 'IPV6']]) {
        if (!String(listed.stdout).includes(`@${set}`)) {
          await run(['add', 'rule', 'inet', 'soc4', chain, family, address, `@${set}`, 'drop', 'comment', `SOC4_BLOCKLIST_${label}_${suffix}`]);
        }
      }
    }
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

function hostCriteriaError(criteria, bothDirectionsOnly = false) {
  if (criteria.domain || criteria.application || criteria.port || (criteria.protocol && criteria.protocol !== 'all')
      || (bothDirectionsOnly && criteria.direction !== 'both')) {
    return 'This host firewall adapter supports IP-only blocks'
      + (bothDirectionsOnly ? ' in both directions' : '')
      + '; use endpoint-agent mode for port, protocol, domain, or application rules';
  }
  return null;
}

async function _applyNftablesBlock(criteria) {
  const { ip } = criteria;
  const error = hostCriteriaError(criteria, true);
  if (error) return { success: false, error };
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
  const error = hostCriteriaError(criteria);
  if (error) return { success: false, error };
  if (!ip || !net.isIP(ip)) return { success: false, error: 'Windows Defender Firewall requires an IP target' };
  const dirs = direction === 'outbound' ? ['Outbound'] : direction === 'inbound' ? ['Inbound'] : ['Inbound', 'Outbound'];
  const created = [];
  for (const dir of dirs) {
    const displayName = _windowsRuleName(ip, dir);
    const result = await _tryExec('powershell.exe', [
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command',
      `$ErrorActionPreference = 'Stop'; if (-not (Get-NetFirewallRule -DisplayName '${displayName}' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '${displayName}' -Direction ${dir} -Action Block -RemoteAddress '${ip}' -Profile Any | Out-Null; 'created' }`,
    ]);
    if (result.error) {
      for (const name of created) {
        await _tryExec('powershell.exe', ['-NoProfile', '-Command', `Remove-NetFirewallRule -DisplayName '${name}' -ErrorAction Stop`]);
      }
      return { success: false, error: result.stderr || result.error.message };
    }
    if (String(result.stdout).trim() === 'created') created.push(displayName);
  }
  logger.block(`[Windows Defender Firewall] Block applied for ${ip}`);
  return { success: true, method: 'windows-defender' };
}

async function _removeWindowsDefenderBlock(entry, resolvedKey) {
  const { ip, direction } = entry;
  if (!ip || !net.isIP(ip)) return { success: false, error: 'Windows Defender Firewall unblock requires an IP target' };
  const dirs = direction === 'outbound' ? ['Outbound'] : direction === 'inbound' ? ['Inbound'] : ['Inbound', 'Outbound'];
  let sharedRuleRetained = false;
  for (const dir of dirs) {
    const shared = [...blocklistCache.entries()].some(([key, value]) => key !== resolvedKey
      && value.ip === ip && value.method === 'windows-defender'
      && (value.direction === 'both' || value.direction === dir.toLowerCase()));
    if (shared) { sharedRuleRetained = true; continue; }
    const name = _windowsRuleName(ip, dir);
    const result = await _tryExec('powershell.exe', ['-NoProfile', '-Command',
      `$ErrorActionPreference = 'Stop'; Get-NetFirewallRule -DisplayName '${name}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop`,
    ]);
    if (result.error) return { success: false, error: result.stderr || result.error.message };
  }
  return { success: true, method: 'windows-defender', sharedRuleRetained };
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
  if (portField === undefined || portField === null || portField === '') return { port: null, portEnd: null };
  if (!['string', 'number'].includes(typeof portField) || !/^\d+(?:-\d+)?$/.test(String(portField).trim())) {
    throw new Error('Invalid port or port range');
  }
  const [port, portEnd = null] = String(portField).trim().split('-').map(Number);
  if (!Number.isInteger(port) || port < 1 || port > 65535
      || (portEnd !== null && (!Number.isInteger(portEnd) || portEnd < port || portEnd > 65535))) {
    throw new Error('Invalid port or port range');
  }
  return { port, portEnd };
}

function validateProtocol(protocol) {
  if (protocol != null && !['tcp', 'udp', 'icmp', 'icmpv6', 'all'].includes(protocol)) {
    throw new Error('Invalid protocol');
  }
}

// ── Public: Block Target ──────────────────────────────────────────────────────
function blockTarget(options = {}) {
  const normalized = normalizeOptions(options);
  return withTargetLock(normalized, () => _blockTarget(normalized));
}

async function _blockTarget(options) {
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
  validateProtocol(protocol);

  if (!ip && !domain && !application && !port && (!protocol || protocol === 'all')) {
    throw new Error('At least one of: ip, domain, application, port, or protocol is required');
  }
  if (ip && !isValidIP(ip)) throw new Error(`Invalid IP address: ${ip}`);
  if (ip && options.automatic !== false && !/^manual$/i.test(source)) {
    const decision = await require('./threatVerificationService').verifyAutomaticBlock({ ip, company });
    if (!decision.allowed) return { ok: false, skipped: true, tiDeferred: true, enforced: false, reason: decision.reason, ip };
  }
  if ((domain && typeof domain !== 'string') || (application && typeof application !== 'string')) {
    throw new Error('Domain and application targets must be strings');
  }
  if (port && (port < 1 || port > 65535)) throw new Error(`Invalid port: ${port}`);

  const ttl = ttlValue(ttlHours);
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
      ttlHours: ttl,
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
          { blockKey, company: company || null },
          { $set: refreshed },
          { upsert: true }
        );
      }
    } catch (err) {
      logger.error(`Failed to refresh existing block timestamp: ${err.message}`);
      throw Object.assign(new Error('Block active, but persistence update failed; retry the block'), { statusCode: 503 });
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
      method: refreshed.method || 'log-only',
      enforced: ['nftables', 'windows-defender'].includes(refreshed.method),
      delegated: refreshed.method === 'endpoint-agent',
      direction: refreshed.direction,
      description: formatBlockDescription(refreshed),
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
    ttlHours: ttl,
    expiresAt: ttl > 0
      ? new Date(Date.now() + (ttl * 60 * 60 * 1000))
      : null,
    company: company || undefined,
    ruleId,
  };

  blocklistCache.set(cacheKey, blockEntry);
  _scheduleExpiry(blockEntry);

  try {
    const db = getDB();
    if (db) {
      await db.collection('firewall_blocks').updateOne({ blockKey, company: company || null }, { $set: blockEntry }, { upsert: true });
    }
  } catch (err) {
    logger.error(`Failed to persist block: ${err.message}`);
    throw Object.assign(new Error('Block active, but persistence failed; retry the block'), { statusCode: 503 });
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
function unblockTarget(options = {}) {
  const normalized = normalizeOptions(options);
  return withTargetLock(normalized, () => _unblockTarget(normalized));
}

async function _unblockTarget(options) {
  const { ip, domain, application, protocol, direction = 'both', rawBlockKey, company } = options;
  const { port, portEnd } = _parsePort(options.port);
  const dir = normalizeDirection(direction);
  validateProtocol(protocol);

  if (!rawBlockKey && !ip && !domain && !application && !port && (!protocol || protocol === 'all')) {
    throw new Error('At least one of: ip, domain, application, port, or protocol is required');
  }

  const generatedKey = generateBlockKey({ ip, port, portEnd, domain, application, protocol, direction: dir });
  const cacheKey     = scopedKey(generatedKey, company);
  const rawCacheKey = rawBlockKey ? scopedKey(rawBlockKey, company) : null;
  // A supplied key identifies one exact rule. Never fall back to another
  // tenant or another port/direction just because the target IP is the same.
  const resolvedKey = rawCacheKey || cacheKey;
  const entry = blocklistCache.get(resolvedKey);
  if (options.expectedEntry && entry !== options.expectedEntry) return { skipped: true };
  if (!entry) {
    return { action: 'unblock', blockKey: rawBlockKey || generatedKey, enforced: false, method: 'none', note: 'not blocked' };
  }
  const fallbackEntry = entry;

  let enforcement;
  try {
    const fwType = entry.method || _getFirewallType();
    if (fwType === 'nftables') {
      const shared = [...blocklistCache.entries()].some(([key, value]) =>
        key !== resolvedKey && value.ip === entry.ip && value.method === 'nftables');
      enforcement = shared
        ? { success: true, method: 'nftables', sharedRuleRetained: true }
        : await _removeNftablesBlock(fallbackEntry);
    } else if (fwType === 'windows-defender') {
      enforcement = await _removeWindowsDefenderBlock(fallbackEntry, resolvedKey);
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

  blocklistCache.delete(resolvedKey);
  _clearExpiry(resolvedKey);
  try {
    const db = getDB();
    if (db) {
      await db.collection('firewall_blocks').deleteOne({ blockKey: entry.blockKey, company: company || null });
    }
  } catch (err) {
    logger.error(`Failed to remove block from DB: ${err.message}`);
    // Keep retryable state rather than resurrecting this rule on restart.
    blocklistCache.set(resolvedKey, entry);
    _scheduleExpiry(entry, 5 * 60 * 1000);
    throw new Error('Firewall rule removed, but persistence cleanup failed; retry the unblock');
  }

  return {
    action: 'unblock',
    blockKey: entry.blockKey,
    sharedRuleRetained: enforcement.sharedRuleRetained === true,
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
  blocklistCache.forEach((value, key) => {
    // Expired rules remain visible until firewall cleanup actually succeeds.
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
    const blocks = await collection.find({ status: 'blocked' }).toArray();
    for (const block of blocks) {
      blocklistCache.set(scopedKey(block.blockKey, block.company), block);
    }
    // Load every reference first: removing an expired shared host rule must
    // not remove a different tenant's still-active rule for the same IP.
    await sweepExpiredBlocks();
    for (const block of blocklistCache.values()) _scheduleExpiry(block);
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

    const active = await db.collection('firewall_blocks').find({ status: 'blocked' }).toArray();
    for (const block of active) {
      const key = scopedKey(block.blockKey, block.company);
      if (!blocklistCache.has(key)) blocklistCache.set(key, block);
    }
    let removed = 0;
    let failed = 0;
    for (const block of expired) {
      try {
        await unblockTarget({
        ip: block.ip,
        port: block.portEnd ? `${block.port}-${block.portEnd}` : block.port,
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
  if (typeof ip !== 'string' || ip.includes('%')) return false;
  const parts = ip.split('/');
  const version = net.isIP(parts[0]);
  if (!version || parts.length > 2) return false;
  return parts.length === 1 || (/^\d+$/.test(parts[1]) && Number(parts[1]) <= (version === 4 ? 32 : 128));
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
