const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { createClient } = require('redis');

const DEFAULT_RULES = Object.freeze([
  // The company landing dashboard fans out across several collections. Keep
  // one snapshot per authenticated tenant scope and collapse concurrent opens
  // so a burst of users does not repeat the same aggregation work.
  { pattern: /^\/api\/company\/overview$/, ttlSeconds: 60 },
  { pattern: /^\/api\/dashboard\/overview$/, ttlSeconds: 15 },
  { pattern: /^\/api\/dashboard\/company\/[a-f\d]{24}\/overview$/i, ttlSeconds: 15 },
  { pattern: /^\/api\/dashboard\/capabilities\/\d+\/live$/, ttlSeconds: 10 },
  { pattern: /^\/api\/dashboard\/alerts\/[a-z-]+$/i, ttlSeconds: 5 },
  { pattern: /^\/api\/security-score(?:\/|$)/, ttlSeconds: 30 },
  { pattern: /^\/api\/edr-cap\/(?:live-overview|status|new-services|service-status)$/, ttlSeconds: 30 },
  { pattern: /^\/api\/soc-edr\/(?:dashboard|endpoint-risk|mitre-coverage|live-telemetry)$/, ttlSeconds: 10 },
  { pattern: /^\/api\/email-threat\/(?:dashboard|live|logs|attachments|urls|authentication|mailbox|threat-intelligence|quarantine|alerts)$/, ttlSeconds: 5 },
  { pattern: /^\/api\/credential-security\/dashboard$/, ttlSeconds: 15 },
  { pattern: /^\/api\/credential-security\/(?:live|logs|reports)$/, ttlSeconds: 10 },
  { pattern: /^\/api\/lateral-movement\/dashboard$/, ttlSeconds: 15 },
  { pattern: /^\/api\/lateral-movement\/(?:live|logs|reports)$/, ttlSeconds: 10 },
  { pattern: /^\/api\/ueba\/dashboard$/, ttlSeconds: 15 },
  { pattern: /^\/api\/ueba\/baseline(?:\/[a-f\d]{24})?$/i, ttlSeconds: 30 },
  { pattern: /^\/api\/(?:l1|l2|l3|soc-manager)\/dashboard$/, ttlSeconds: 30, personal: true },
  { pattern: /^\/api\/soc-dashboard\/summary$/, ttlSeconds: 30, personal: true },
  { pattern: /^\/api\/(?:partner|fraud|forensics)\/dashboard$/, ttlSeconds: 10 },
  { pattern: /^\/api\/soar\/dashboard\/summary$/, ttlSeconds: 10 },
]);

class BoundedMemoryCache {
  constructor(maxEntries = 2000) {
    this.maxEntries = Math.max(10, Number(maxEntries) || 2000);
    this.entries = new Map();
  }

  get(key) {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.entries.delete(key);
      return null;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key, value, ttlSeconds) {
    this.entries.delete(key);
    this.entries.set(key, { value, expiresAt: Date.now() + (ttlSeconds * 1000) });
    while (this.entries.size > this.maxEntries) {
      this.entries.delete(this.entries.keys().next().value);
    }
  }

  clear() {
    this.entries.clear();
  }
}

class TieredResponseCache {
  constructor(options = {}) {
    this.memory = options.memory || new BoundedMemoryCache(options.maxEntries || process.env.READ_CACHE_MAX_ENTRIES);
    this.redisUrl = options.redisUrl === undefined
      ? (process.env.READ_CACHE_REDIS_URL || process.env.REDIS_URL || process.env.SOCKET_REDIS_URL)
      : options.redisUrl;
    this.redisEnabled = options.redisEnabled === undefined
      ? process.env.READ_CACHE_REDIS_ENABLED !== 'false'
      : options.redisEnabled;
    this.redisClient = null;
    this.connecting = null;
    this.retryAfter = 0;
  }

  async redis() {
    if (!this.redisEnabled || !this.redisUrl || Date.now() < this.retryAfter) return null;
    if (this.redisClient?.isReady) return this.redisClient;
    if (this.connecting) return this.connecting;

    const client = createClient({
      url: this.redisUrl,
      socket: { connectTimeout: 1000, reconnectStrategy: false },
    });
    client.on('error', () => {});
    this.connecting = client.connect()
      .then(() => {
        this.redisClient = client;
        return client;
      })
      .catch(() => {
        this.retryAfter = Date.now() + 30_000;
        client.destroy?.();
        return null;
      })
      .finally(() => { this.connecting = null; });
    return this.connecting;
  }

  async get(key) {
    const local = this.memory.get(key);
    if (local !== null) return local;
    const client = await this.redis();
    if (!client) return null;
    try {
      const raw = await client.get(key);
      if (!raw) return null;
      const value = JSON.parse(raw);
      this.memory.set(key, value, 5);
      return value;
    } catch {
      return null;
    }
  }

  async set(key, value, ttlSeconds) {
    this.memory.set(key, value, ttlSeconds);
    const client = await this.redis();
    if (!client) return;
    try {
      await client.setEx(key, ttlSeconds, JSON.stringify(value));
    } catch { /* memory cache remains available */ }
  }

  async close() {
    const client = this.redisClient;
    this.redisClient = null;
    this.connecting = null;
    if (client?.isOpen) await client.quit().catch(() => client.destroy?.());
  }
}

function canonicalQuery(query = {}) {
  return Object.keys(query).sort().map(key => {
    const value = Array.isArray(query[key]) ? [...query[key]].sort() : query[key];
    return `${encodeURIComponent(key)}=${encodeURIComponent(JSON.stringify(value))}`;
  }).join('&');
}

function matchingRule(pathname, rules = DEFAULT_RULES) {
  return rules.find(rule => rule.pattern.test(pathname)) || null;
}

function verifiedClaims(req) {
  const header = String(req.headers.authorization || '');
  if (!header.startsWith('Bearer ') || !process.env.JWT_SECRET) return null;
  try {
    return jwt.verify(header.slice(7), process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

function requestCacheKey(req, claims, rule) {
  const scope = [
    claims.tenantId || 'tenant',
    claims.partnerId || 'partner',
    claims.companyId || 'company',
    claims.departmentId || 'department',
    claims.role || 'role',
    rule.personal ? (claims.id || claims._id || 'user') : 'shared',
  ].map(String).join(':');
  const raw = `${scope}|${req.path}|${canonicalQuery(req.query)}`;
  return `soc:read:v2:${crypto.createHash('sha256').update(raw).digest('hex')}`;
}

const sharedCache = new TieredResponseCache();

function createScalableReadCache(options = {}) {
  const cache = options.cache || sharedCache;
  const rules = options.rules || DEFAULT_RULES;
  const enabled = options.enabled === undefined
    ? process.env.SCALABLE_READ_CACHE_ENABLED !== 'false'
    : options.enabled;
  const maxConcurrentMisses = Math.max(1, Number(options.maxConcurrentMisses || process.env.READ_CACHE_MAX_CONCURRENT_MISSES || 64));
  const maxPayloadBytes = Math.max(1024, Number(options.maxPayloadBytes || process.env.READ_CACHE_MAX_PAYLOAD_BYTES || 2_000_000));
  const waitTimeoutMs = Math.max(250, Number(options.waitTimeoutMs || process.env.READ_CACHE_WAIT_TIMEOUT_MS || 10_000));
  const inFlight = new Map();
  let activeMisses = 0;

  return async function scalableReadCache(req, res, next) {
    if (!enabled || req.method !== 'GET' || req.headers['x-skip-server-cache'] === '1') return next();
    const rule = matchingRule(req.path, rules);
    if (!rule) return next();
    const claims = verifiedClaims(req);
    if (!claims) return next();
    req.user = claims;
    const key = requestCacheKey(req, claims, rule);

    const cached = await cache.get(key).catch(() => null);
    if (cached !== null) {
      res.setHeader('x-soc-cache', 'HIT');
      res.setHeader('cache-control', 'private, no-cache');
      return res.status(200).json(cached);
    }

    const existing = inFlight.get(key);
    if (existing) {
      let waitTimer;
      const result = await Promise.race([
        existing,
        new Promise(resolve => { waitTimer = setTimeout(() => resolve(null), waitTimeoutMs); }),
      ]);
      clearTimeout(waitTimer);
      if (result?.cacheable) {
        res.setHeader('x-soc-cache', 'COALESCED');
        res.setHeader('cache-control', 'private, no-cache');
        return res.status(result.status).json(result.body);
      }
      // Never turn a slow cache fill into a request stampede. Starting another
      // copy here is especially expensive for dashboard aggregation routes and
      // can keep MongoDB saturated indefinitely while clients continue polling.
      if (result === null) {
        res.setHeader('Retry-After', '2');
        res.setHeader('x-soc-cache', 'REFRESHING');
        return res.status(503).json({
          message: 'Dashboard snapshot is still refreshing',
          code: 'READ_SNAPSHOT_REFRESHING',
        });
      }
      return next();
    }

    if (activeMisses >= maxConcurrentMisses) {
      return next();
    }

    activeMisses += 1;
    let resolveFlight;
    let settled = false;
    const flight = new Promise(resolve => { resolveFlight = resolve; });
    inFlight.set(key, flight);

    const settle = result => {
      if (settled) return;
      settled = true;
      activeMisses = Math.max(0, activeMisses - 1);
      inFlight.delete(key);
      resolveFlight(result);
    };
    const originalJson = res.json.bind(res);
    res.json = body => {
      let payloadBytes = Infinity;
      try { payloadBytes = Buffer.byteLength(JSON.stringify(body)); } catch { /* do not cache */ }
      const cacheable = res.statusCode === 200 && payloadBytes <= maxPayloadBytes;
      if (cacheable) {
        cache.set(key, body, rule.ttlSeconds).catch(() => {});
        settle({ cacheable: true, status: res.statusCode, body });
        res.setHeader('x-soc-cache', 'MISS');
        res.setHeader('cache-control', 'private, no-cache');
      } else {
        settle({ cacheable: false });
      }
      return originalJson(body);
    };
    res.once('finish', () => settle({ cacheable: false }));
    res.once('close', () => settle({ cacheable: false }));
    return next();
  };
}

const scalableReadCache = createScalableReadCache();

module.exports = {
  DEFAULT_RULES,
  BoundedMemoryCache,
  TieredResponseCache,
  canonicalQuery,
  matchingRule,
  requestCacheKey,
  createScalableReadCache,
  scalableReadCache,
  closeScalableReadCache: () => sharedCache.close(),
};
