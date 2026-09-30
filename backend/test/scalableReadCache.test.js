const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const {
  BoundedMemoryCache,
  canonicalQuery,
  createScalableReadCache,
  matchingRule,
} = require('../src/middleware/scalableReadCache');

class FakeCache {
  constructor() { this.values = new Map(); }
  async get(key) { return this.values.has(key) ? this.values.get(key) : null; }
  async set(key, value) { this.values.set(key, value); }
}

function responsePromise(run) {
  return new Promise((resolve, reject) => {
    const headers = {};
    const res = {
      statusCode: 200,
      setHeader(name, value) { headers[name.toLowerCase()] = value; },
      status(code) { this.statusCode = code; return this; },
      json(body) { resolve({ status: this.statusCode, body, headers }); return this; },
      once() {},
    };
    Promise.resolve(run(res)).catch(reject);
  });
}

test('canonical query keys are stable regardless of parameter order', () => {
  assert.equal(canonicalQuery({ z: 2, a: 1 }), canonicalQuery({ a: 1, z: 2 }));
});

test('company overview is protected by the shared read cache', () => {
  const rule = matchingRule('/api/company/overview');
  assert.ok(rule);
  assert.equal(rule.ttlSeconds, 60);
  assert.equal(rule.personal, undefined);
});

test('bounded memory cache evicts the least recently used entry', () => {
  const cache = new BoundedMemoryCache(10);
  for (let i = 0; i < 11; i += 1) cache.set(`k${i}`, i, 60);
  assert.equal(cache.get('k0'), null);
  assert.equal(cache.get('k10'), 10);
});

test('identical dashboard cache misses are coalesced into one route execution', async () => {
  const oldSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'test-secret-that-is-long-enough-for-jwt-cache';
  const token = jwt.sign({ id: 'user-1', companyId: 'company-1', role: 'company_admin' }, process.env.JWT_SECRET);
  const cache = new FakeCache();
  const middleware = createScalableReadCache({
    cache,
    rules: [{ pattern: /^\/api\/test$/, ttlSeconds: 10 }],
    maxConcurrentMisses: 2,
  });
  let routeRuns = 0;
  const request = () => ({
    method: 'GET', path: '/api/test', query: { range: '24h' },
    headers: { authorization: `Bearer ${token}` },
  });

  const first = responsePromise(res => middleware(request(), res, () => {
    routeRuns += 1;
    setTimeout(() => res.json({ value: 42 }), 25);
  }));
  const second = responsePromise(res => middleware(request(), res, () => {
    routeRuns += 1;
    res.json({ value: 99 });
  }));
  const [a, b] = await Promise.all([first, second]);
  const third = await responsePromise(res => middleware(request(), res, () => {
    routeRuns += 1;
    res.json({ value: 100 });
  }));

  assert.equal(routeRuns, 1);
  assert.deepEqual(a.body, { value: 42 });
  assert.deepEqual(b.body, { value: 42 });
  assert.deepEqual(third.body, { value: 42 });
  assert.equal(b.headers['x-soc-cache'], 'COALESCED');
  assert.equal(third.headers['x-soc-cache'], 'HIT');
  if (oldSecret === undefined) delete process.env.JWT_SECRET;
  else process.env.JWT_SECRET = oldSecret;
});
