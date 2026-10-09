const test = require('node:test');
const assert = require('node:assert/strict');
const Alert = require('../src/models/Alert.model');
const router = require('../src/routes/idsips.routes');

const handler = router.stack.find(layer => layer.route?.path === '/idsips/logs').route.stack.at(-1).handle;
const NOW = Date.parse('2026-10-09T12:00:00Z');
const DAY = 86400000;
const companyId = '6a8efb532c942f67c29534cc';

async function request(query = {}, company = companyId) {
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
  await handler({ user: { role: 'company_admin', companyId: company }, query }, res);
  return res;
}

function captureReads(t) {
  t.mock.method(Date, 'now', () => NOW);
  const queries = [];
  t.mock.method(Alert, 'find', filter => {
    queries.push(filter);
    const chain = { lean: async () => [] };
    for (const name of ['sort', 'skip', 'limit', 'select', 'maxTimeMS']) chain[name] = () => chain;
    return chain;
  });
  return queries;
}

test('IDS logs support historical ranges through 180 days without losing tenant or severity scope', async t => {
  const queries = captureReads(t);
  for (const [range, days] of [['24h', 1], ['7d', 7], ['30d', 30], ['60d', 60], ['90d', 90], ['180d', 180]]) {
    const res = await request({ range, skipCount: 'true', severity: 'high', companyId: 'foreign-company' });
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.queryWindowDays, days);
    assert.equal(res.body.maxQueryDays, 180);
    const filter = queries.at(-1);
    assert.equal(filter.createdAt.$gte.getTime(), NOW - days * DAY);
    assert.equal(String(filter.companyId), companyId);
    assert.equal(filter.severity, 'high');
    assert.ok(filter.$and.some(item => item.event_category?.$in.includes('ids_alert')));
  }
});

test('existing clients retain the default 24-hour and legacy 90-day windows', async t => {
  const queries = captureReads(t);
  for (const [query, days] of [[{}, 1], [{ range: 'retention' }, 90]]) {
    const res = await request({ ...query, skipCount: 'true' });
    assert.equal(res.statusCode, 200);
    assert.equal(queries.at(-1).createdAt.$gte.getTime(), NOW - days * DAY);
  }
});

test('row and count queries use the same window and cached counts stay separate by range', async t => {
  const queries = captureReads(t);
  const countFilters = [];
  t.mock.method(Alert, 'aggregate', pipeline => {
    const filter = pipeline[0].$match;
    countFilters.push(filter);
    const days = (NOW - filter.createdAt.$gte.getTime()) / DAY;
    return { option: () => Promise.resolve([{ _id: 'high', count: days }]) };
  });
  for (const range of ['24h', '180d', '180d']) {
    const res = await request({ range, severity: 'high' }, '6a8efb532c942f67c29534cd');
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.total, range === '24h' ? 1 : 180);
    assert.equal(res.body.overallTotal, res.body.total);
    assert.equal(queries.at(-1).createdAt.$gte.getTime(), countFilters.at(-1).createdAt.$gte.getTime());
  }
  assert.equal(countFilters.length, 2, 'each range gets its own cached aggregation');
});

test('unsupported or malformed ranges cannot create an unbounded historical query', async t => {
  const queries = captureReads(t);
  t.mock.method(Alert, 'aggregate', () => { throw new Error('must not query'); });
  for (const range of ['181d', '365d', 'all', '__proto__', '', ['180d'], { days: 180 }]) {
    const res = await request({ range });
    assert.equal(res.statusCode, 400);
    assert.match(res.body.message, /Invalid log range/);
  }
  assert.equal(queries.length, 0);
});

test('explicit dates can narrow a historical range but cannot extend it beyond 180 days', async t => {
  const queries = captureReads(t);
  const to = new Date(NOW - 3 * DAY).toISOString();
  for (const [fromDays, expectedDays] of [[200, 180], [10, 10]]) {
    const res = await request({ range: '180d', skipCount: 'true', from: new Date(NOW - fromDays * DAY).toISOString(), to });
    assert.equal(res.statusCode, 200);
    assert.equal(queries.at(-1).createdAt.$gte.getTime(), NOW - expectedDays * DAY);
    assert.equal(queries.at(-1).createdAt.$lte.toISOString(), to);
  }
});
