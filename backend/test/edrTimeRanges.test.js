const test = require('node:test');
const assert = require('node:assert/strict');
const Alert = require('../src/models/Alert.model');
const System = require('../src/models/System.model');
const dashboard = require('../src/routes/dashboard.routes');
const network = require('../src/routes/network.routes');
const { LOG_RANGE_HOURS } = require('../src/utils/edrTimeRange');

const companyId = '6a8efb532c942f67c29534cc';
const departmentId = '6a8efb532c942f67c29534cd';
const systemId = '6a8efb532c942f67c29534ce';
const end = new Date('2026-01-01T12:00:00Z');
const handler = path => dashboard.stack.find(layer => layer.route?.path === path).route.stack.at(-1).handle;
function response() {
  return { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
}
function fixture(t) {
  const calls = {};
  t.mock.method(Alert, 'find', query => {
    calls.query = query;
    return {
      hint(value) { calls.hint = value; return this; },
      sort(order) { calls.sort = order; return this; },
      skip(value) { calls.skip = value; return this; },
      limit(value) { calls.limit = value; return this; },
      select() { return this; }, populate() { return this; }, maxTimeMS() { return this; },
      lean: async () => calls.rows || [],
    };
  });
  t.mock.method(Alert, 'countDocuments', query => {
    calls.countQuery = query;
    const result = Promise.resolve(650);
    result.maxTimeMS = () => result;
    return result;
  });
  return calls;
}
function dates(value, key, found = []) {
  if (!value || typeof value !== 'object') return found;
  for (const [name, item] of Object.entries(value)) {
    if (name === key && item instanceof Date) found.push(item);
    else dates(item, key, found);
  }
  return found;
}

test('all six log ranges use an ordered index and bounded pages without counting the full history', async t => {
  const calls = fixture(t);
  for (const [range, hours] of Object.entries(LOG_RANGE_HOURS)) {
    const res = response();
    await handler('/capabilities/:capabilityId/logs')({
      user: { companyId, role: 'company_admin' }, params: { capabilityId: '1' },
      query: { range, windowEnd: end.toISOString(), page: '2', limit: '1000', companyId: 'foreign-company' },
    }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.total, null);
    assert.equal(res.body.hasMore, false);
    assert.equal(res.body.limit, 500);
    assert.equal(calls.skip, 500);
    assert.equal(calls.limit, 501);
    assert.deepEqual(calls.sort, { createdAt: -1 });
    assert.deepEqual(calls.hint, { companyId: 1, createdAt: -1 });
    assert.equal(calls.countQuery, undefined);
    assert.equal(dates(calls.query, '$gte')[0].getTime(), end.getTime() - hours * 3600000);
    assert.equal(dates(calls.query, '$lte')[0].getTime(), end.getTime());
    assert.match(JSON.stringify(calls.query), new RegExp(companyId));
    assert.doesNotMatch(JSON.stringify(calls.query), /foreign-company/);
  }
});

test('log pagination derives hasMore from one lookahead row and never returns that extra row', async t => {
  const calls = fixture(t);
  t.mock.method(Alert, 'countDocuments', () => { throw new Error('Historical count must not block page loading'); });
  for (const count of [0, 2, 3]) {
    calls.rows = Array.from({ length: count }, (_, index) => ({ _id: `event-${index}` }));
    const res = response();
    await handler('/capabilities/:capabilityId/logs')({
      user: { companyId, role: 'company_admin' }, params: { capabilityId: '28' }, query: { range: '180d', limit: '2' },
    }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.alerts.length, Math.min(count, 2));
    assert.equal(res.body.hasMore, count > 2);
    assert.equal(calls.limit, 3);
    assert.deepEqual(calls.hint, { companyId: 1, source: 1, createdAt: -1 });
    assert.equal(calls.query.$and[0].source, 'lolbins');
  }
});

test('log queries preserve department-admin and validated endpoint scope', async t => {
  const calls = fixture(t);
  t.mock.method(System, 'findOne', query => {
    assert.equal(String(query.companyId), companyId);
    assert.equal(String(query.departmentId), departmentId);
    return { select() { return this; }, lean: async () => ({ _id: systemId }) };
  });
  const res = response();
  await handler('/capabilities/:capabilityId/logs')({
    user: { companyId, role: 'department_admin', departmentId }, params: { capabilityId: '2' },
    query: { range: '180d', systemId, departmentId: 'foreign-department' },
  }, res);
  assert.equal(res.statusCode, 200);
  const serialized = JSON.stringify(calls.query);
  assert.match(serialized, new RegExp(departmentId));
  assert.match(serialized, new RegExp(systemId));
  assert.doesNotMatch(serialized, /foreign-department/);
});

test('invalid log ranges and dates are rejected before database reads', async t => {
  let reads = 0;
  t.mock.method(Alert, 'find', () => { reads++; throw new Error('Unexpected database query'); });
  for (const query of [{ range: '181d' }, { range: '__proto__' }, { windowEnd: 'invalid' }, { page: 'Infinity' }]) {
    const res = response();
    await handler('/capabilities/:capabilityId/logs')({ user: { companyId }, params: { capabilityId: '1' }, query }, res);
    assert.equal(res.statusCode, 400);
  }
  assert.equal(reads, 0);
});

test('the default log window stays at 24 hours and memory metrics retain tenant scope', async t => {
  const calls = fixture(t);
  const res = response();
  await handler('/capabilities/:capabilityId/logs')({
    user: { companyId, role: 'department_admin', departmentId }, params: { capabilityId: '5' }, query: {},
  }, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.range, '24h');
  assert.equal(new Date(res.body.until) - new Date(res.body.since), 86400000);
  const metricScope = calls.query.$and[0].$or[1];
  assert.equal(String(metricScope.companyId), companyId);
  assert.equal(String(metricScope.departmentId), departmentId);
  assert.match(JSON.stringify(metricScope), /memory.metric/);
  assert.equal(metricScope.createdAt.$gte.getTime(), new Date(res.body.since).getTime());
});

test('six-month process and shared reports query the full 180 days', async t => {
  const calls = fixture(t);
  for (const [path, capabilityId] of [['/process-activity/report', 1], ['/capability-report/:capabilityId', 9], ['/capability-report/:capabilityId', 28]]) {
    const res = response();
    await handler(path)({ user: { companyId, role: 'company_admin' }, params: { capabilityId }, query: { period: '180days', category: 'all' } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.period, '180days');
    assert.equal(new Date(res.body.until) - new Date(res.body.since), 180 * 86400000);
    assert.equal(dates(calls.query, '$lte')[0] - dates(calls.query, '$gte')[0], 180 * 86400000);
    assert.deepEqual(calls.query, calls.countQuery);
  }
});

test('network logs support 180 days without widening the default overview window', () => {
  const now = new Date('2026-10-09T12:00:00Z');
  const windowEnd = new Date(now.getTime() - 120000).toISOString();
  const logs = network.networkWindow({ range: '180d', windowEnd, to: windowEnd }, now);
  assert.equal(logs.hours, 4320);
  assert.equal(logs.to - logs.from, 180 * 86400000);
  assert.equal(network.networkWindow({ hours: 4320 }, now).hours, 24);
  assert.throws(() => network.networkWindow({ range: '200d' }, now), /Invalid log time range/);
});
