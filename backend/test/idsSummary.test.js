const test = require('node:test');
const assert = require('node:assert/strict');

const {
  IDS_SUMMARY_INDEX_HINT,
  loadIdsAlertRollup,
  normalizeIdsAlertRollup,
} = require('../src/services/idsSummary.service');

function aggregateStub(result) {
  const state = { pipeline: null, hint: null, options: null };
  const query = {
    hint(value) { state.hint = value; return this; },
    option(value) { state.options = value; return this; },
    async exec() {
      if (result instanceof Error) throw result;
      return result;
    },
  };
  return {
    state,
    Alert: {
      aggregate(pipeline) { state.pipeline = pipeline; return query; },
    },
  };
}

test('IDS summary returns the live rollup and uses the dedicated compound index', async () => {
  const { Alert, state } = aggregateStub([{
    total: 41,
    high: 6,
    critical: 0,
    blocked: 2,
    activeAgents: ['linux1', '', null, 'linux2'],
  }]);
  const result = await loadIdsAlertRollup(Alert, { companyId: 'company', createdAt: { $gte: new Date(0) } });

  assert.deepEqual(result, { total: 41, blocked: 2, critical: 0, high: 6, activeSystems: 2 });
  assert.deepEqual(state.hint, IDS_SUMMARY_INDEX_HINT);
  assert.ok(state.options.maxTimeMS >= 5000);
  assert.equal(state.pipeline[0].$match.companyId, 'company');
});

test('IDS summary reports a genuine empty window as numeric zeroes', () => {
  assert.deepEqual(normalizeIdsAlertRollup(), {
    total: 0,
    blocked: 0,
    critical: 0,
    high: 0,
    activeSystems: 0,
  });
});

test('IDS summary query failures propagate instead of becoming false zero counts', async () => {
  const timeout = new Error('operation exceeded time limit');
  timeout.code = 50;
  const { Alert } = aggregateStub(timeout);

  await assert.rejects(
    loadIdsAlertRollup(Alert, { companyId: 'company' }),
    error => error === timeout,
  );
});
