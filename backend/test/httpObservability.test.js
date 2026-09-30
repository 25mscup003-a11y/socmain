const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeRoute } = require('../src/observability/httpObservability');

test('metrics route labels remove object ids and large numeric ids', () => {
  assert.equal(normalizeRoute({ path: '/api/company/507f1f77bcf86cd799439011/events/123456' }), '/api/company/:id/events/:n');
});

test('registered express route is preferred over raw cardinality', () => {
  assert.equal(normalizeRoute({ baseUrl: '/api/alerts', route: { path: '/:id' } }), '/api/alerts/:id');
});
