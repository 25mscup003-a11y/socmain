const test = require('node:test');
const assert = require('node:assert/strict');

const apiMonitoring = require('../src/routes/api-monitoring.routes');
const {
  normalizeAlert, normalizeWaf, summarize, safeTelemetry, categoryMatches,
} = apiMonitoring._private;

test('normalizes agent API request telemetry without inventing fields', () => {
  const event = normalizeAlert({
    _id: '507f1f77bcf86cd799439011', capabilityId: 20, createdAt: new Date('2026-08-30T10:00:00Z'),
    hostname: 'api-01', srcip: '198.51.100.4', httpMethod: 'post', requestPath: '/v1/orders',
    statusCode: 201, responseTime: 42, requestSize: 120, responseSize: 340, severity: 'low',
  });
  assert.equal(event.method, 'POST');
  assert.equal(event.url, '/v1/orders');
  assert.equal(event.statusCode, 201);
  assert.equal(event.responseTimeMs, 42);
  assert.equal(event.hostname, 'api-01');
  assert.equal(event.wafProvider, undefined);
});

test('normalizes WAF events and calculates risk from real detection context', () => {
  const event = normalizeWaf({
    _id: '507f1f77bcf86cd799439012', company: '507f1f77bcf86cd799439013', ts: new Date(),
    provider: 'F5 ASM', ip: '203.0.113.8', method: 'GET', requestPath: '/api/users?id=1',
    attackType: 'SQL Injection', ruleId: 'WAF_SQLI', severity: 'critical', blocked: true,
  });
  assert.equal(event.capabilityId, 20);
  assert.equal(event.wafProvider, 'F5 ASM');
  assert.equal(event.blocked, true);
  assert.equal(event.riskScore, 100);
  assert.equal(categoryMatches(event, 'attacks'), true);
});

test('redacts secrets recursively before forensic API responses', () => {
  assert.deepEqual(safeTelemetry({ Authorization: 'Bearer abc.def', body: { password: 'secret', name: 'safe' } }), {
    Authorization: '[REDACTED]', body: { password: '[REDACTED]', name: 'safe' },
  });
});

test('summarizes only supplied live API events', () => {
  const summary = summarize([
    { severity: 'low', url: '/health', method: 'GET', statusCode: 200, responseTimeMs: 10, sourceIp: '10.0.0.1' },
    { severity: 'critical', url: '/login', method: 'POST', statusCode: 403, responseTimeMs: 30, sourceIp: '10.0.0.2', blocked: true },
  ], 2, [{ isOnline: true }]);
  assert.equal(summary.totalApiCalls, 2);
  assert.equal(summary.successfulCalls, 1);
  assert.equal(summary.failedCalls, 1);
  assert.equal(summary.wafBlockedRequests, 1);
  assert.equal(summary.averageResponseTimeMs, 20);
  assert.equal(summary.onlineSystems, 1);
});
