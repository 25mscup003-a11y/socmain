const test = require('node:test');
const assert = require('node:assert/strict');
const { configuredLevel, isLevelEnabled, accessLogsEnabled } = require('../src/observability/runtimeLogging');

test('development logging defaults to warnings without access logs', () => {
  const env = { NODE_ENV: 'development' };
  assert.equal(configuredLevel(env), 'warn');
  assert.equal(isLevelEnabled('info', env), false);
  assert.equal(isLevelEnabled('warn', env), true);
  assert.equal(accessLogsEnabled(env), false);
});

test('production defaults to structured info access logs', () => {
  const env = { NODE_ENV: 'production' };
  assert.equal(configuredLevel(env), 'info');
  assert.equal(accessLogsEnabled(env), true);
});

test('explicit logging settings override environment defaults', () => {
  assert.equal(isLevelEnabled('info', { NODE_ENV: 'development', LOG_LEVEL: 'info' }), true);
  assert.equal(accessLogsEnabled({ NODE_ENV: 'production', HTTP_ACCESS_LOGS: 'false' }), false);
});
