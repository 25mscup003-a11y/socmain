const test = require('node:test');
const assert = require('node:assert/strict');
const {
  boundedInteger,
  escapeRegex,
  enforceBatchLimit,
} = require('../src/utils/requestLimits');

test('pagination values are bounded', () => {
  assert.equal(boundedInteger('999999', { defaultValue: 50, max: 200 }), 200);
  assert.equal(boundedInteger('-5', { defaultValue: 50, max: 200 }), 1);
  assert.equal(boundedInteger('bad', { defaultValue: 50, max: 200 }), 50);
});

test('user search text is escaped before becoming a regular expression', () => {
  assert.equal(escapeRegex('a.*(b)+'), 'a\\.\\*\\(b\\)\\+');
});

test('oversized batches are rejected instead of silently truncated', () => {
  assert.deepEqual(enforceBatchLimit([1, 2], 2), { ok: true });
  const rejected = enforceBatchLimit([1, 2, 3], 2, 'logs');
  assert.equal(rejected.ok, false);
  assert.equal(rejected.status, 413);
});
