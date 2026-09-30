const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeRetention, applyRetention, DAY_MS } = require('../src/utils/retentionPolicy');

test('retention never expires before the hot window', () => {
  assert.deepEqual(normalizeRetention({ hotDays: 30, totalDays: 7 }), {
    hotDays: 30, totalDays: 30, archiveEnabled: false, legalHold: false,
  });
});

test('expiry is deterministic from event time', () => {
  const start = new Date('2026-01-01T00:00:00.000Z');
  const result = applyRetention({}, { hotDays: 1, totalDays: 5 }, start);
  assert.equal(result.expiresAt.getTime(), start.getTime() + 5 * DAY_MS);
});

test('legal hold removes automatic expiry', () => {
  assert.equal(applyRetention({}, { legalHold: true }).expiresAt, null);
});
