const test = require('node:test');
const assert = require('node:assert/strict');
const { getPeriodEnd } = require('../src/utils/billingPeriod');

test('monthly and yearly billing starts from the new purchase date', () => {
  const purchase = new Date('2026-10-06T09:30:00Z');
  assert.equal(getPeriodEnd('monthly', purchase).toISOString(), '2026-11-06T09:30:00.000Z');
  assert.equal(getPeriodEnd('yearly', purchase).toISOString(), '2027-10-06T09:30:00.000Z');
  assert.equal(purchase.toISOString(), '2026-10-06T09:30:00.000Z');
});

test('month-end and leap-day purchases stay in the next billing month', () => {
  for (const [cycle, start, expected] of [
    ['monthly', '2026-01-31', '2026-02-28'],
    ['monthly', '2028-01-31', '2028-02-29'],
    ['monthly', '2026-12-31', '2027-01-31'],
    ['yearly', '2028-02-29', '2029-02-28'],
  ]) assert.equal(getPeriodEnd(cycle, new Date(start)).toISOString().slice(0, 10), expected);
});
