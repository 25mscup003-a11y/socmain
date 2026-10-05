import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizePartnerCompanies } from '../src/utils/partnerCompanySummary.js';

const now = Date.parse('2026-10-05T00:00:00Z');
const first = { status: 'active', totalAgents: 10, activeAgents: 8, inactiveAgents: 2, revenue: 12000, pendingRevenue: 500, plan: { isActive: true, expiresAt: '2026-10-10' } };
const second = { status: 'suspended', totalAgents: 4, activeAgents: 0, inactiveAgents: 4, revenue: 3000, pendingRevenue: 1000, plan: { isActive: false, expiresAt: '2026-10-12' } };

test('each partner summary totals only the companies supplied by its scoped company list', () => {
  const partnerOne = summarizePartnerCompanies([first, second], now);
  assert.deepEqual(partnerOne, {
    companies: 2, activeCompanies: 1, inactiveCompanies: 1,
    totalAgents: 14, activeAgents: 8, inactiveAgents: 6,
    activePlans: 1, expiringPlans: 1, totalCollection: 15000, pendingRevenue: 1500,
  });
  const partnerTwo = summarizePartnerCompanies([{ ...first, totalAgents: 30, activeAgents: 30, inactiveAgents: 0, revenue: 50000, pendingRevenue: 0 }], now);
  assert.equal(partnerTwo.companies, 1);
  assert.equal(partnerTwo.totalAgents, 30);
  assert.equal(partnerTwo.totalCollection, 50000);
});

test('empty company lists produce zero totals', () => {
  assert.ok(Object.values(summarizePartnerCompanies([], now)).every(value => value === 0));
});

test('missing or invalid company metrics remain unavailable rather than understating totals', () => {
  const summary = summarizePartnerCompanies([first, { ...second, totalAgents: undefined, revenue: 'invalid', pendingRevenue: null }], now);
  assert.equal(summary.totalAgents, null);
  assert.equal(summary.totalCollection, null);
  assert.equal(summary.pendingRevenue, null);
  assert.equal(summary.activeAgents, 8);
});

test('expiring plans only include active plans due within the next fifteen days', () => {
  const companies = ['2026-10-04', '2026-10-05', '2026-10-20', '2026-10-21', 'invalid'].map(expiresAt => ({ ...first, plan: { isActive: true, expiresAt } }));
  assert.equal(summarizePartnerCompanies(companies, now).expiringPlans, 2);
});
