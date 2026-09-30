const test = require('node:test');
const assert = require('node:assert/strict');
const { expandFimCategoryScope, fimCapabilityFilter } = require('../src/utils/fimQuery');

test('FIM capability includes file evidence promoted to another category', () => {
  const base = { companyId: 'company-a', eventCategory: 'file', createdAt: { $gte: new Date(0) } };
  const expanded = expandFimCategoryScope(base, 'file', 2);
  assert.equal(expanded.eventCategory, undefined);
  assert.equal(expanded.companyId, 'company-a');
  assert.deepEqual(expanded.createdAt, base.createdAt);
  assert.equal(base.eventCategory, 'file');
});

test('ordinary category queries remain category scoped', () => {
  assert.equal(expandFimCategoryScope({ eventCategory: 'file' }, 'file', 7).eventCategory, 'file');
  assert.equal(expandFimCategoryScope({ eventCategory: 'network' }, 'network', 2).eventCategory, 'network');
});

test('FIM queries use the indexed stable capability id', () => {
  assert.deepEqual(fimCapabilityFilter(), { capabilityId: 2 });
});
