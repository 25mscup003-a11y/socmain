const { ensureTenantIndexes } = require('../src/db/indexes');
let mockCollection;
jest.mock('../src/db/mongodb', () => ({ getDB: () => ({ collection: () => mockCollection }), getMainDB: () => null }));
jest.mock('../src/utils/logger', () => ({ warn: jest.fn(), info: jest.fn() }));
const mongo = require('../src/services/mongoService');

test('tenant indexes replace only legacy global uniqueness after the new index succeeds', async () => {
  const operations = [];
  const db = { collection: name => ({
    createIndex: async key => operations.push(['create', name, key]),
    listIndexes: () => ({ toArray: async () => [
      { name: '_id_', key: { _id: 1 }, unique: true },
      { name: 'legacy', key: { [name === 'whitelist' ? 'value' : 'blockKey']: 1 }, unique: true },
      { name: 'tenant', key: { company: 1, value: 1 }, unique: true },
    ] }),
    dropIndex: async index => operations.push(['drop', name, index]),
  }) };
  await ensureTenantIndexes(db);
  expect(operations).toEqual([
    ['create', 'firewall_blocks', { blockKey: 1, company: 1 }], ['drop', 'firewall_blocks', 'legacy'],
    ['create', 'whitelist', { company: 1, value: 1 }], ['drop', 'whitelist', 'legacy'],
  ]);
});

test('existing index remains intact if creating the replacement fails', async () => {
  const dropIndex = jest.fn();
  const db = { collection: () => ({ createIndex: async () => { throw new Error('conflict'); }, dropIndex }) };
  await expect(ensureTenantIndexes(db)).rejects.toThrow('conflict');
  expect(dropIndex).not.toHaveBeenCalled();
});

test('whitelist storage errors are propagated rather than acknowledged as success', async () => {
  mockCollection = { updateOne: jest.fn().mockRejectedValue(new Error('offline')) };
  await expect(mongo.addToWhitelist('203.0.113.1', 'ip', '', 'tenant-a')).rejects.toMatchObject({ statusCode: 503 });
});

test('failed whitelist lookup prevents a block from bypassing the whitelist', async () => {
  mockCollection = { find: () => ({ toArray: async () => { throw new Error('offline'); } }) };
  await expect(mongo.isWhitelisted('203.0.113.1', 'tenant-a')).rejects.toMatchObject({ statusCode: 503 });
});

test('delegated and log-only records do not claim confirmed SOC blocking', () => {
  for (const method of ['endpoint-agent', 'log-only']) {
    const alert = mongo._test._socIpsAlert({ company: '507f1f77bcf86cd799439011', block: { ip: '203.0.113.1', method } });
    expect(alert.blocked).toBe(false);
    expect(alert.containmentStatus).toBe('pending');
  }
});
