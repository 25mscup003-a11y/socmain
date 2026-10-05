// Replace legacy global uniqueness only after tenant uniqueness is in place.
// No records are removed by this migration.
async function ensureTenantIndexes(db) {
  for (const [name, field, key] of [
    ['firewall_blocks', 'blockKey', { blockKey: 1, company: 1 }],
    ['whitelist', 'value', { company: 1, value: 1 }],
  ]) {
    const collection = db.collection(name);
    await collection.createIndex(key, { unique: true, sparse: true });
    const indexes = await collection.listIndexes().toArray();
    for (const index of indexes) {
      if (index.unique && Object.keys(index.key).length === 1 && index.key[field]) {
        await collection.dropIndex(index.name);
      }
    }
  }
}

module.exports = { ensureTenantIndexes };
