require('dotenv').config({ path: process.env.DOTENV_CONFIG_PATH || require('path').resolve(__dirname, '../.env') });
const { MongoClient } = require('mongodb');

async function ensureBrokerStorageIndex(db) {
  const alerts = db.collection('alerts');
  const indexes = await alerts.indexes().catch(error => {
    if (error.code === 26) return [];
    throw error;
  });
  const existing = indexes.find(index => {
    const keys = Object.entries(index.key);
    return keys.length === 2 && keys[0][0] === 'companyId' && keys[0][1] === 1
      && keys[1][0] === 'eventId' && keys[1][1] === 1 && !index.partialFilterExpression;
  });
  if (existing) return { status: 'ready', index: existing.name, unique: Boolean(existing.unique), created: false };
  // Additive only: existing legacy duplicates and operational indexes remain.
  const name = await alerts.createIndex({ companyId: 1, eventId: 1 }, { name: 'company_event_id_lookup', sparse: true });
  return { status: 'ready', index: name, unique: false, created: true };
}

async function provision() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  const client = new MongoClient(process.env.MONGO_URI, { serverSelectionTimeoutMS: 10000 });
  try {
    await client.connect();
    console.log(JSON.stringify(await ensureBrokerStorageIndex(client.db())));
  } finally { await client.close(); }
}

if (require.main === module) provision().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});

module.exports = { ensureBrokerStorageIndex };
