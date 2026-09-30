require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const collection = mongoose.connection.db.collection('uebaprofilelockevents');
  const sameKey = (left, right) => JSON.stringify(left) === JSON.stringify(right);
  const existing = await collection.indexes();
  let created = 0;
  async function ensure(key, options) {
    const found = existing.find(index => sameKey(index.key, key));
    if (found) {
      if (options.unique && found.unique !== true) throw new Error(`Existing ${found.name} index is not unique`);
      console.log(`Reusing uebaprofilelockevents.${found.name}`);
      return;
    }
    await collection.createIndex(key, options);
    created += 1;
  }
  await ensure({ alertId: 1 }, { unique: true, name: 'alertId_unique' });
  await ensure({ companyId: 1, createdAt: -1 }, { name: 'companyId_createdAt' });
  await ensure({ companyId: 1, status: 1, createdAt: -1 }, { name: 'companyId_status_createdAt' });
  await ensure({ companyId: 1, departmentId: 1, createdAt: -1 }, { name: 'companyId_departmentId_createdAt' });
  await ensure({ companyId: 1, sourceType: 1, createdAt: -1 }, { name: 'companyId_sourceType_createdAt' });
  await ensure({ 'responseActions.responseId': 1 }, { name: 'responseActions_responseId' });
  console.log(`UEBA profile lock indexes are ready: ${created} created`);
  await mongoose.disconnect();
}

if (require.main === module) run().catch(error => {
  console.error(error);
  process.exit(1);
});

module.exports = run;
