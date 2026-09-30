require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const Alert = require('../src/models/Alert.model');

const INDEX_NAME = 'company_event_fingerprint_unique';

async function fixAlertFingerprintIndex() {
  await connectDB();
  const indexes = await Alert.collection.indexes();
  const existing = indexes.find(index => index.name === INDEX_NAME);
  const alreadyPartial = existing?.unique === true
    && existing.partialFilterExpression?.eventFingerprint?.$type === 'string';

  if (!alreadyPartial && existing) {
    await Alert.collection.dropIndex(INDEX_NAME);
  }
  if (!alreadyPartial) {
    await Alert.collection.createIndex(
      { companyId: 1, eventFingerprint: 1 },
      {
        name: INDEX_NAME,
        unique: true,
        partialFilterExpression: { eventFingerprint: { $type: 'string' } },
      },
    );
  }

  return { changed: !alreadyPartial, index: INDEX_NAME };
}

if (require.main === module) {
  fixAlertFingerprintIndex()
    .then(result => console.log(JSON.stringify(result)))
    .catch(error => {
      console.error(error);
      process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
}

module.exports = { fixAlertFingerprintIndex };
