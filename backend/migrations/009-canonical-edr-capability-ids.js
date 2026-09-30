require('dotenv').config();
const mongoose = require('mongoose');

const DIRECT_MAPPING = Object.freeze({
  1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 10, 11: 11,
  13: 12, 14: 13, 16: 14, 18: 15, 19: 16, 20: 17, 21: 18, 22: 19,
  23: 20, 24: 21, 26: 22, 27: 23, 28: 24, 30: 25, 31: 26, 32: 27,
  33: 28, 36: 29, 37: 30, 38: 31,
});

function mappingBranches(input) {
  return Object.entries(DIRECT_MAPPING).map(([legacy, canonical]) => ({
    case: { $eq: [input, Number(legacy)] }, then: canonical,
  }));
}

function mappedValue(input) {
  return { $switch: { branches: mappingBranches(input), default: null } };
}

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const alerts = mongoose.connection.collection('alerts');
  const filter = {
    capabilitySchemaVersion: { $ne: 2 },
    $or: [{ capabilityId: { $exists: true } }, { capabilityIds: { $exists: true, $ne: [] } }],
  };
  const result = await alerts.updateMany(filter, [
    {
      $set: {
        capabilityId: mappedValue({ $convert: { input: '$capabilityId', to: 'int', onError: null, onNull: null } }),
        capabilityIds: {
          $setUnion: [
            {
              $filter: {
                input: {
                  $map: {
                    input: { $ifNull: ['$capabilityIds', []] },
                    as: 'legacyId',
                    in: mappedValue({ $convert: { input: '$$legacyId', to: 'int', onError: null, onNull: null } }),
                  },
                },
                as: 'canonicalId',
                cond: { $and: [{ $ne: ['$$canonicalId', null] }, { $gte: ['$$canonicalId', 1] }, { $lte: ['$$canonicalId', 31] }] },
              },
            },
            [],
          ],
        },
        capabilitySchemaVersion: 2,
      },
    },
  ]);
  console.log(JSON.stringify({ matched: result.matchedCount, modified: result.modifiedCount, schemaVersion: 2 }));
  await mongoose.disconnect();
}

run().catch(async error => {
  console.error(error);
  await mongoose.disconnect().catch(() => {});
  process.exitCode = 1;
});
