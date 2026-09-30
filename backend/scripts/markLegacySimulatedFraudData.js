require('dotenv').config();
const mongoose = require('mongoose');
const Device = require('../src/models/Device.model');

async function main() {
  await mongoose.connect(process.env.MONGO_URI);
  const result = await Device.updateMany(
    {
      simulatedData: { $ne: true },
      deviceFingerprint: /^df_/,
      visitorId: /^visitor_/,
    },
    { $set: { simulatedData: true } },
  );
  console.log(JSON.stringify({
    matched: result.matchedCount,
    markedSimulated: result.modifiedCount,
  }));
  await mongoose.disconnect();
}

main().catch(async error => {
  console.error(error);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
