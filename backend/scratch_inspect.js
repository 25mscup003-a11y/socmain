const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/test';

async function inspect() {
  await mongoose.connect(mongoUri);
  console.log('Connected to DB');
  const db = mongoose.connection.db;

  const targetRules = [
    'NET_DNS_SUMMARY',
    'NET_THREAT_INTEL_SUMMARY',
    'NET_SCAN',
    'ZEEK_dns',
    'IDS_PORT_SCAN'
  ];

  for (const ruleId of targetRules) {
    const sample = await db.collection('alerts').findOne({ ruleId });
    if (sample) {
      console.log(`\n--- Sample for ruleId [${ruleId}] ---`);
      console.log(JSON.stringify({
        ruleId: sample.ruleId,
        description: sample.description,
        type: sample.type,
        category: sample.category,
        srcip: sample.srcip,
        destPort: sample.destPort,
        port: sample.port,
        protocol: sample.protocol,
        direction: sample.direction,
        rawEvent: sample.rawEvent
      }, null, 2));
    } else {
      console.log(`\nNo sample found for ruleId [${ruleId}]`);
    }
  }

  await mongoose.disconnect();
}
inspect().catch(console.error);
