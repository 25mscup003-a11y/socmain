'use strict';

require('dotenv').config();
const mongoose = require('mongoose');
const Alert = require('../src/models/Alert.model');
const { ingestNetworkTelemetry } = require('../src/services/networkMonitoring.service');

async function main() {
  await mongoose.connect(process.env.MONGO_URI);
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const cursor = Alert.find({
    ruleId: 'NET_CONNECTION_SUMMARY',
    createdAt: { $gte: since },
    'rawEvent.raw.connections.0': { $exists: true },
  }).sort({ createdAt: 1 }).cursor();

  let summaries = 0;
  let materialized = 0;
  for await (const alert of cursor) {
    const result = await ingestNetworkTelemetry(alert, null);
    summaries += 1;
    materialized += Number(result.upserted || 0);
  }
  console.log(JSON.stringify({ summaries, materialized, since }));
  await mongoose.disconnect();
}

main().catch(async error => {
  console.error(error.message);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
