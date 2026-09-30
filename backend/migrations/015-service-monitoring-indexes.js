require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  await mongoose.connect(process.env.MONGO_URI);
  try {
    const alerts = mongoose.connection.collection('alerts');
    const existing = await alerts.indexes();
    const desired = [
      [{ companyId: 1, serviceName: 1, createdAt: -1 }, { name: 'company_service_time' }],
      [{ companyId: 1, serviceEventType: 1, createdAt: -1 }, { name: 'company_service_event_time' }],
      [{ companyId: 1, inventoryType: 1, ruleId: 1, systemId: 1, createdAt: -1 }, { name: 'company_service_inventory_time' }],
    ];
    let available = Math.max(0, 64 - existing.length);
    let created = 0;
    for (const [key, options] of desired) {
      if (existing.some(index => JSON.stringify(index.key) === JSON.stringify(key))) continue;
      if (available === 0) break;
      await alerts.createIndex(key, options);
      available -= 1;
      created += 1;
    }
    if (created === 0 && existing.length >= 64) {
      console.warn('Alert index limit reached; Service Monitoring will reuse existing company/capability/time and company/rule/time indexes.');
    }
  } finally {
    await mongoose.disconnect();
  }
}

run().then(() => {
  console.log('Service monitoring indexes are ready.');
}).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
