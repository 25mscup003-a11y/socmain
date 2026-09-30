require('dotenv').config();
const { migrateClickHouse, closeClickHouse } = require('../src/services/clickhouse.service');

async function run() {
  const result = await migrateClickHouse();
  console.log(JSON.stringify({ migration: 'clickhouse-alerts-v2', ...result }));
  await closeClickHouse();
}

if (require.main === module) run().catch(error => {
  console.error(error.message);
  process.exit(1);
});
