require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../config/db');
const { runArchiveCycle } = require('../services/archive.service');

let stopping = false;
async function run() {
  await connectDB();
  const interval = Math.max(60_000, Number(process.env.ARCHIVE_INTERVAL_MS || 3_600_000));
  while (!stopping) {
    const result = await runArchiveCycle();
    console.log(JSON.stringify({ level: 'info', event: 'archive_cycle', ...result }));
    await new Promise(resolve => {
      const timer = setTimeout(resolve, interval);
      run.timer = timer;
    });
  }
}

async function shutdown(signal) {
  stopping = true;
  if (run.timer) clearTimeout(run.timer);
  console.log(JSON.stringify({ level: 'info', event: 'archive_shutdown', signal }));
  await mongoose.disconnect().catch(() => {});
  process.exit(0);
}

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
if (require.main === module) run().catch(error => {
  console.error(JSON.stringify({ level: 'error', event: 'archive_failed', message: error.message }));
  process.exit(1);
});

module.exports = { run };
