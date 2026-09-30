/**
 * Logger Utility
 * Writes runtime output to the console and, once connected, MongoDB.
 * No server-side log files or directories are created.
 */

const COLLECTION = 'ips_logs';
const MAX_PENDING_LOGS = 500;
let database = null;
let pendingLogs = [];

function persist(doc) {
  if (!database) {
    pendingLogs.push(doc);
    if (pendingLogs.length > MAX_PENDING_LOGS) pendingLogs.shift();
    return Promise.resolve(null);
  }

  return database.collection(COLLECTION).insertOne(doc).catch((err) => {
    console.error(`Failed to write log to MongoDB: ${err.message}`);
    return null;
  });
}

function log(level, msg, metadata = {}) {
  const ts = new Date();
  const message = String(msg);
  const line = `[${ts.toISOString()}] [${level}] ${message}`;

  console.log(line);

  const doc = { ts, level, message };
  if (metadata && typeof metadata === 'object') Object.assign(doc, metadata);
  return persist(doc);
}

async function setDatabase(nextDatabase) {
  database = nextDatabase || null;
  if (!database || pendingLogs.length === 0) return;

  const batch = pendingLogs;
  pendingLogs = [];
  try {
    await database.collection(COLLECTION).insertMany(batch, { ordered: false });
  } catch (err) {
    console.error(`Failed to flush logs to MongoDB: ${err.message}`);
  }
}

const logger = {
  setDatabase,
  info: (msg, metadata) => log('INFO', msg, metadata),
  warn: (msg, metadata) => log('WARN', msg, metadata),
  error: (msg, metadata) => log('ERROR', msg, metadata),
  debug: (msg, metadata) => log('DEBUG', msg, metadata),
  block: (msg, metadata) => log('BLOCK', msg, metadata),
  unblock: (msg, metadata) => log('UNBLOCK', msg, metadata),
};

module.exports = logger;
