const mongoose = require('mongoose');

// Never retain application queries in memory while MongoDB is unavailable.
// Polling endpoints can otherwise enqueue many copies of the same expensive
// query until Mongoose's buffer timeout expires, causing a CPU/memory spike.
mongoose.set('bufferCommands', false);

let connectionEventsInstalled = false;

function installConnectionEvents(connection = mongoose.connection, logger = console) {
  if (connectionEventsInstalled || !connection?.on) return;
  connectionEventsInstalled = true;
  connection.on('disconnected', () => {
    logger.warn('⚠️  MongoDB disconnected; waiting for driver reconnection');
  });
  connection.on('reconnected', () => {
    logger.log('✅ MongoDB reconnected');
  });
  connection.on('error', (err) => {
    logger.error('⚠️  MongoDB connection warning:', err.message);
  });
}

function retryDelay(attempt, baseMs, maxMs) {
  return Math.min(maxMs, baseMs * (2 ** Math.max(0, attempt - 1)));
}

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Connect without terminating the process on a transient Mongo outage.
 * maxAttempts=0 means retry until Mongo returns (the default for API/workers).
 * Tests and one-shot commands can supply a finite maxAttempts.
 */
async function connectDB(options = {}) {
  const mongoUri = options.uri
    || process.env.MONGO_URI
    || process.env.MONGODB_URI
    || process.env.MONGO_URI_LOCAL
    || process.env.MONGO_URI_CLOUD;
  if (!mongoUri) throw new Error('MongoDB URI is missing. Set MONGO_URI in backend/.env.');

  const logger = options.logger || console;
  const connect = options.connect || ((uri, connectOptions) => mongoose.connect(uri, connectOptions));
  const sleep = options.sleep || wait;
  const maxAttempts = options.maxAttempts ?? Math.max(0, Number(process.env.MONGO_CONNECT_MAX_ATTEMPTS || 0));
  const baseDelayMs = options.baseDelayMs ?? Math.max(100, Number(process.env.MONGO_RETRY_BASE_MS || 1000));
  const maxDelayMs = options.maxDelayMs ?? Math.max(baseDelayMs, Number(process.env.MONGO_RETRY_MAX_MS || 10000));
  const connectOptions = options.connectOptions || {
    serverSelectionTimeoutMS: Number(process.env.MONGO_SERVER_SELECTION_TIMEOUT_MS || 15000),
    socketTimeoutMS: Number(process.env.MONGO_SOCKET_TIMEOUT_MS || 45000),
    connectTimeoutMS: Number(process.env.MONGO_CONNECT_TIMEOUT_MS || 15000),
    heartbeatFrequencyMS: Number(process.env.MONGO_HEARTBEAT_FREQUENCY_MS || 10000),
    maxPoolSize: Number(process.env.MONGO_MAX_POOL_SIZE) || 100,
    // Do not continuously maintain a socket while the database is offline.
    minPoolSize: Math.max(0, Number(process.env.MONGO_MIN_POOL_SIZE) || 0),
    retryWrites: true,
  };

  if (options.installEvents !== false) installConnectionEvents(mongoose.connection, logger);

  let attempt = 0;
  for (;;) {
    attempt += 1;
    try {
      const result = await connect(mongoUri, connectOptions);
      logger.log(`✅ MongoDB connected${attempt > 1 ? ` after ${attempt} attempts` : ''}`);
      return result;
    } catch (err) {
      const exhausted = maxAttempts > 0 && attempt >= maxAttempts;
      if (exhausted) {
        logger.error(`❌ MongoDB connection failed after ${attempt} attempts:`, err.message);
        throw err;
      }
      const delayMs = retryDelay(attempt, baseDelayMs, maxDelayMs);
      logger.warn(`[MongoDB] Connection attempt ${attempt} failed: ${err.message}; retrying in ${delayMs}ms`);
      await sleep(delayMs);
    }
  }
}

module.exports = connectDB;
module.exports.installConnectionEvents = installConnectionEvents;
module.exports.retryDelay = retryDelay;
