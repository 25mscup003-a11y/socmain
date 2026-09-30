/**
 * MongoDB Connection Handler
 * Manages connection to MongoDB for IPS firewall persistence
 * 
 * Two databases:
 *   soc4_ips  — IPS-specific data (blocks, threats, logs, whitelist)
 *   main DB   — Company records (read-only, from main SOC4 backend)
 */

const { MongoClient } = require('mongodb');
const logger = require('../utils/logger');

let db = null;        // soc4_ips database
let mainDb = null;    // main SOC4 database (for reading companies)
let client = null;

/**
 * Connect to MongoDB
 * @returns {Promise<object>} Database connection
 */
async function connectDB() {
  if (db) {
    logger.info('MongoDB already connected');
    return db;
  }

  try {
    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
      throw new Error('MONGO_URI environment variable not set');
    }

    logger.info('Attempting MongoDB connection (this may take 10-30 seconds)...');

    client = new MongoClient(mongoUri, {
      maxPoolSize: 10,
      minPoolSize: 2,
      serverSelectionTimeoutMS: 30000,  // 30 seconds
      socketTimeoutMS: 45000,            // 45 seconds
      connectTimeoutMS: 30000,           // 30 seconds
      retryWrites: true,
    });

    await client.connect();
    db = client.db('soc4_ips');
    await logger.setDatabase(db);

    // Also get the main SOC4 DB (same cluster, different database)
    // The main backend uses the default DB from the connection string
    const mainDbName = process.env.MAIN_DB_NAME || 'test';
    mainDb = client.db(mainDbName);

    logger.info(`✅ Connected to MongoDB (soc4_ips + ${mainDbName} databases)`);

    // Create indexes for performance
    await ensureIndexes();

    return db;
  } catch (err) {
    logger.error(`❌ MongoDB connection failed: ${err.message}`);
    logger.warn('⚠️  Continuing in in-memory only mode (blocks will not persist across restarts)');
    // Don't exit - allow server to run in memory-only mode
    return null;
  }
}

/**
 * Create indexes for firewall collection
 */
async function ensureIndexes() {
  try {
    /* firewall_blocks */
    const blocks = db.collection('firewall_blocks');
    await blocks.createIndex({ blockKey: 1 }, { unique: true, sparse: true });
    await blocks.createIndex({ ip: 1 });
    await blocks.createIndex({ domain: 1 });
    await blocks.createIndex({ application: 1 });
    await blocks.createIndex({ ts: -1 });
    await blocks.createIndex({ status: 1 });

    /* ips_logs */
    const logs = db.collection('ips_logs');
    await logs.createIndex({ ts: -1 });
    await logs.createIndex({ level: 1 });

    /* threat_intel */
    const threats = db.collection('threat_intel');
    await threats.createIndex({ ip: 1 });
    await threats.createIndex({ domain: 1 });
    await threats.createIndex({ attackType: 1 });
    await threats.createIndex({ ts: -1 });

    /* attack_events */
    const attacks = db.collection('attack_events');
    await attacks.createIndex({ ip: 1 });
    await attacks.createIndex({ attackType: 1 });
    await attacks.createIndex({ ts: -1 });

    /* whitelist */
    const wl = db.collection('whitelist');
    await wl.createIndex({ value: 1 }, { unique: true });

    logger.info('✅ Database indexes verified/created');
  } catch (err) {
    if (err.codeName === 'DuplicateKey') {
      logger.debug('Indexes already exist');
    } else {
      logger.warn(`Index creation warning: ${err.message}`);
    }
  }
}

/**
 * Get database connection
 * @returns {object|null} MongoDB database instance (null if not connected)
 */
function getDB() {
  return db;
}

/**
 * Get the main SOC4 database (for reading companies)
 */
function getMainDB() {
  return mainDb;
}

/**
 * Check if MongoDB is connected
 */
function isConnected() {
  return db !== null;
}

/**
 * Disconnect from MongoDB
 */
async function disconnectDB() {
  if (client) {
    try {
      logger.setDatabase(null);
      await client.close();
      db = null;
      client = null;
      logger.info('Disconnected from MongoDB');
    } catch (err) {
      logger.error(`Error disconnecting: ${err.message}`);
    }
  }
}

module.exports = {
  connectDB,
  getDB,
  getMainDB,
  isConnected,
  disconnectDB,
};
