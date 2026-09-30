#!/usr/bin/env node

/**
 * IPS Webhook Server — Entry Point
 *
 * Port:   IPS_WEBHOOK_PORT (default 5050)
 * Socket: Same port via Socket.IO
 *
 * Emits real-time events to all dashboards:
 *   ips:block    — when an IP/domain is blocked
 *   ips:unblock  — when unblocked
 *   ips:threat   — when a new threat is detected
 *   ips:log      — new server log entry
 */

// Single .env — ipsserver/back-end/.env (sab settings yahan hain)
require('dotenv').config();

const http     = require('http');
const { Server: SocketIOServer } = require('socket.io');
const { requestHandler } = require('./src/app');
const logger   = require('./src/utils/logger');
const { connectDB, disconnectDB, isConnected } = require('./src/db/mongodb');
const { loadPersistedBlocks, sweepExpiredBlocks } = require('./src/services/firewallService');
const mongoService = require('./src/services/mongoService');

const PORT = parseInt(process.env.IPS_WEBHOOK_PORT || '5050', 10);

let httpServer;
let io;

/**
 * Broadcast an IPS event to all connected dashboard clients.
 * Call this from webhook controller whenever state changes.
 */
function emitIPSEvent(event, data) {
  if (!io) return;
  try {
    const eventName = `ips:${event}`;
    io.emit(eventName, data);
    if (data && (data.company || data.companyId)) {
      const room = `company:${data.company || data.companyId}`;
      io.to(room).emit(eventName, data);
    }
    if (['isolation', 'recovery', 'alert'].includes(event)) {
      io.to('superadmin').emit(eventName, data);
    }
  } catch (err) {
    logger.warn(`[Socket] Emit error: ${err.message}`);
  }
}

// Make emitter globally available to controllers
global.emitIPSEvent = emitIPSEvent;

// Expose IPS Server reference for cross-service use (e.g. simulateAttack controller)
// The main IPS engine runs in the backend process, not here.
// We store the emitIPSEvent so simulation results can be broadcast.
global._ipsServerEmit = emitIPSEvent;

async function startServer() {
  try {
    // ── MongoDB ──
    if (process.env.MONGO_URI) {
      logger.info('Attempting MongoDB connection...');
      await connectDB();

      if (isConnected()) {
        await mongoService.ensureAllIndexes();
        logger.info('Loading persisted firewall blocks...');
        await loadPersistedBlocks();
        setInterval(async () => {
          await sweepExpiredBlocks();
        }, 5 * 60 * 1000).unref?.();
        setInterval(async () => {
          logger.info('[Scheduler] Running daily MongoDB cleanup...');
          await mongoService.cleanup();
        }, 24 * 60 * 60 * 1000);
      }
    } else {
      logger.warn('⚠️  MONGO_URI not configured — running in memory-only mode');
    }

    // ── HTTP Server + Socket.IO ──
    httpServer = http.createServer(requestHandler);

    io = new SocketIOServer(httpServer, {
      cors: {
        origin: '*',
        methods: ['GET', 'POST'],
      },
    });

    io.on('connection', (socket) => {
      logger.info(`[Socket] Dashboard connected: ${socket.id}`);

      socket.on('join:company', (companyId) => {
        if (companyId) {
          socket.join(`company:${companyId}`);
          logger.info(`[Socket] ${socket.id} joined company:${companyId}`);
        }
      });

      socket.on('join:superadmin', () => {
        socket.join('superadmin');
        logger.info(`[Socket] ${socket.id} joined superadmin room`);
      });

      socket.on('disconnect', () => {
        logger.info(`[Socket] Dashboard disconnected: ${socket.id}`);
      });
    });

    // Listen on the HTTP server (not appServer) so Socket.IO shares the port
    httpServer.listen(PORT, () => {
      const dbStatus = isConnected() ? '✅ MongoDB (soc4_ips + main DB)' : '📝 In-Memory only';
      logger.info(`✅ IPS Webhook Server + Socket.IO running on port ${PORT}`);
      logger.info(`   Database: ${dbStatus}`);
    });
  } catch (err) {
    logger.error(`Failed to start server: ${err.message}`);
    process.exit(1);
  }
}

startServer();

async function gracefulShutdown(signal) {
  logger.info(`${signal} received — shutting down`);
  if (httpServer) {
    httpServer.close(async () => {
      await disconnectDB();
      logger.info('Server closed');
      process.exit(0);
    });
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT',  () => gracefulShutdown('SIGINT'));
// restart trigger

