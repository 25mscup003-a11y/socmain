const { emitCompanyPartnerUpdate } = require('../utils/partnerRealtime');
/**
 * Heartbeat Sweeper Service
 * Periodically checks all active systems and marks them offline
 * if their lastSeen exceeds the threshold (3 missed heartbeats = 3 minutes).
 *
 * This ensures that uninstalled/crashed agents are detected even when
 * no uninstall signal is received.
 */
const System = require('../models/System.model');

const SWEEP_INTERVAL_MS = 2 * 60 * 1000;  // Run every 2 minutes
const OFFLINE_THRESHOLD_MS = 3 * 60 * 1000; // 3 minutes = 3 missed 60s heartbeats

let sweepTimer = null;

async function sweep(io) {
  try {
    const threshold = new Date(Date.now() - OFFLINE_THRESHOLD_MS);

    // Find active systems with lastSeen older than threshold
    const stale = await System.find({
      status: 'active',
      lastSeen: { $lt: threshold },
    }).select('_id name hostname companyId lastSeen').lean();

    if (stale.length === 0) return;

    // Batch update to 'disconnected'
    const ids = stale.map(s => s._id);
    await System.updateMany(
      { _id: { $in: ids } },
      { $set: { status: 'disconnected' } }
    );

    for (const sys of stale) {
      const ago = Math.round((Date.now() - new Date(sys.lastSeen).getTime()) / 1000);
      console.log(
        `[HeartbeatSweeper] ⚠️  ${sys.name || sys.hostname || sys._id} → DISCONNECTED (last seen ${ago}s ago)`
      );

      // Notify dashboard via Socket.IO
      if (io && sys.companyId) {
        io.to(`company:${sys.companyId}`).emit('system:status_changed', {
          systemId: sys._id,
          name: sys.name,
          status: 'disconnected',
          lastSeen: sys.lastSeen,
        });
      }
    }

    for (const companyId of new Set(stale.map(system => String(system.companyId || '')).filter(Boolean))) {
      void emitCompanyPartnerUpdate(io, companyId, 'agent_status');
    }

    console.log(`[HeartbeatSweeper] Marked ${stale.length} system(s) as disconnected`);
  } catch (err) {
    console.error('[HeartbeatSweeper] Error:', err.message);
  }
}

function startSweeper(io) {
  if (sweepTimer) clearInterval(sweepTimer);

  // Initial sweep after 30s startup grace
  setTimeout(() => sweep(io), 30 * 1000);

  sweepTimer = setInterval(() => sweep(io), SWEEP_INTERVAL_MS);
  console.log(`[HeartbeatSweeper] Started (every ${SWEEP_INTERVAL_MS / 1000}s, threshold ${OFFLINE_THRESHOLD_MS / 1000}s)`);
}

function stopSweeper() {
  if (sweepTimer) {
    clearInterval(sweepTimer);
    sweepTimer = null;
  }
}

module.exports = { startSweeper, stopSweeper };
