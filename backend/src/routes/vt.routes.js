/**
 * VirusTotal proxy — frontend calls this instead of VT directly
 * so the API key never leaves the server.
 *
 * GET  /api/vt/hash/:hash   — file hash scan
 * GET  /api/vt/ip/:ip       — IP reputation
 * GET  /api/vt/alert/:id    — scan file hash from a specific alert
 */
const router = require('express').Router();
const { authenticate } = require('../middleware/auth.middleware');
const vt = require('../services/virustotal.service');
const Alert = require('../models/Alert.model');

router.use(authenticate);

// GET /api/vt/hash/:hash
router.get('/hash/:hash', async (req, res) => {
  try {
    if (!vt.isEnabled()) return res.json({ score: 0, verdict: 'disabled', engines: [] });
    const result = await vt.scanHash(req.params.hash);
    res.json(result || { score: 0, verdict: 'not_found', engines: [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/vt/ip/:ip
router.get('/ip/:ip', async (req, res) => {
  try {
    if (!vt.isEnabled()) return res.json({ score: 0, verdict: 'disabled', engines: [] });
    const result = await vt.scanIp(req.params.ip);
    res.json(result || { score: 0, verdict: 'private_or_not_found', engines: [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/vt/alert/:alertId — scan the file hash from a specific alert
router.get('/alert/:alertId', async (req, res) => {
  try {
    const alert = await Alert.findOne({
      _id: req.params.alertId,
      companyId: req.user.companyId,
    }).select('fileHash srcip eventCategory vtScore vtDetections vtTotal vtEngines');

    if (!alert) return res.status(404).json({ error: 'Alert not found' });

    // Return cached VT result if already scanned
    if (alert.vtScore != null) {
      return res.json({
        score: alert.vtScore,
        detections: alert.vtDetections,
        total: alert.vtTotal,
        ratio: `${alert.vtDetections}/${alert.vtTotal}`,
        engines: alert.vtEngines || [],
      });
    }

    if (!vt.isEnabled()) return res.json({ score: 0, verdict: 'disabled', engines: [] });

    let result = null;
    if (alert.fileHash) result = await vt.scanHash(alert.fileHash);
    else if (alert.srcip) result = await vt.scanIp(alert.srcip);

    if (result) {
      // Save to alert for future use
      await Alert.findByIdAndUpdate(alert._id, {
        vtScore: result.score,
        vtDetections: result.detections,
        vtTotal: result.total,
        vtEngines: result.engines,
        vtScannedAt: result.scannedAt,
      });
    }

    res.json(result || { score: 0, verdict: 'no_hash', engines: [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
