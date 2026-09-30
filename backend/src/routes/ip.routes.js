const router = require('express').Router();
const { authenticate } = require('../middleware/auth.middleware');
const ipEnrichmentService = require('../services/ipEnrichmentService');
const net = require('net');

// GET /api/ip/:ip — Enrich one IP
router.get('/:ip', authenticate, async (req, res) => {
  try {
    const ip = req.params.ip;
    if (!net.isIP(ip)) {
      return res.status(400).json({ success: false, error: 'Invalid IP address format' });
    }

    const data = await ipEnrichmentService.enrichIp(ip);
    res.json({
      success: true,
      data
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// POST /api/ip/bulk — Enrich bulk IPs
router.post('/bulk', authenticate, async (req, res) => {
  try {
    const { ips } = req.body;
    if (!ips || !Array.isArray(ips)) {
      return res.status(400).json({ success: false, error: 'Request body must contain an array of ips' });
    }

    const results = await Promise.all(
      ips.map(async (ip) => {
        if (!net.isIP(ip)) {
          return { ip, success: false, error: 'Invalid IP address format' };
        }
        try {
          const data = await ipEnrichmentService.enrichIp(ip);
          return { ip, success: true, data };
        } catch (err) {
          return { ip, success: false, error: err.message };
        }
      })
    );

    res.json({
      success: true,
      results
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;
