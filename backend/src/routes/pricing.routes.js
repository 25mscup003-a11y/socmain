/**
 * pricing.routes.js — Super Admin controlled pricing management
 *
 * Two independent price sets (flat fields, no nested subdocs):
 *   new-user         → newUser_* fields  (first-time checkout)
 *   renewal-existing → renewal_* fields  (existing company renewal/upgrade)
 *
 * GET  /api/pricing               — Both price sets (public)
 * PUT  /api/pricing               — Update ONE set based on note (super admin)
 * GET  /api/pricing/history       — Change history (super admin)
 * DELETE /api/pricing/history/:i  — Delete one history entry
 */
const router  = require('express').Router();
const Pricing = require('../models/Pricing.model');
const { authenticate, requireSuperAdmin } = require('../middleware/auth.middleware');

// ── Helper: get or create the single active Pricing doc ───────────────────────
async function getOrCreate() {
  let p = await Pricing.findOne({ isActive: true }).sort({ updatedAt: -1 });
  if (!p) {
    p = await Pricing.create({
	      newUser_pricePerSystemMonthly: 200, newUser_pricePerSystemYearly: 2000,
	      newUser_pricePerPhoneMonthly: 200, newUser_pricePerPhoneYearly: 2000,
	      newUser_pricePerServerMonthly: 500, newUser_pricePerServerYearly: 5000,
	      renewal_pricePerSystemMonthly: 200, renewal_pricePerSystemYearly: 2000,
	      renewal_pricePerPhoneMonthly: 200, renewal_pricePerPhoneYearly: 2000,
	      renewal_pricePerServerMonthly: 500, renewal_pricePerServerYearly: 5000,
	      pricePerSystemMonthly: 200, pricePerSystemYearly: 2000,
	      pricePerPhoneMonthly: 200, pricePerPhoneYearly: 2000,
	      pricePerServerMonthly: 500, pricePerServerYearly: 5000,
    });
  }
  // Back-fill new flat fields if this is a legacy document (migration)
  let dirty = false;
  if (!p.newUser_pricePerSystemMonthly) {
	    p.newUser_pricePerSystemMonthly = p.pricePerSystemMonthly || 200;
	    p.newUser_pricePerSystemYearly  = p.pricePerSystemYearly  || 2000;
	    p.newUser_pricePerPhoneMonthly  = p.pricePerPhoneMonthly || p.pricePerSystemMonthly || 200;
	    p.newUser_pricePerPhoneYearly   = p.pricePerPhoneYearly || p.pricePerSystemYearly || 2000;
	    p.newUser_pricePerServerMonthly = p.pricePerServerMonthly || 500;
    p.newUser_pricePerServerYearly  = p.pricePerServerYearly  || 5000;
    dirty = true;
  }
  if (!p.renewal_pricePerSystemMonthly) {
	    p.renewal_pricePerSystemMonthly = p.pricePerSystemMonthly || 200;
	    p.renewal_pricePerSystemYearly  = p.pricePerSystemYearly  || 2000;
	    p.renewal_pricePerPhoneMonthly  = p.pricePerPhoneMonthly || p.pricePerSystemMonthly || 200;
	    p.renewal_pricePerPhoneYearly   = p.pricePerPhoneYearly || p.pricePerSystemYearly || 2000;
	    p.renewal_pricePerServerMonthly = p.pricePerServerMonthly || 500;
    p.renewal_pricePerServerYearly  = p.pricePerServerYearly  || 5000;
    dirty = true;
	  }
	  if (!p.newUser_pricePerPhoneMonthly) {
	    p.newUser_pricePerPhoneMonthly = p.pricePerPhoneMonthly || p.newUser_pricePerSystemMonthly || 200;
	    p.newUser_pricePerPhoneYearly  = p.pricePerPhoneYearly || p.newUser_pricePerSystemYearly || 2000;
	    dirty = true;
	  }
	  if (!p.renewal_pricePerPhoneMonthly) {
	    p.renewal_pricePerPhoneMonthly = p.pricePerPhoneMonthly || p.renewal_pricePerSystemMonthly || 200;
	    p.renewal_pricePerPhoneYearly  = p.pricePerPhoneYearly || p.renewal_pricePerSystemYearly || 2000;
	    dirty = true;
	  }
  if (dirty) await p.save();
  return p;
}

/** Shape the response object consistently */
function buildResponse(p) {
  return {
    // Per-type sets (what the UI and payment routes use)
    newUser: {
	      pricePerSystemMonthly: p.newUser_pricePerSystemMonthly,
	      pricePerSystemYearly:  p.newUser_pricePerSystemYearly,
	      pricePerPhoneMonthly:  p.newUser_pricePerPhoneMonthly,
	      pricePerPhoneYearly:   p.newUser_pricePerPhoneYearly,
	      pricePerServerMonthly: p.newUser_pricePerServerMonthly,
      pricePerServerYearly:  p.newUser_pricePerServerYearly,
    },
    renewal: {
	      pricePerSystemMonthly: p.renewal_pricePerSystemMonthly,
	      pricePerSystemYearly:  p.renewal_pricePerSystemYearly,
	      pricePerPhoneMonthly:  p.renewal_pricePerPhoneMonthly,
	      pricePerPhoneYearly:   p.renewal_pricePerPhoneYearly,
	      pricePerServerMonthly: p.renewal_pricePerServerMonthly,
      pricePerServerYearly:  p.renewal_pricePerServerYearly,
    },
    // Legacy flat fields (for /payment/pricing backward compat)
	    pricePerSystemMonthly: p.pricePerSystemMonthly,
	    pricePerSystemYearly:  p.pricePerSystemYearly,
	    pricePerPhoneMonthly:  p.pricePerPhoneMonthly,
	    pricePerPhoneYearly:   p.pricePerPhoneYearly,
	    pricePerServerMonthly: p.pricePerServerMonthly,
    pricePerServerYearly:  p.pricePerServerYearly,
    updatedAt: p.updatedAt,
  };
}

// ── GET /api/pricing ──────────────────────────────────────────────────────────
router.get('/', async (_req, res) => {
  try {
    const p = await getOrCreate();
    res.json(buildResponse(p));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── PUT /api/pricing — update ONE price set ───────────────────────────────────
router.put('/', authenticate, requireSuperAdmin, async (req, res) => {
  const {
	    pricePerSystemMonthly,
	    pricePerSystemYearly,
	    pricePerPhoneMonthly,
	    pricePerPhoneYearly,
	    pricePerServerMonthly,
    pricePerServerYearly,
    note,   // 'new-user' | 'renewal-existing'  ← REQUIRED
  } = req.body;

  // Validate note
  if (!note || !['new-user', 'renewal-existing'].includes(note)) {
    return res.status(400).json({ message: 'note must be "new-user" or "renewal-existing"' });
  }

  // Validate all 4 values
	  const vals = { pricePerSystemMonthly, pricePerSystemYearly, pricePerPhoneMonthly, pricePerPhoneYearly, pricePerServerMonthly, pricePerServerYearly };
  for (const [key, val] of Object.entries(vals)) {
    if (val === undefined || val === '' || isNaN(Number(val)) || Number(val) < 0) {
      return res.status(400).json({ message: `${key} must be a valid non-negative number` });
    }
  }

  try {
    const p = await getOrCreate();
    const isNewUser = note === 'new-user';
    const prefix    = isNewUser ? 'newUser' : 'renewal';

    // ── Snapshot OLD values into history ──────────────────────────────────
    const snap = {
      userType:              note,
	      pricePerSystemMonthly: p[`${prefix}_pricePerSystemMonthly`],
	      pricePerSystemYearly:  p[`${prefix}_pricePerSystemYearly`],
	      pricePerPhoneMonthly:  p[`${prefix}_pricePerPhoneMonthly`],
	      pricePerPhoneYearly:   p[`${prefix}_pricePerPhoneYearly`],
	      pricePerServerMonthly: p[`${prefix}_pricePerServerMonthly`],
      pricePerServerYearly:  p[`${prefix}_pricePerServerYearly`],
      changedAt: new Date(),
      changedBy: req.user.id,
      note,
    };
    if (!p.history) p.history = [];
    p.history.unshift(snap);
    if (p.history.length > 20) p.history = p.history.slice(0, 20);

    // ── Apply new values to the selected set ONLY ─────────────────────────
	    p[`${prefix}_pricePerSystemMonthly`] = Number(pricePerSystemMonthly);
	    p[`${prefix}_pricePerSystemYearly`]  = Number(pricePerSystemYearly);
	    p[`${prefix}_pricePerPhoneMonthly`]  = Number(pricePerPhoneMonthly);
	    p[`${prefix}_pricePerPhoneYearly`]   = Number(pricePerPhoneYearly);
	    p[`${prefix}_pricePerServerMonthly`] = Number(pricePerServerMonthly);
    p[`${prefix}_pricePerServerYearly`]  = Number(pricePerServerYearly);

    // Keep legacy flat fields = newUser prices (backward compat)
    if (isNewUser) {
	      p.pricePerSystemMonthly = Number(pricePerSystemMonthly);
	      p.pricePerSystemYearly  = Number(pricePerSystemYearly);
	      p.pricePerPhoneMonthly  = Number(pricePerPhoneMonthly);
	      p.pricePerPhoneYearly   = Number(pricePerPhoneYearly);
	      p.pricePerServerMonthly = Number(pricePerServerMonthly);
      p.pricePerServerYearly  = Number(pricePerServerYearly);
    }

    p.updatedBy  = req.user.id;
    p.updateNote = note;
    p.markModified('history');
    await p.save();

	    console.log(`[pricing] ✅ ${note} pricing updated — sys/mo: ${pricePerSystemMonthly}, phone/mo: ${pricePerPhoneMonthly}, srv/mo: ${pricePerServerMonthly}`);
    res.json({ success: true, note, pricing: buildResponse(p) });

  } catch (err) {
    console.error('[pricing] ❌ Update error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/pricing/history ──────────────────────────────────────────────────
router.get('/history', authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const p = await Pricing.findOne({ isActive: true })
      .populate('history.changedBy', 'name email')
      .sort({ updatedAt: -1 });
    if (!p) return res.json({ history: [] });
    res.json({ history: p.history || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── DELETE /api/pricing/history/:index ───────────────────────────────────────
router.delete('/history/:index', authenticate, requireSuperAdmin, async (req, res) => {
  const idx = parseInt(req.params.index);
  try {
    const p = await Pricing.findOne({ isActive: true }).sort({ updatedAt: -1 });
    if (!p || !p.history) return res.status(404).json({ message: 'No history found' });
    if (idx < 0 || idx >= p.history.length) return res.status(400).json({ message: 'Invalid index' });
    p.history.splice(idx, 1);
    p.markModified('history');
    await p.save();
    res.json({ success: true, history: p.history });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
