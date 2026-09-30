const mongoose = require('mongoose');

/**
 * Pricing — Super Admin controlled dynamic pricing.
 * Two completely separate flat price sets:
 *   newUser_*  — applied on first-time checkout
 *   renewal_*  — applied on renewal / upgrade for existing companies
 *
 * Flat fields (no nested subdocs) = clean Mongoose change tracking.
 */
const PricingSchema = new mongoose.Schema({
  // ── New User Pricing ──────────────────────────────────────────────────────
  newUser_pricePerSystemMonthly: { type: Number, default: 200 },
  newUser_pricePerSystemYearly:  { type: Number, default: 2000 },
  newUser_pricePerPhoneMonthly:  { type: Number, default: 200 },
  newUser_pricePerPhoneYearly:   { type: Number, default: 2000 },
  newUser_pricePerServerMonthly: { type: Number, default: 500 },
  newUser_pricePerServerYearly:  { type: Number, default: 5000 },

  // ── Renewal Pricing (existing companies) ─────────────────────────────────
  renewal_pricePerSystemMonthly: { type: Number, default: 200 },
  renewal_pricePerSystemYearly:  { type: Number, default: 2000 },
  renewal_pricePerPhoneMonthly:  { type: Number, default: 200 },
  renewal_pricePerPhoneYearly:   { type: Number, default: 2000 },
  renewal_pricePerServerMonthly: { type: Number, default: 500 },
  renewal_pricePerServerYearly:  { type: Number, default: 5000 },

  // ── Legacy flat fields (backward compat — kept equal to newUser) ─────────
  pricePerSystemMonthly: { type: Number, default: 200 },
  pricePerSystemYearly:  { type: Number, default: 2000 },
  pricePerPhoneMonthly:  { type: Number, default: 200 },
  pricePerPhoneYearly:   { type: Number, default: 2000 },
  pricePerServerMonthly: { type: Number, default: 500 },
  pricePerServerYearly:  { type: Number, default: 5000 },

  // Metadata
  updatedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updateNote:  { type: String, default: '' },
  isActive:    { type: Boolean, default: true },

  // History (last 20 changes)
  history: [{
    userType:              String,   // 'new-user' | 'renewal-existing'
    pricePerSystemMonthly: Number,
    pricePerSystemYearly:  Number,
    pricePerPhoneMonthly:  Number,
    pricePerPhoneYearly:   Number,
    pricePerServerMonthly: Number,
    pricePerServerYearly:  Number,
    changedAt: { type: Date, default: Date.now },
    changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    note:      String,
  }],
}, { timestamps: true });

module.exports = mongoose.model('Pricing', PricingSchema);
