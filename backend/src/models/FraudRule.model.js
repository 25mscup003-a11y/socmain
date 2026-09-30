/**
 * FraudRule Model
 * Dynamic, database-editable rules evaluated by the Rules Engine.
 * Supports IF/THEN logic for ALLOW, BLOCK, CHALLENGE, MANUAL_REVIEW.
 */
const mongoose = require('mongoose');

const FraudRuleSchema = new mongoose.Schema({
  name:        { type: String, required: true, trim: true },
  description: { type: String, default: '' },

  // Condition field + operator + value
  conditionField: {
    type: String,
    required: true,
    enum: [
      'riskScore', 'isVpn', 'isTor', 'isProxy', 'isBot',
      'country', 'asn', 'ipAddress',
      'isNewDevice', 'isNewCountry', 'multipleAccounts',
      'multipleDevices', 'velocity', 'impossibleTravel',
      'decision',
    ],
  },
  conditionOperator: {
    type: String,
    required: true,
    enum: ['gt', 'lt', 'gte', 'lte', 'eq', 'neq', 'is_true', 'is_false', 'in', 'not_in'],
  },
  conditionValue: { type: mongoose.Schema.Types.Mixed }, // number, string, array, boolean

  // Action to take when rule matches
  action: {
    type: String,
    required: true,
    enum: ['ALLOW', 'BLOCK', 'CHALLENGE', 'MANUAL_REVIEW', 'ALERT', 'HIGH_RISK', 'REQUIRE_MFA'],
  },

  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  priority: { type: Number, default: 50 }, // Higher = evaluated first

  isActive: { type: Boolean, default: true, index: true },
  isBuiltIn:{ type: Boolean, default: false }, // built-in rules cannot be deleted via API

  // Stats
  triggerCount:   { type: Number, default: 0 },
  lastTriggeredAt:{ type: Date },

  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

FraudRuleSchema.index({ isActive: 1, priority: -1 });

module.exports = mongoose.model('FraudRule', FraudRuleSchema);
