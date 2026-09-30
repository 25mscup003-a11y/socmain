/**
 * Rules Engine Service
 * Evaluates all active FraudRules from MongoDB against incoming telemetry.
 * Returns matched rules and the highest-priority action to take.
 */
const FraudRule = require('../models/FraudRule.model');

// ── Operator evaluation ───────────────────────────────────────────────────────
function evaluateOperator(operator, fieldValue, ruleValue) {
  switch (operator) {
    case 'gt':       return Number(fieldValue) > Number(ruleValue);
    case 'lt':       return Number(fieldValue) < Number(ruleValue);
    case 'gte':      return Number(fieldValue) >= Number(ruleValue);
    case 'lte':      return Number(fieldValue) <= Number(ruleValue);
    case 'eq':       return String(fieldValue) === String(ruleValue);
    case 'neq':      return String(fieldValue) !== String(ruleValue);
    case 'is_true':  return Boolean(fieldValue) === true;
    case 'is_false': return Boolean(fieldValue) === false;
    case 'in':       return Array.isArray(ruleValue) && ruleValue.includes(fieldValue);
    case 'not_in':   return Array.isArray(ruleValue) && !ruleValue.includes(fieldValue);
    default:         return false;
  }
}

// ── Map rule condition field to telemetry property ────────────────────────────
function resolveTelemetryField(field, telemetry, context) {
  const map = {
    riskScore:        telemetry.riskScore,
    isVpn:            telemetry.isVpn,
    isTor:            telemetry.isTor,
    isProxy:          telemetry.isProxy,
    isBot:            telemetry.isBot,
    country:          telemetry.country,
    asn:              telemetry.asn,
    ipAddress:        telemetry.ip,
    isNewDevice:      context.isNewDevice,
    isNewCountry:     context.isNewCountry,
    multipleAccounts: context.multipleAccounts,
    multipleDevices:  context.multipleDevices,
    velocity:         context.recentLoginCount,
    impossibleTravel: context.impossibleTravel,
  };
  return map[field];
}

// ── Action priority ranking (higher = more severe) ────────────────────────────
const ACTION_PRIORITY = {
  ALLOW:         0,
  ALERT:         1,
  REQUIRE_MFA:   2,
  HIGH_RISK:     3,
  CHALLENGE:     4,
  MANUAL_REVIEW: 5,
  BLOCK:         6,
};

/**
 * evaluateRules
 * @param {Object} telemetry - Normalized Stytch telemetry payload
 * @param {Object} context   - Contextual signals (isNewDevice, velocity, etc.)
 * @returns {Promise<{matchedRules, highestAction, severity, ruleIds}>}
 */
async function evaluateRules(telemetry, context = {}) {
  const rules = await FraudRule.find({ isActive: true }).sort({ priority: -1 }).lean();

  const matchedRules = [];
  let highestAction = 'ALLOW';
  let highestPriority = ACTION_PRIORITY['ALLOW'];
  let highestSeverity = 'low';
  const matchedRuleIds = [];

  for (const rule of rules) {
    const fieldValue = resolveTelemetryField(rule.conditionField, telemetry, context);
    const isMatch = evaluateOperator(rule.conditionOperator, fieldValue, rule.conditionValue);

    if (isMatch) {
      matchedRules.push(rule.name);
      matchedRuleIds.push(rule._id);

      // Track highest severity action
      const actionPriority = ACTION_PRIORITY[rule.action] ?? 0;
      if (actionPriority > highestPriority) {
        highestPriority = actionPriority;
        highestAction = rule.action;
        highestSeverity = rule.severity || 'medium';
      }

      // Fire-and-forget: update rule trigger stats
      FraudRule.findByIdAndUpdate(rule._id, {
        $inc: { triggerCount: 1 },
        $set: { lastTriggeredAt: new Date() },
      }).catch(() => {});
    }
  }

  return {
    matchedRules,
    matchedRuleIds,
    highestAction,
    highestSeverity,
  };
}

module.exports = { evaluateRules };
