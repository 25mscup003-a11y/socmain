/**
 * Decision Engine Service
 * Resolves rules engine output + telemetry risk score into a final
 * decision: ALLOW | BLOCK | CHALLENGE | MANUAL_REVIEW
 * Also determines secondary actions: lock account, block IP/device, create alert.
 */
const stytchConfig = require('../config/stytch.config');

// ── Compute risk level from numeric score ─────────────────────────────────────
function getRiskLevel(score) {
  const t = stytchConfig.thresholds;
  if (score >= t.critical) return 'critical';
  if (score >= t.high)     return 'high';
  if (score >= t.medium)   return 'medium';
  return 'low';
}

// ── Map rules engine action to final decision ─────────────────────────────────
function mapActionToDecision(action, riskScore) {
  switch (action) {
    case 'BLOCK':         return 'BLOCK';
    case 'CHALLENGE':     return 'CHALLENGE';
    case 'MANUAL_REVIEW': return 'MANUAL_REVIEW';
    case 'REQUIRE_MFA':   return 'CHALLENGE';
    case 'HIGH_RISK':
      return riskScore >= 85 ? 'BLOCK' : 'CHALLENGE';
    case 'ALERT':
      return 'ALLOW'; // Alert only, don't interrupt
    default:              return 'ALLOW';
  }
}

/**
 * decide
 * @param {Object} telemetry    - Normalized Stytch telemetry
 * @param {Object} rulesResult  - Output from rulesEngine.evaluateRules()
 * @param {Object} context      - Extra context (isNewDevice, etc.)
 * @returns {Object}            - Full DecisionResult
 */
function decide(telemetry, rulesResult, context = {}) {
  const { riskScore = 0, isVpn, isTor, isProxy, isBot } = telemetry;
  const { highestAction = 'ALLOW', matchedRules = [], highestSeverity = 'low' } = rulesResult;

  const riskLevel = getRiskLevel(riskScore);

  // Map action → decision
  let decision = mapActionToDecision(highestAction, riskScore);

  // Score-based override (even without matching rules, very high score → challenge)
  if (decision === 'ALLOW' && riskScore >= stytchConfig.thresholds.high) {
    decision = 'CHALLENGE';
  }

  // ── Secondary action flags ──────────────────────────────────────────────────
  const requiresMFA       = decision === 'CHALLENGE' || highestAction === 'REQUIRE_MFA';
  const shouldLockAccount = decision === 'BLOCK' && (riskScore >= 90 || context.bruteForceDetected);
  const shouldBlockIP     = isTor || (decision === 'BLOCK' && riskScore >= 95);
  const shouldBlockDevice = decision === 'BLOCK' && (isTor || riskScore >= 90);
  const shouldCreateAlert =
    decision !== 'ALLOW' ||
    riskLevel === 'critical' ||
    isTor ||
    isBot ||
    highestAction === 'ALERT' ||
    matchedRules.length > 0;

  return {
    decision,
    riskScore,
    riskLevel,
    requiresMFA,
    shouldLockAccount,
    shouldBlockIP,
    shouldBlockDevice,
    shouldCreateAlert,
    matchedRules,
    highestSeverity,
    summary: buildSummary(decision, riskScore, riskLevel, matchedRules, telemetry),
  };
}

// ── Human-readable summary for logs and alerts ────────────────────────────────
function buildSummary(decision, score, level, rules, telemetry) {
  const signals = [];
  if (telemetry.isVpn)   signals.push('VPN');
  if (telemetry.isTor)   signals.push('TOR');
  if (telemetry.isProxy) signals.push('Proxy');
  if (telemetry.isBot)   signals.push('Bot');
  const sigStr = signals.length ? ` (${signals.join(', ')})` : '';
  return `Decision: ${decision} | Score: ${score} (${level})${sigStr} | Rules: ${rules.join(', ') || 'none'}`;
}

module.exports = { decide, getRiskLevel };
