/**
 * securityScore.js — Centralized Security Score Engine
 *
 * ══════════════════════════════════════════════════════════════════════════════
 * WHY THIS APPROACH?
 * ══════════════════════════════════════════════════════════════════════════════
 *
 * Old formula:  score = 100 − (count × weight)
 *   Problem:    Linear deductions explode with volume.
 *               133 critical × 40 = 5,320 alone → score = −5,220 → clamped to 0.
 *               16,408 medium × 10 = 164,080 → absurd.
 *               ANY non-trivial data yields 0/100.
 *
 * New formula:  Logarithmic scaling with per-severity caps.
 *
 *   deduction(severity) = min( cap, weight × log₂(1 + count) )
 *
 *   Severity    Weight   Cap (max deduction)
 *   ─────────   ──────   ───────────────────
 *   critical     6        30   (most impactful, but capped so score doesn't vanish)
 *   high         4        20
 *   medium       2        15
 *   low          1        10
 *
 *   totalDeduction = sum of all per-severity deductions   (max possible = 75)
 *   score = max(0, 100 − totalDeduction)
 *
 * WHY LOGARITHMIC?
 *   • 1 critical   → −6    (immediate impact)
 *   • 10 critical  → −21   (serious concern)
 *   • 100 critical → −30   (cap reached — catastrophic, but score still > 0)
 *   • 16,000 medium → −15  (cap — lots of noise, but doesn't dominate the score)
 *
 *   This gives a GRADUAL decline that never collapses to 0 unless ALL severities
 *   are heavily triggered simultaneously. Even in worst case → minimum score ≈ 25.
 *
 * GRADE SCALE:
 *   A = 90–100  |  B = 75–89  |  C = 60–74  |  D = 40–59  |  F = 0–39
 *
 * ══════════════════════════════════════════════════════════════════════════════
 */

// ── Severity configuration ──────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  critical: { weight: 6,  cap: 30 },
  high:     { weight: 4,  cap: 20 },
  medium:   { weight: 2,  cap: 15 },
  low:      { weight: 1,  cap: 10 },
};

/**
 * Compute the deduction for a single severity level.
 *
 * Formula: min(cap, weight × log₂(1 + count))
 *
 * The +1 inside the log prevents log(0) = -Infinity and ensures
 * that count=0 → deduction=0.
 *
 * @param {string} severity - 'critical' | 'high' | 'medium' | 'low'
 * @param {number} count    - Number of alerts for this severity
 * @returns {number}        - Deduction points (0 to cap)
 */
function severityDeduction(severity, count) {
  const cfg = SEVERITY_CONFIG[severity];
  if (!cfg || count <= 0) return 0;
  return Math.min(cfg.cap, cfg.weight * Math.log2(1 + count));
}

/**
 * Calculate the total security score from severity counts.
 *
 * @param {{ critical: number, high: number, medium: number, low: number }} sevCounts
 * @returns {{ score: number, grade: string, risk: string, systemHealth: string, deductions: object }}
 */
function calculateScore(sevCounts) {
  const deductions = {};
  let totalDeduction = 0;

  for (const [sev, count] of Object.entries(sevCounts)) {
    const d = severityDeduction(sev, count);
    deductions[sev] = Math.round(d * 10) / 10; // 1 decimal precision
    totalDeduction += d;
  }

  const score = Math.round(Math.max(0, Math.min(100, 100 - totalDeduction)));

  return {
    score,
    grade:        scoreToGrade(score),
    risk:         scoreToRisk(score),
    systemHealth: scoreToHealth(score),
    deductions,
    totalDeduction: Math.round(totalDeduction * 10) / 10,
  };
}

/**
 * Calculate score from per-category counts (used by compliance.service.js).
 *
 * Uses the same logarithmic approach but with category-specific weights and caps.
 *
 * @param {object} categoryCounts - { fileViolations, usbViolations, networkAttacks, malwareEvents, loginFailures, unresolvedCritical }
 * @returns {{ score: number, deductions: object }}
 */
const CATEGORY_CONFIG = {
  fileViolations:     { weight: 1.5, cap: 10 },
  usbViolations:      { weight: 2.5, cap: 12 },
  networkAttacks:     { weight: 1.5, cap: 10 },
  malwareEvents:      { weight: 4,   cap: 25 },
  loginFailures:      { weight: 1,   cap: 8  },
  unresolvedCritical: { weight: 5,   cap: 30 },
  privilege_escalation: { weight: 3, cap: 18 },
  ransomware:         { weight: 5,   cap: 28 },
  reverse_shell:      { weight: 4.5, cap: 25 },
};

function categoryDeduction(category, count) {
  const cfg = CATEGORY_CONFIG[category];
  if (!cfg || count <= 0) return 0;
  return Math.min(cfg.cap, cfg.weight * Math.log2(1 + count));
}

function calculateCategoryScore(categoryCounts) {
  const deductions = {};
  let totalDeduction = 0;

  for (const [cat, count] of Object.entries(categoryCounts)) {
    const d = categoryDeduction(cat, count);
    deductions[cat] = Math.round(d * 10) / 10;
    totalDeduction += d;
  }

  // Cap total deduction at 85 so score never goes below 15 from categories alone
  totalDeduction = Math.min(85, totalDeduction);
  const score = Math.round(Math.max(0, Math.min(100, 100 - totalDeduction)));

  return { score, deductions };
}

// ── Grade / Risk / Health mappers ───────────────────────────────────────────
function scoreToGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function scoreToRisk(score) {
  if (score >= 80) return 'low';
  if (score >= 60) return 'medium';
  if (score >= 40) return 'high';
  return 'critical';
}

function scoreToHealth(score) {
  if (score >= 80) return 'Healthy';
  if (score >= 60) return 'Degraded';
  if (score >= 40) return 'At Risk';
  return 'Critical';
}

module.exports = {
  SEVERITY_CONFIG,
  CATEGORY_CONFIG,
  severityDeduction,
  calculateScore,
  calculateCategoryScore,
  categoryDeduction,
  scoreToGrade,
  scoreToRisk,
  scoreToHealth,
};
