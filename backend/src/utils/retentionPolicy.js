const DAY_MS = 24 * 60 * 60 * 1000;

function normalizeRetention(policy = {}, defaults = {}) {
  const hotDays = Math.max(1, Number(policy.hotDays || defaults.hotDays || process.env.EVENT_HOT_RETENTION_DAYS || 30));
  const totalDays = Math.max(hotDays, Number(policy.totalDays || defaults.totalDays || process.env.EVENT_TOTAL_RETENTION_DAYS || 90));
  return {
    hotDays,
    totalDays,
    archiveEnabled: policy.archiveEnabled === true,
    legalHold: policy.legalHold === true,
  };
}

function applyRetention(document, policy, eventTime = null) {
  const normalized = normalizeRetention(policy);
  const base = new Date(eventTime || document.createdAt || document.receivedAt || Date.now());
  return {
    ...document,
    expiresAt: normalized.legalHold ? null : new Date(base.getTime() + normalized.totalDays * DAY_MS),
  };
}

module.exports = { DAY_MS, normalizeRetention, applyRetention };
