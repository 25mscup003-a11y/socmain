function boundedInteger(value, { defaultValue, min = 1, max }) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return defaultValue;
  return Math.min(max, Math.max(min, parsed));
}

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function enforceBatchLimit(items, max, name = 'items') {
  if (!Array.isArray(items)) {
    return { ok: false, status: 400, message: `${name} array required` };
  }
  if (items.length > max) {
    return {
      ok: false,
      status: 413,
      message: `${name} exceeds maximum batch size of ${max}`,
    };
  }
  return { ok: true };
}

module.exports = {
  boundedInteger,
  escapeRegex,
  enforceBatchLimit,
};
