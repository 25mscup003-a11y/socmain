const LOG_RANGE_HOURS = Object.freeze({
  '24h': 24, '7d': 168, '30d': 720, '60d': 1440, '90d': 2160, '180d': 4320,
});

const REPORT_PERIOD_HOURS = Object.freeze({
  daily: 24, weekly: 168, monthly: 720, '90days': 2160, '180days': 4320,
});

module.exports = { LOG_RANGE_HOURS, REPORT_PERIOD_HOURS };
