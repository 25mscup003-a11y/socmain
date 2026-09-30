'use strict';

// This index is already present in production. The alerts collection is at
// MongoDB's index limit, so the summary deliberately narrows the 24h company
// window with this index before evaluating IDS categories in memory.
const IDS_SUMMARY_INDEX_HINT = { companyId: 1, createdAt: -1 };
const IDS_SUMMARY_QUERY_TIMEOUT_MS = Math.max(
  5000,
  Number(process.env.IDS_SUMMARY_QUERY_TIMEOUT_MS || 15000),
);

function normalizeIdsAlertRollup(row = {}) {
  const activeAgents = Array.isArray(row.activeAgents)
    ? row.activeAgents.filter(value => value !== null && String(value).trim() !== '')
    : [];
  return {
    total: Number(row.total || 0),
    blocked: Number(row.blocked || 0),
    critical: Number(row.critical || 0),
    high: Number(row.high || 0),
    activeSystems: activeAgents.length,
  };
}

async function loadIdsAlertRollup(Alert, filter) {
  const query = Alert.aggregate([
    { $match: filter },
    {
      $addFields: {
        normalizedSeverity: {
          $toLower: { $toString: { $ifNull: ['$severity', 'low'] } },
        },
      },
    },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        blocked: {
          $sum: {
            $cond: [
              {
                $or: [
                  { $eq: ['$blocked', true] },
                  { $in: ['$action', ['blocked', 'dropped', 'rejected']] },
                  { $eq: ['$type', 'IPS_BLOCK'] },
                ],
              },
              1,
              0,
            ],
          },
        },
        critical: { $sum: { $cond: [{ $eq: ['$normalizedSeverity', 'critical'] }, 1, 0] } },
        high: { $sum: { $cond: [{ $eq: ['$normalizedSeverity', 'high'] }, 1, 0] } },
        activeAgents: { $addToSet: '$agentName' },
      },
    },
  ])
    .hint(IDS_SUMMARY_INDEX_HINT)
    .option({ maxTimeMS: IDS_SUMMARY_QUERY_TIMEOUT_MS });

  // Query failures must reach the route error handler. Returning an empty
  // object on timeout makes a live IDS deployment look as if it has 0 events.
  const rows = await query.exec();
  return normalizeIdsAlertRollup(rows[0]);
}

module.exports = {
  IDS_SUMMARY_INDEX_HINT,
  IDS_SUMMARY_QUERY_TIMEOUT_MS,
  loadIdsAlertRollup,
  normalizeIdsAlertRollup,
};
