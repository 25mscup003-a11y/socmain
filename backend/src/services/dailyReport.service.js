/**
 * Daily Report Service
 * - generateDailyReport(companyId, departmentId?, date?, generatedBy?)
 *   → runs aggregation for that day and upserts a DailyReport document
 * - scheduleDailyReports()
 *   → fires every day at midnight for ALL active companies (and each dept)
 * - getLatestReport(companyId, departmentId?)
 *   → returns the most recent stored DailyReport
 */

const mongoose    = require('mongoose');
const Alert       = require('../models/Alert.model');
const Company     = require('../models/Company.model');
const Department  = require('../models/Department.model');
const DailyReport = require('../models/DailyReport.model');

// ─── Core generator ──────────────────────────────────────────────────────────
async function generateDailyReport(companyId, departmentId = null, date = null, generatedBy = 'auto') {
  const targetDate = date || new Date().toISOString().slice(0, 10);
  const start = new Date(targetDate + 'T00:00:00.000Z');
  const end   = new Date(targetDate + 'T23:59:59.999Z');

  const base = {
    companyId: new mongoose.Types.ObjectId(companyId),
    createdAt: { $gte: start, $lte: end },
  };
  if (departmentId) base.departmentId = new mongoose.Types.ObjectId(departmentId);

  const [total, bySeverity, byStatus, byCategory, topRules, topSystems, resolvedAvg] =
    await Promise.all([
      Alert.countDocuments(base),
      Alert.aggregate([{ $match: base }, { $group: { _id: '$severity', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Alert.aggregate([{ $match: base }, { $group: { _id: '$status',   count: { $sum: 1 } } }]),
      Alert.aggregate([{ $match: base }, { $group: { _id: '$eventCategory', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Alert.aggregate([
        { $match: { ...base, type: { $exists: true } } },
        { $group: { _id: '$type', count: { $sum: 1 }, description: { $first: '$description' } } },
        { $sort: { count: -1 } }, { $limit: 5 },
      ]),
      Alert.aggregate([
        { $match: base },
        { $group: { _id: '$agentName', count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 5 },
      ]),
      Alert.aggregate([
        { $match: { ...base, status: 'resolved', resolvedAt: { $exists: true } } },
        { $project: { diff: { $divide: [{ $subtract: ['$resolvedAt', '$createdAt'] }, 60000] } } },
        { $group: { _id: null, avg: { $avg: '$diff' } } },
      ]),
    ]);

  const sevMap = {};
  bySeverity.forEach(r => { sevMap[r._id] = r.count; });

  const reportData = {
    companyId,
    departmentId:  departmentId || null,
    date:          targetDate,
    generatedBy,
    summary: {
      totalAlerts:         total,
      critical:            sevMap.critical || 0,
      high:                sevMap.high     || 0,
      medium:              sevMap.medium   || 0,
      low:                 sevMap.low      || 0,
      avgResolutionMinutes: resolvedAvg[0]?.avg ? Math.round(resolvedAvg[0].avg) : null,
    },
    bySeverity: bySeverity.map(r => ({ severity: r._id, count: r.count })),
    byStatus:   byStatus.map(r   => ({ status:   r._id, count: r.count })),
    byCategory: byCategory.filter(r => r._id).map(r => ({ category: r._id, count: r.count })),
    topRules:   topRules.map(r   => ({ ruleId: r._id, description: r.description, count: r.count })),
    topSystems: topSystems.filter(r => r._id).map(r => ({ agent: r._id, count: r.count })),
  };

  // Upsert — same company+dept+date = overwrite
  await DailyReport.findOneAndUpdate(
    { companyId, departmentId: departmentId || null, date: targetDate, generatedBy },
    reportData,
    { upsert: true, new: true }
  );

  return reportData;
}

// ─── Get latest stored report ─────────────────────────────────────────────────
async function getLatestReport(companyId, departmentId = null) {
  const q = { companyId, departmentId: departmentId || null };
  return DailyReport.findOne(q).sort({ date: -1, createdAt: -1 }).lean();
}

// ─── Get report for a specific date ──────────────────────────────────────────
async function getReportForDate(companyId, date, departmentId = null) {
  return DailyReport.findOne({
    companyId,
    departmentId: departmentId || null,
    date,
  }).sort({ createdAt: -1 }).lean();
}

// ─── Auto-scheduler: runs at midnight for all companies ──────────────────────
function scheduleDailyReports() {
  const msUntilMidnight = () => {
    const now  = new Date();
    const next = new Date(now);
    next.setUTCDate(next.getUTCDate() + 1);
    next.setUTCHours(0, 0, 10, 0); // 00:00:10 UTC next day
    return next - now;
  };

  const runNightly = async () => {
    try {
      const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
      console.log(`[DailyReport] Running nightly generation for ${yesterday}`);

      const companies = await Company.find({ 'plan.isActive': true }).select('_id').lean();
      for (const co of companies) {
        // Company-level report
        await generateDailyReport(co._id, null, yesterday, 'auto').catch(e =>
          console.error(`[DailyReport] company ${co._id}:`, e.message)
        );
        // Per-department reports
        const depts = await Department.find({ companyId: co._id }).select('_id').lean();
        for (const dept of depts) {
          await generateDailyReport(co._id, dept._id, yesterday, 'auto').catch(e =>
            console.error(`[DailyReport] dept ${dept._id}:`, e.message)
          );
        }
      }
      console.log(`[DailyReport] Done for ${yesterday}`);
      // Trigger weekly + monthly compliance reports on appropriate days
      await runWeeklyAndMonthlyReports(yesterday).catch(e =>
        console.error('[Weekly/Monthly]', e.message)
      );
    } catch (err) {
      console.error('[DailyReport] Scheduler error:', err.message);
    }
    // Schedule next run
    setTimeout(runNightly, msUntilMidnight());
  };

  setTimeout(runNightly, msUntilMidnight());
  console.log(`[DailyReport] Scheduler set — next run in ${Math.round(msUntilMidnight()/60000)} minutes`);
}

const { generateComplianceReport } = require('./compliance.service');

// ─── Auto-scheduler: weekly + monthly compliance reports ─────────────────────
async function runWeeklyAndMonthlyReports(yesterday) {
  const yDate = new Date(yesterday + 'T00:00:00.000Z');
  const dayOfWeek = yDate.getUTCDay();  // 0 = Sunday
  const dayOfMonth = yDate.getUTCDate();

  const companies = await Company.find({ 'plan.isActive': true }).select('_id').lean();

  for (const co of companies) {
    // Weekly — every Sunday (day 0)
    if (dayOfWeek === 0) {
      const from = new Date(yDate.getTime() - 6 * 86400000).toISOString();
      const to   = yDate.toISOString();
      generateComplianceReport(co._id.toString(), { reportType: 'weekly', from, to })
        .catch(e => console.error(`[WeeklyReport] company ${co._id}:`, e.message));
    }

    // Monthly — 1st of every month
    if (dayOfMonth === 1) {
      const to   = yDate.toISOString();
      const from = new Date(new Date(to).setUTCDate(1)).toISOString();
      generateComplianceReport(co._id.toString(), { reportType: 'monthly', from, to })
        .catch(e => console.error(`[MonthlyReport] company ${co._id}:`, e.message));
    }
  }
}

module.exports = { generateDailyReport, getLatestReport, getReportForDate, scheduleDailyReports };

