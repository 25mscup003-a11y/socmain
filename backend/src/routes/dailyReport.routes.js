/**
 * Daily Report Routes
 * GET  /api/daily-report/latest          — latest report for current user's company/dept
 * GET  /api/daily-report/:date           — report for a specific YYYY-MM-DD
 * POST /api/daily-report/generate        — analyst manually generates today's report
 * GET  /api/daily-report/company/:id/latest  — superadmin: any company
 * GET  /api/daily-report/company/:id/:date   — superadmin: any company + date
 */
const router = require('express').Router();
const { authenticate, requireAnalyst, requireSuperAdmin } = require('../middleware/auth.middleware');
const { generateDailyReport, getLatestReport, getReportForDate } = require('../services/dailyReport.service');

router.use(authenticate);

// GET /api/daily-report/latest
router.get('/latest', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const deptFilter = req.query.departmentId ||
      (role === 'department_admin' ? departmentId : null);
    const report = await getLatestReport(companyId, deptFilter);
    res.json(report || null);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/daily-report/:date  (YYYY-MM-DD)
router.get('/:date(\\d{4}-\\d{2}-\\d{2})', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const deptFilter = req.query.departmentId ||
      (role === 'department_admin' ? departmentId : null);
    const report = await getReportForDate(companyId, req.params.date, deptFilter);
    res.json(report || null);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/daily-report/generate  — analyst manual trigger
router.post('/generate', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId, id } = req.user;
    const date       = req.body.date || new Date().toISOString().slice(0, 10);
    const deptFilter = req.body.departmentId ||
      (role === 'department_admin' ? departmentId : null);
    const report = await generateDailyReport(companyId, deptFilter, date, id);
    res.json(report);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Superadmin routes
router.get('/company/:companyId/latest', requireSuperAdmin, async (req, res) => {
  try {
    const deptFilter = req.query.departmentId || null;
    const report = await getLatestReport(req.params.companyId, deptFilter);
    res.json(report || null);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/company/:companyId/:date', requireSuperAdmin, async (req, res) => {
  try {
    const deptFilter = req.query.departmentId || null;
    const report = await getReportForDate(req.params.companyId, req.params.date, deptFilter);
    res.json(report || null);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.post('/company/:companyId/generate', requireSuperAdmin, async (req, res) => {
  try {
    const date   = req.body.date || new Date().toISOString().slice(0, 10);
    const deptId = req.body.departmentId || null;
    const report = await generateDailyReport(req.params.companyId, deptId, date, 'superadmin');
    res.json(report);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
