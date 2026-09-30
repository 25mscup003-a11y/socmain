const router  = require('express').Router();
const { authenticate, requireAnalyst, requireSuperAdmin } = require('../middleware/auth.middleware');
const { generateReport, reportToCsv, reportToPdf } = require('../services/report.service');

router.use(authenticate);

// GET /api/reports — company user
router.get('/', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const deptFilter = req.query.departmentId || (role === 'department_admin' ? departmentId : null);
    const report = await generateReport(companyId, req.query, deptFilter);
    res.json(report);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/reports/csv
router.get('/csv', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const deptFilter = req.query.departmentId || (role === 'department_admin' ? departmentId : null);
    const report = await generateReport(companyId, { ...req.query, exportMode: true }, deptFilter);
    const csv    = reportToCsv(report);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="soc-report-${report.meta.from.slice(0,10)}.csv"`);
    res.send(csv);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/reports/pdf — HTML-based PDF (print-friendly)
router.get('/pdf', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const deptFilter = req.query.departmentId || (role === 'department_admin' ? departmentId : null);
    const report  = await generateReport(companyId, { ...req.query, exportMode: true }, deptFilter);
    const html    = reportToPdf(report);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `inline; filename="soc-report-${report.meta.from.slice(0,10)}.html"`);
    res.send(html);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── Superadmin report for any company ─────────────────────────────────────────
router.get('/company/:companyId', requireSuperAdmin, async (req, res) => {
  try {
    const deptFilter = req.query.departmentId || req.query.departmentIds?.split(',') || null;
    const report = await generateReport(req.params.companyId, req.query, deptFilter);
    res.json(report);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/company/:companyId/pdf', requireSuperAdmin, async (req, res) => {
  try {
    const deptFilter = req.query.departmentId || req.query.departmentIds?.split(',') || null;
    const report  = await generateReport(req.params.companyId, req.query, deptFilter);
    const html    = reportToPdf(report);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `inline; filename="soc-report-${report.meta.from.slice(0,10)}.html"`);
    res.send(html);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/company/:companyId/csv', requireSuperAdmin, async (req, res) => {
  try {
    const deptFilter = req.query.departmentId || req.query.departmentIds?.split(',') || null;
    const report  = await generateReport(req.params.companyId, req.query, deptFilter);
    const csv     = reportToCsv(report);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="soc-report.csv"`);
    res.send(csv);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
