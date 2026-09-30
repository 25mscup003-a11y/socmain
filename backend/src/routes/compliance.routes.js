/**
 * compliance.routes.js
 * API endpoints for compliance reporting and security scoring.
 *
 * GET  /api/compliance/score      — real-time security score
 * GET  /api/compliance/latest     — latest compliance report
 * POST /api/compliance/generate   — generate new compliance report
 * GET  /api/compliance/history    — paginated past reports
 * GET  /api/compliance/pdf/:id    — download as HTML/PDF
 * GET  /api/compliance/csv/:id    — download as CSV
 */
const router  = require('express').Router();
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { generateComplianceReport, calculateSecurityScore, complianceReportToHtml } = require('../services/compliance.service');
const ComplianceReport = require('../models/Compliance.model');

router.use(authenticate);

// ── GET /api/compliance/score — live security score (fast, no report saved) ──
router.get('/score', requireAnalyst, async (req, res) => {
  try {
    const { from, to } = req.query;
    const result = await calculateSecurityScore(
      req.user.companyId.toString(),
      { from, to },
    );
    res.json(result);
  } catch (err) {
    console.error('[compliance/score]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/compliance/latest — latest saved report (any type) ──────────────
router.get('/latest', requireAnalyst, async (req, res) => {
  try {
    const { type, companyId: qCompanyId } = req.query;
    // Superadmin can query any company via ?companyId=
    const companyId = (req.user.role === 'superadmin' && qCompanyId)
      ? qCompanyId : req.user.companyId;
    const filter = { companyId };
    if (type) filter.reportType = type;
    if (req.user.role === 'department_admin') filter.departmentId = req.user.departmentId;

    const report = await ComplianceReport.findOne(filter).sort({ createdAt: -1 }).lean();
    res.json(report || null);
  } catch (err) {
    console.error('[compliance/latest]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/compliance/history — paginated past reports ─────────────────────
router.get('/history', requireAnalyst, async (req, res) => {
  try {
    const { page = 1, limit = 10, type } = req.query;
    const filter = { companyId: req.user.companyId };
    if (type) filter.reportType = type;
    if (req.user.role === 'department_admin') filter.departmentId = req.user.departmentId;

    const [reports, total] = await Promise.all([
      ComplianceReport.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * Number(limit))
        .limit(Number(limit))
        .select('reportType periodStart periodEnd securityScore summary createdAt frameworks')
        .lean(),
      ComplianceReport.countDocuments(filter),
    ]);

    res.json({ reports, total, page: Number(page) });
  } catch (err) {
    console.error('[compliance/history]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/compliance/generate — generate & save new report ────────────────
router.post('/generate', requireManager, async (req, res) => {
  try {
    const {
      reportType = 'manual',
      from, to,
      frameworks = ['ISO_27001', 'PCI_DSS', 'GDPR', 'HIPAA'],
    } = req.body;

    const companyId = req.user.companyId.toString();
    const deptId    = req.user.role === 'department_admin' ? req.user.departmentId?.toString() : null;

    const report = await generateComplianceReport(companyId, {
      reportType, from, to, frameworks, deptId,
    });

    res.status(201).json({ ok: true, report });
  } catch (err) {
    console.error('[compliance/generate]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/compliance/pdf/:id — download HTML/PDF ──────────────────────────
router.get('/pdf/:id', requireAnalyst, async (req, res) => {
  try {
    const report = await ComplianceReport.findOne({
      _id:       req.params.id,
      companyId: req.user.companyId,
    }).lean();
    if (!report) return res.status(404).json({ message: 'Report not found' });

    const Company = require('../models/Company.model');
    const company = await Company.findById(req.user.companyId).select('name').lean();

    const html = complianceReportToHtml(report, company?.name || '');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="compliance_report_${report._id}.html"`);
    res.send(html);
  } catch (err) {
    console.error('[compliance/pdf]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/compliance/csv/:id — download CSV ───────────────────────────────
router.get('/csv/:id', requireAnalyst, async (req, res) => {
  try {
    const report = await ComplianceReport.findOne({
      _id: req.params.id, companyId: req.user.companyId,
    }).lean();
    if (!report) return res.status(404).json({ message: 'Report not found' });

    const lines = [
      ['Framework', 'Control ID', 'Control Name', 'Status', 'Score', 'Evidence'].join(','),
    ];

    for (const fw of report.frameworks || []) {
      for (const c of fw.controls || []) {
        lines.push([
          fw.name, c.id,
          `"${(c.name || '').replace(/"/g, '""')}"`,
          c.status,
          c.score ?? '',
          `"${(c.evidence || '').replace(/"/g, '""')}"`,
        ].join(','));
      }
    }
    const csv = lines.join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="compliance_${report._id}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('[compliance/csv]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/compliance/frameworks — list latest per-framework scores ─────────
router.get('/frameworks', requireAnalyst, async (req, res) => {
  try {
    const report = await ComplianceReport.findOne({
      companyId: req.user.companyId,
    }).sort({ createdAt: -1 }).select('frameworks securityScore periodStart periodEnd createdAt').lean();

    if (!report) {
      return res.json({
        securityScore: null,
        frameworks: [],
        message: 'No compliance report generated yet. Click Generate Report.',
      });
    }

    res.json({
      securityScore: report.securityScore,
      frameworks: (report.frameworks || []).map(fw => ({
        name:         fw.name,
        overallScore: fw.overallScore,
        status:       fw.status,
        passCount:    fw.passCount,
        failCount:    fw.failCount,
        partialCount: fw.partialCount,
      })),
      reportId:    report._id,
      periodStart: report.periodStart,
      periodEnd:   report.periodEnd,
      generatedAt: report.createdAt,
    });
  } catch (err) {
    console.error('[compliance/frameworks]', err.message);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
