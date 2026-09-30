/**
 * compliance.service.js
 * Generates compliance assessments (ISO 27001, PCI-DSS, GDPR, HIPAA)
 * and security scores based on alert data in MongoDB.
 *
 * Security Score Formula (Logarithmic):
 *   deduction(category) = min(cap, weight × log₂(1 + count))
 *   score = max(0, 100 − totalDeduction)
 *   Clamped to [0, 100]
 */

const Alert            = require('../models/Alert.model');
const System           = require('../models/System.model');
const SoarLog          = require('../models/SoarLog.model');
const ComplianceReport = require('../models/Compliance.model');
const mongoose         = require('mongoose');
const { calculateCategoryScore } = require('../utils/securityScore');

// ── Security Score Calculation ────────────────────────────────────────────────
async function calculateSecurityScore(companyId, { from, to } = {}) {
  const start = from ? new Date(from) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const end   = to   ? new Date(to)   : new Date();
  const cid   = new mongoose.Types.ObjectId(companyId);
  const base  = { companyId: cid, createdAt: { $gte: start, $lte: end } };

  const [fileViolations, usbViolations, networkAttacks, malwareEvents, loginFailures, unresolvedCritical, totalAlerts] =
    await Promise.all([
      Alert.countDocuments({ ...base, eventCategory: 'file' }),
      Alert.countDocuments({ ...base, eventCategory: 'usb' }),
      Alert.countDocuments({ ...base, eventCategory: 'network' }),
      Alert.countDocuments({ ...base, eventCategory: 'malware' }),
      Alert.countDocuments({ ...base, eventCategory: 'edr', userAction: { $in: ['failed_login','auth_failure','brute_force'] } }),
      Alert.countDocuments({ ...base, severity: 'critical', status: { $in: ['open','investigating'] } }),
      Alert.countDocuments(base),
    ]);

  const categoryCounts = {
    fileViolations:     fileViolations,
    usbViolations:      usbViolations,
    networkAttacks:     networkAttacks,
    malwareEvents:      malwareEvents,
    loginFailures:      loginFailures,
    unresolvedCritical: unresolvedCritical,
  };

  // ── If no data at all → perfect score (no threats = 100) ─────────────────
  if (totalAlerts === 0) {
    return {
      score: 100,
      breakdown: { fileViolations: 0, usbViolations: 0, networkAttacks: 0, malwareEvents: 0, loginFailures: 0, unresolvedCritical: 0 },
      deductions: { fileViolations: 0, usbViolations: 0, networkAttacks: 0, malwareEvents: 0, loginFailures: 0, unresolvedCritical: 0 },
      period: { from: start.toISOString(), to: end.toISOString() },
    };
  }

  // Logarithmic scoring with per-category caps
  const { score, deductions } = calculateCategoryScore(categoryCounts);

  return {
    score: Math.round(score),
    breakdown: {
      fileViolations, usbViolations, networkAttacks,
      malwareEvents, loginFailures, unresolvedCritical,
    },
    deductions,
    period: { from: start.toISOString(), to: end.toISOString() },
  };
}

// ── Framework Assessment ──────────────────────────────────────────────────────

async function assessISO27001(companyId, summary, from, to) {
  const cid  = new mongoose.Types.ObjectId(companyId);
  const base = { companyId: cid, createdAt: { $gte: from, $lte: to } };

  const [hasFIM, hasUSBControl, hasNetworkMonitor, hasEDR, hasMalwareDet, resolvedCritical, criticalTotal] =
    await Promise.all([
      Alert.countDocuments({ ...base, eventCategory: 'file' }),
      Alert.countDocuments({ ...base, eventCategory: 'usb' }),
      Alert.countDocuments({ ...base, eventCategory: 'network' }),
      Alert.countDocuments({ ...base, eventCategory: 'edr' }),
      Alert.countDocuments({ ...base, eventCategory: 'malware' }),
      Alert.countDocuments({ ...base, severity: 'critical', status: 'resolved' }),
      Alert.countDocuments({ ...base, severity: 'critical' }),
    ]);

  const resolutionRate = criticalTotal > 0 ? (resolvedCritical / criticalTotal) * 100 : 100;

  const controls = [
    {
      id: 'A.8.1', name: 'Responsibility for assets',
      status: hasFIM > 0 ? 'pass' : 'fail',
      description: 'File Integrity Monitoring active',
      evidence:    `${hasFIM} file events detected`,
      score:       hasFIM > 0 ? 100 : 0,
    },
    {
      id: 'A.9.4', name: 'System and application access control',
      status: hasEDR > 0 ? 'pass' : 'fail',
      description: 'User authentication events monitored',
      evidence:    `${hasEDR} EDR events captured`,
      score:       hasEDR > 0 ? 100 : 0,
    },
    {
      id: 'A.10.1', name: 'Cryptographic controls',
      status: 'na',
      description: 'Manual assessment required',
      evidence:    'Not auto-assessable from logs',
      score:       0,
    },
    {
      id: 'A.12.2', name: 'Protection from malware',
      status: hasMalwareDet > 0 ? 'pass' : 'partial',
      description: 'Malware detection engine active',
      evidence:    `${hasMalwareDet} malware events detected`,
      score:       hasMalwareDet >= 0 ? 80 : 50,
    },
    {
      id: 'A.12.6', name: 'Technical vulnerability management',
      status: hasNetworkMonitor > 0 ? 'pass' : 'fail',
      description: 'Network threat monitoring active',
      evidence:    `${hasNetworkMonitor} network events captured`,
      score:       hasNetworkMonitor > 0 ? 100 : 0,
    },
    {
      id: 'A.12.7', name: 'Information systems audit controls',
      status: 'pass',
      description: 'Central log collection active',
      evidence:    `${summary.totalAlerts} total events logged`,
      score:       100,
    },
    {
      id: 'A.13.1', name: 'Network security management',
      status: hasNetworkMonitor > 0 ? 'pass' : 'fail',
      description: 'Network monitoring enabled',
      evidence:    `${hasNetworkMonitor} network alerts`,
      score:       hasNetworkMonitor > 0 ? 100 : 0,
    },
    {
      id: 'A.16.1', name: 'Management of information security incidents',
      status: resolutionRate >= 80 ? 'pass' : resolutionRate >= 50 ? 'partial' : 'fail',
      description: 'Incident resolution rate',
      evidence:    `${Math.round(resolutionRate)}% of critical alerts resolved`,
      score:       Math.round(resolutionRate),
    },
  ];

  const passing = controls.filter(c => c.status === 'pass').length;
  const failing = controls.filter(c => c.status === 'fail').length;
  const partial = controls.filter(c => c.status === 'partial').length;
  const na      = controls.filter(c => c.status === 'na').length;
  const scorableCount = controls.filter(c => c.status !== 'na').length;
  const overallScore  = scorableCount > 0
    ? Math.round(controls.filter(c => c.status !== 'na').reduce((s, c) => s + c.score, 0) / scorableCount)
    : 0;

  return {
    name: 'ISO_27001', version: '2013',
    overallScore, passCount: passing, failCount: failing, partialCount: partial, naCount: na,
    controls,
    status: overallScore >= 80 ? 'compliant' : overallScore >= 50 ? 'partial' : 'non_compliant',
  };
}

async function assessPCIDSS(companyId, summary, from, to) {
  const cid  = new mongoose.Types.ObjectId(companyId);
  const base = { companyId: cid, createdAt: { $gte: from, $lte: to } };

  const [networkEvents, loginFails, malwareEvents, fileEvents] = await Promise.all([
    Alert.countDocuments({ ...base, eventCategory: 'network' }),
    Alert.countDocuments({ ...base, eventCategory: 'edr', userAction: { $in: ['failed_login','brute_force'] } }),
    Alert.countDocuments({ ...base, eventCategory: 'malware' }),
    Alert.countDocuments({ ...base, eventCategory: 'file' }),
  ]);

  const controls = [
    {
      id: 'REQ.1', name: 'Install and maintain network security controls',
      status: networkEvents >= 0 ? 'pass' : 'fail',
      description: 'Network traffic monitored via SOC agent',
      evidence:    `${networkEvents} network events captured`,
      score: 85,
    },
    {
      id: 'REQ.5', name: 'Protect all systems and networks from malicious software',
      status: summary.malwareEvents >= 0 ? 'pass' : 'fail',
      description: 'Anti-malware / YARA scanning active',
      evidence:    `${malwareEvents} malware detections`,
      score: malwareEvents === 0 ? 100 : 80,
    },
    {
      id: 'REQ.7', name: 'Restrict access to system components',
      status: 'partial',
      description: 'User access tracking via EDR',
      evidence:    `${loginFails} failed login attempts detected`,
      score: loginFails === 0 ? 90 : 60,
    },
    {
      id: 'REQ.10', name: 'Log and monitor all access to system components',
      status: 'pass',
      description: 'Centralized log collection active',
      evidence:    `${summary.totalAlerts} events logged`,
      score: 100,
    },
    {
      id: 'REQ.11', name: 'Test security of systems and networks regularly',
      status: 'partial',
      description: 'Continuous monitoring via agent',
      evidence:    'Automated scanning active; manual pentest: not tracked',
      score: 70,
    },
    {
      id: 'REQ.12', name: 'Support information security with policies and procedures',
      status: 'partial',
      description: 'SOAR automated response policies active',
      evidence:    `${summary.soarActionsExecuted || 0} SOAR actions executed`,
      score: 65,
    },
  ];

  const passing = controls.filter(c => c.status === 'pass').length;
  const failing = controls.filter(c => c.status === 'fail').length;
  const partial = controls.filter(c => c.status === 'partial').length;
  const overallScore = Math.round(controls.reduce((s, c) => s + c.score, 0) / controls.length);

  return {
    name: 'PCI_DSS', version: '4.0',
    overallScore, passCount: passing, failCount: failing, partialCount: partial, naCount: 0,
    controls,
    status: overallScore >= 80 ? 'compliant' : overallScore >= 50 ? 'partial' : 'non_compliant',
  };
}

async function assessGDPR(companyId, summary, from, to) {
  const cid  = new mongoose.Types.ObjectId(companyId);
  const base = { companyId: cid, createdAt: { $gte: from, $lte: to } };

  const [usbEvents, dataAccess, breachAlerts] = await Promise.all([
    Alert.countDocuments({ ...base, eventCategory: 'usb' }),
    Alert.countDocuments({ ...base, eventCategory: 'file' }),
    Alert.countDocuments({ ...base, severity: { $in: ['critical', 'high'] }, eventCategory: { $in: ['malware', 'network'] } }),
  ]);

  const controls = [
    {
      id: 'Art.5', name: 'Principles of processing personal data',
      status: 'partial',
      description: 'Data access monitoring via FIM',
      evidence:    `${dataAccess} file access events monitored`,
      score: 65,
    },
    {
      id: 'Art.25', name: 'Data protection by design and by default',
      status: 'partial',
      description: 'USB data transfer monitoring',
      evidence:    `${usbEvents} USB events captured`,
      score: usbEvents >= 0 ? 70 : 40,
    },
    {
      id: 'Art.32', name: 'Security of processing — encryption & integrity',
      status: 'pass',
      description: 'Agent uses HTTPS for data transmission; FIM active',
      evidence:    'Secure transport layer confirmed',
      score: 90,
    },
    {
      id: 'Art.33', name: 'Notification of personal data breach',
      status: breachAlerts > 0 ? 'pass' : 'partial',
      description: 'Breach alerts generated and logged',
      evidence:    `${breachAlerts} potential breach alerts detected`,
      score: 80,
    },
    {
      id: 'Art.35', name: 'Data protection impact assessment',
      status: 'partial',
      description: 'Risk scoring available in SOC system',
      evidence:    'Automated DPIA support via compliance score',
      score: 60,
    },
  ];

  const passing = controls.filter(c => c.status === 'pass').length;
  const failing = controls.filter(c => c.status === 'fail').length;
  const partial = controls.filter(c => c.status === 'partial').length;
  const overallScore = Math.round(controls.reduce((s, c) => s + c.score, 0) / controls.length);

  return {
    name: 'GDPR', version: '2018',
    overallScore, passCount: passing, failCount: failing, partialCount: partial, naCount: 0,
    controls,
    status: overallScore >= 80 ? 'compliant' : overallScore >= 50 ? 'partial' : 'non_compliant',
  };
}

async function assessHIPAA(companyId, summary, from, to) {
  const cid  = new mongoose.Types.ObjectId(companyId);
  const base = { companyId: cid, createdAt: { $gte: from, $lte: to } };

  const [loginFails, fileAccess, networkAlerts, edrAlerts] = await Promise.all([
    Alert.countDocuments({ ...base, eventCategory: 'edr', userAction: { $in: ['failed_login','brute_force'] } }),
    Alert.countDocuments({ ...base, eventCategory: 'file' }),
    Alert.countDocuments({ ...base, eventCategory: 'network' }),
    Alert.countDocuments({ ...base, eventCategory: 'edr' }),
  ]);

  const controls = [
    {
      id: '164.308(a)(1)', name: 'Security Management Process',
      status: 'pass',
      description: 'Risk analysis and management via SOC platform',
      evidence:    'Security score computed automatically',
      score: 90,
    },
    {
      id: '164.308(a)(5)', name: 'Security Awareness and Training',
      status: 'partial',
      description: 'Login failure monitoring active',
      evidence:    `${loginFails} suspicious login events`,
      score: loginFails === 0 ? 80 : 60,
    },
    {
      id: '164.312(a)(1)', name: 'Access Control',
      status: edrAlerts > 0 ? 'pass' : 'partial',
      description: 'User access events monitored',
      evidence:    `${edrAlerts} EDR events captured`,
      score: edrAlerts > 0 ? 85 : 50,
    },
    {
      id: '164.312(b)', name: 'Audit Controls',
      status: 'pass',
      description: 'All system events logged and retained',
      evidence:    `${summary.totalAlerts} total log entries`,
      score: 100,
    },
    {
      id: '164.312(c)(1)', name: 'Integrity — ePHI unchanged',
      status: fileAccess >= 0 ? 'pass' : 'fail',
      description: 'File Integrity Monitoring (FIM) active',
      evidence:    `${fileAccess} file events monitored`,
      score: 88,
    },
    {
      id: '164.312(e)(1)', name: 'Transmission Security',
      status: 'pass',
      description: 'Network monitoring + HTTPS agent transport',
      evidence:    `${networkAlerts} network events monitored`,
      score: 90,
    },
  ];

  const passing = controls.filter(c => c.status === 'pass').length;
  const failing = controls.filter(c => c.status === 'fail').length;
  const partial = controls.filter(c => c.status === 'partial').length;
  const overallScore = Math.round(controls.reduce((s, c) => s + c.score, 0) / controls.length);

  return {
    name: 'HIPAA', version: '2013',
    overallScore, passCount: passing, failCount: failing, partialCount: partial, naCount: 0,
    controls,
    status: overallScore >= 80 ? 'compliant' : overallScore >= 50 ? 'partial' : 'non_compliant',
  };
}

// ── Main report generator ──────────────────────────────────────────────────────
async function generateComplianceReport(companyId, {
  reportType = 'manual',
  from, to,
  frameworks = ['ISO_27001', 'PCI_DSS', 'GDPR', 'HIPAA'],
  deptId = null,
} = {}) {
  const start = from ? new Date(from) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const end   = to   ? new Date(to)   : new Date();
  const cid   = new mongoose.Types.ObjectId(companyId);
  const base  = { companyId: cid, createdAt: { $gte: start, $lte: end } };

  if (deptId) base.departmentId = new mongoose.Types.ObjectId(deptId);

  // Gather event summary
  const [totalAlerts, criticalAlerts, highAlerts, malwareEvents, networkAttacks, fileViolations, usbEvents, loginFailures, activeSystems] =
    await Promise.all([
      Alert.countDocuments(base),
      Alert.countDocuments({ ...base, severity: 'critical' }),
      Alert.countDocuments({ ...base, severity: 'high' }),
      Alert.countDocuments({ ...base, eventCategory: 'malware' }),
      Alert.countDocuments({ ...base, eventCategory: 'network' }),
      Alert.countDocuments({ ...base, eventCategory: 'file' }),
      Alert.countDocuments({ ...base, eventCategory: 'usb' }),
      Alert.countDocuments({ ...base, eventCategory: 'edr', userAction: { $in: ['failed_login','auth_failure','brute_force'] } }),
      System.countDocuments({ companyId: cid, status: 'active', isActive: true }),
    ]);

  const soarActionsExecuted = await SoarLog.countDocuments({ companyId: cid, createdAt: { $gte: start, $lte: end } });

  const summary = {
    totalAlerts, criticalAlerts, highAlerts, malwareEvents, networkAttacks,
    fileViolations, usbEvents, loginFailures, activeSystems, soarActionsExecuted,
  };

  // Security score
  const scoreResult = await calculateSecurityScore(companyId, { from: start, to: end });

  // Framework assessments
  const allFrameworks = {};
  if (frameworks.includes('ISO_27001')) allFrameworks.ISO_27001 = await assessISO27001(companyId, summary, start, end);
  if (frameworks.includes('PCI_DSS'))   allFrameworks.PCI_DSS   = await assessPCIDSS(companyId, summary, start, end);
  if (frameworks.includes('GDPR'))      allFrameworks.GDPR       = await assessGDPR(companyId, summary, start, end);
  if (frameworks.includes('HIPAA'))     allFrameworks.HIPAA      = await assessHIPAA(companyId, summary, start, end);

  // Key violations list
  const violations = await Alert.find({
    ...base,
    severity: { $in: ['critical', 'high'] },
    status:   { $in: ['open', 'investigating'] },
  }).sort({ createdAt: -1 }).limit(20).select('description severity eventCategory agentName createdAt').lean();

  const report = await ComplianceReport.create({
    companyId,
    departmentId: deptId || undefined,
    reportType,
    periodStart: start,
    periodEnd:   end,
    securityScore:  scoreResult.score,
    scoreBreakdown: scoreResult.breakdown,
    frameworks:     Object.values(allFrameworks),
    summary,
    violations,
  });

  return report;
}

// ── Compliance report to HTML/PDF-printable ──────────────────────────────────
function complianceReportToHtml(report, companyName = '') {
  const fwRows = (report.frameworks || []).map(fw => {
    const statusColor = fw.status === 'compliant' ? '#16a34a' : fw.status === 'partial' ? '#d97706' : '#dc2626';
    const controlRows = (fw.controls || []).map(c => `
      <tr>
        <td>${c.id}</td><td>${c.name}</td>
        <td style="color:${c.status === 'pass' ? '#16a34a' : c.status === 'fail' ? '#dc2626' : '#d97706'}">${c.status?.toUpperCase()}</td>
        <td>${c.score ?? '—'}%</td><td>${c.evidence || '—'}</td>
      </tr>`).join('');
    return `
      <h2 style="color:#1e40af;margin-top:28px">${fw.name} <span style="font-size:14px;color:${statusColor}">● ${fw.status?.replace('_',' ').toUpperCase()}</span></h2>
      <p>Overall Score: <strong>${fw.overallScore}%</strong> | Pass: ${fw.passCount} | Fail: ${fw.failCount} | Partial: ${fw.partialCount}</p>
      <table><tr><th>ID</th><th>Control</th><th>Status</th><th>Score</th><th>Evidence</th></tr>${controlRows}</table>`;
  }).join('');

  const scoreColor = report.securityScore >= 80 ? '#16a34a' : report.securityScore >= 50 ? '#d97706' : '#dc2626';
  const s = report.summary || {};
  const b = report.scoreBreakdown || {};

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>SOC4 Compliance Report — ${companyName}</title>
<style>
  body { font-family: Arial,sans-serif; color: #1e293b; margin: 32px; font-size: 13px; }
  h1   { font-size: 22px; color: #1e3a5f; border-bottom: 2px solid #1e3a5f; padding-bottom: 8px; }
  h2   { font-size: 15px; margin-top: 24px; }
  .meta{ color:#64748b; font-size:12px; margin-bottom:24px; }
  .score-big { font-size: 64px; font-weight: 700; color: ${scoreColor}; }
  .cards { display:flex; gap:16px; flex-wrap:wrap; margin:16px 0; }
  .card  { border:1px solid #e2e8f0; border-radius:8px; padding:14px 18px; min-width:130px; }
  .card-num { font-size:28px; font-weight:700; color:#1e40af; }
  .card-label { font-size:11px; color:#64748b; }
  table { border-collapse:collapse; width:100%; margin-top:8px; }
  th,td{ border:1px solid #e2e8f0; padding:7px 12px; text-align:left; font-size:12px; }
  th   { background:#f1f5f9; font-weight:600; }
  .badge{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
  @media print { body { margin:0; } }
</style>
</head>
<body>
<h1>🛡️ SOC4 Compliance Report</h1>
<div class="meta">
  Company: <strong>${companyName}</strong> &nbsp;|&nbsp;
  Period: ${report.periodStart?.toISOString?.()?.slice(0,10) || '—'} → ${report.periodEnd?.toISOString?.()?.slice(0,10) || '—'} &nbsp;|&nbsp;
  Generated: ${new Date(report.generatedAt || report.createdAt).toLocaleString()}
</div>

<h2>Security Score</h2>
<div class="score-big">${report.securityScore}<span style="font-size:24px">/100</span></div>
<p style="color:${scoreColor};font-weight:600;">${report.securityScore >= 80 ? '✅ GOOD' : report.securityScore >= 50 ? '⚠️ NEEDS ATTENTION' : '🔴 CRITICAL'}</p>

<h2>Score Breakdown (Deductions)</h2>
<table>
  <tr><th>Category</th><th>Count</th><th>Weight</th><th>Deduction</th></tr>
  <tr><td>File Violations</td><td>${b.fileViolations||0}</td><td>×5</td><td>${(b.fileViolations||0)*5}</td></tr>
  <tr><td>USB Violations</td><td>${b.usbViolations||0}</td><td>×10</td><td>${(b.usbViolations||0)*10}</td></tr>
  <tr><td>Network Attacks</td><td>${b.networkAttacks||0}</td><td>×5</td><td>${(b.networkAttacks||0)*5}</td></tr>
  <tr><td>Malware Events</td><td>${b.malwareEvents||0}</td><td>×15</td><td>${(b.malwareEvents||0)*15}</td></tr>
  <tr><td>Login Failures</td><td>${b.loginFailures||0}</td><td>×2</td><td>${(b.loginFailures||0)*2}</td></tr>
  <tr><td>Unresolved Critical</td><td>${b.unresolvedCritical||0}</td><td>×8</td><td>${(b.unresolvedCritical||0)*8}</td></tr>
</table>

<h2>Event Summary (Period)</h2>
<div class="cards">
  <div class="card"><div class="card-num">${s.totalAlerts||0}</div><div class="card-label">Total Alerts</div></div>
  <div class="card"><div class="card-num">${s.criticalAlerts||0}</div><div class="card-label">Critical</div></div>
  <div class="card"><div class="card-num">${s.malwareEvents||0}</div><div class="card-label">Malware</div></div>
  <div class="card"><div class="card-num">${s.networkAttacks||0}</div><div class="card-label">Network</div></div>
  <div class="card"><div class="card-num">${s.usbEvents||0}</div><div class="card-label">USB Events</div></div>
  <div class="card"><div class="card-num">${s.loginFailures||0}</div><div class="card-label">Login Failures</div></div>
  <div class="card"><div class="card-num">${s.activeSystems||0}</div><div class="card-label">Active Systems</div></div>
  <div class="card"><div class="card-num">${s.soarActionsExecuted||0}</div><div class="card-label">SOAR Actions</div></div>
</div>

${fwRows}

${(report.violations || []).length > 0 ? `
<h2>Open Violations (Top 20)</h2>
<table>
  <tr><th>Time</th><th>Severity</th><th>Category</th><th>System</th><th>Description</th></tr>
  ${report.violations.map(v => `<tr>
    <td>${new Date(v.createdAt).toLocaleString()}</td>
    <td>${v.severity}</td><td>${v.eventCategory}</td>
    <td>${v.agentName||'—'}</td><td>${v.description||'—'}</td>
  </tr>`).join('')}
</table>` : ''}

<script>window.print();</script>
</body>
</html>`;
}

module.exports = { generateComplianceReport, calculateSecurityScore, complianceReportToHtml };
