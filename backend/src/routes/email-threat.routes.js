const router = require('express').Router();
const mongoose = require('mongoose');
const net = require('net');
const { authenticate, requireAnalyst, requireCompanyAdmin } = require('../middleware/auth.middleware');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const threatIntel = require('../services/threat-intel.service');
const virusTotal = require('../services/virustotal.service');
const { createResponse } = require('../services/automatedResponse.service');
const { emailCapabilityFilter } = require('../utils/capabilityOverview');

const EMAIL_FILTER = {
  isSynthetic: { $ne: true },
  ...emailCapabilityFilter(),
};

const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));
const companyScope = req => ({
  companyId: new mongoose.Types.ObjectId(String(req.user.companyId?._id || req.user.companyId)),
  ...(req.user.departmentId ? { departmentId: new mongoose.Types.ObjectId(req.user.departmentId) } : {}),
});
const periodStart = value => {
  const hours = integer(value, 24, 1, 24 * 365);
  return new Date(Date.now() - hours * 60 * 60 * 1000);
};
const eventTime = row => row.eventTimestamp || row.createdAt;
const field = (row, ...names) => names.map(name => row?.[name]).find(value => value !== undefined && value !== null && value !== '') || '';
const csvCell = value => `"${String(value ?? '').replace(/"/g, '""')}"`;
const xmlCell = value => String(value ?? '').replace(/[<>&"']/g, char => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[char]));
function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No email threat records found']);
  const objects = [];
  const pageIds = pages.map((_, index) => 4 + index * 2);
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pages.length} >>`;
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  pages.forEach((pageLines, index) => {
    const pageId = pageIds[index];
    const contentId = pageId + 1;
    const content = `BT /F1 8 Tf 30 810 Td 11 TL ${pageLines.map(line => `(${safe(line)}) Tj T*`).join(' ')} ET`;
    objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`;
    objects[contentId] = `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`;
  });
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (let id = 1; id < objects.length; id += 1) { offsets[id] = Buffer.byteLength(pdf); pdf += `${id} 0 obj\n${objects[id]}\nendobj\n`; }
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id += 1) pdf += `${String(offsets[id]).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf);
}

async function writeAudit(req, action, event, metadata = {}) {
  const tenantId = req.user.tenantId || event?.tenantId;
  const actorId = req.user.id || req.user._id;
  if (!tenantId || !actorId) return;
  await SocAuditEvent.create({
    tenantId, companyId: event?.companyId || req.user.companyId, actorId, action,
    targetType: 'EmailThreat', targetId: String(event?._id || ''), metadata,
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}
const classificationText = { $toLower: { $concat: [
  { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$threatCategory', ''] }, ' ',
  { $ifNull: ['$description', ''] }, ' ', { $ifNull: ['$eventType', ''] },
] } };
const matches = regex => ({ $regexMatch: { input: classificationText, regex } });
const sumWhen = expression => ({ $sum: { $cond: [expression, 1, 0] } });
const emailQuery = req => {
  const query = { ...companyScope(req), ...EMAIL_FILTER };
  query.$nor = [{
    ruleId: /^EMAIL_WEBMAIL_LINK_OPEN$/i,
    url: /(?:localhost|127\.0\.0\.1|\/company-admin\/edr)/i,
  }];
  const from = req.query.from ? new Date(req.query.from) : periodStart(req.query.windowHours || req.query.hours);
  const to = req.query.to ? new Date(req.query.to) : null;
  query.createdAt = { $gte: Number.isNaN(from.getTime()) ? periodStart(24) : from };
  if (to && !Number.isNaN(to.getTime())) query.createdAt.$lte = to;
  if (req.query.severity && ['low', 'medium', 'high', 'critical'].includes(req.query.severity)) query.severity = req.query.severity;
  if (req.query.status && ['open', 'investigating', 'resolved', 'false_positive', 'under_observation'].includes(req.query.status)) query.status = req.query.status;
  if (req.query.hostname) query.hostname = new RegExp(`^${escapeRegex(req.query.hostname)}$`, 'i');
  if (req.query.user) {
    const user = new RegExp(escapeRegex(req.query.user), 'i');
    query.$and = [...(query.$and || []), { $or: [{ username: user }, { emailRecipient: user }, { emailSender: user }] }];
  }
  if (req.query.threatType) query.threatCategory = new RegExp(escapeRegex(req.query.threatType), 'i');
  if (req.query.domain) query.domain = new RegExp(`^${escapeRegex(req.query.domain)}$`, 'i');
  if (req.query.search) {
    const search = new RegExp(escapeRegex(req.query.search).slice(0, 200), 'i');
    query.$and = [...(query.$and || []), { $or: [{ description: search }, { ruleId: search }, { hostname: search }, { username: search }, { emailSender: search }, { emailRecipient: search }, { emailSubject: search }, { domain: search }, { url: search }, { fileName: search }, { fileHash: search }] }];
  }
  return query;
};

router.use(authenticate, requireAnalyst);

router.get('/dashboard', async (req, res) => {
  try {
    const query = emailQuery(req);
    const [summary = {}, timeline, threats, users, senders, domains, compromisedMailboxes, usersUnderAttack] = await Promise.all([
      Alert.aggregate([{ $match: query }, { $group: {
        _id: null,
        totalEmails: { $sum: 1 },
        incomingEmails: sumWhen({ $eq: ['$emailDirection', 'incoming'] }),
        outgoingEmails: sumWhen({ $eq: ['$emailDirection', 'outgoing'] }),
        blockedEmails: sumWhen({ $or: [{ $eq: ['$blocked', true] }, { $in: ['$actionTaken', ['Blocked', 'Deleted']] }] }),
        quarantinedEmails: sumWhen({ $eq: ['$quarantined', true] }),
        spamEmails: sumWhen(matches('spam')),
        phishingEmails: sumWhen(matches('phish')),
        attachmentDownloads: sumWhen(matches('attachment.download|email.attachment.downloaded')),
        maliciousAttachments: sumWhen(matches('attachment.malware|malicious.attachment|suspicious.attachment|macro|payload')),
        credentialPhishing: sumWhen(matches('credential|fake.login|harvest')),
        becAttacks: sumWhen(matches('business.email.compromise|bec|wire.fraud')),
        spoofedEmails: sumWhen(matches('spoof')),
        spfFailures: sumWhen(matches('spf.*fail')),
        dkimFailures: sumWhen(matches('dkim.*fail')),
        dmarcFailures: sumWhen(matches('dmarc.*fail|dmarc.*reject')),
        highSeverityThreats: sumWhen({ $in: ['$severity', ['high', 'critical']] }),
        mediumSeverity: sumWhen({ $eq: ['$severity', 'medium'] }),
        lowSeverity: sumWhen({ $eq: ['$severity', 'low'] }),
        attachmentMalware: sumWhen(matches('attachment.malware|malicious.attachment|email.payload')),
        suspiciousUrls: sumWhen(matches('suspicious.url|email.url|link.open|typosquat')),
        dataLeakAttempts: sumWhen(matches('data.leak|exfil|large.file.sent|cloud.upload')),
        averageRiskScore: { $avg: { $ifNull: ['$riskScore', 0] } },
      } }]),
      Alert.aggregate([{ $match: query }, { $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, count: { $sum: 1 } } }, { $sort: { _id: 1 } }]),
      Alert.aggregate([{ $match: query }, { $group: { _id: { $ifNull: ['$threatCategory', '$ruleId'] }, count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      Alert.aggregate([{ $match: query }, { $group: { _id: '$username', count: { $sum: 1 }, maxRisk: { $max: '$riskScore' } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      Alert.aggregate([{ $match: query }, { $group: { _id: '$emailSender', count: { $sum: 1 } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      Alert.aggregate([{ $match: query }, { $group: { _id: '$domain', count: { $sum: 1 } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      Alert.distinct('username', { ...query, mailboxEventType: { $nin: [null, ''] }, severity: { $in: ['high', 'critical'] } }),
      Alert.distinct('username', { ...query, username: { $nin: [null, ''] }, severity: { $in: ['medium', 'high', 'critical'] } }),
    ]);
    res.json({
      summary: { ...summary, _id: undefined, total: summary.totalEmails || 0, blocked: summary.blockedEmails || 0, quarantined: summary.quarantinedEmails || 0, usersUnderAttack: usersUnderAttack.length, compromisedMailboxes: compromisedMailboxes.length },
      timeline, topThreatTypes: threats, topTargetedUsers: users, topSenders: senders,
      topMaliciousDomains: domains, generatedAt: new Date(),
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/live', async (req, res) => {
  try {
    const rows = await Alert.find(emailQuery(req)).sort({ createdAt: -1 }).limit(integer(req.query.limit, 100, 1, 500)).lean();
    res.json({ events: rows, total: rows.length, realtimeEvent: 'email:event' });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/logs', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 100000);
    const limit = integer(req.query.limit, 100, 1, 500);
    const query = emailQuery(req);
    const [events, total] = await Promise.all([
      Alert.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Alert.countDocuments(query),
    ]);
    res.json({ events, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/log/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), ...EMAIL_FILTER }).lean();
    if (!event) return res.status(404).json({ message: 'Email threat event not found' });
    res.json({ event });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

const facet = (path, extra = {}) => async (req, res) => {
  try {
    const query = { $and: [emailQuery(req), extra] };
    const events = await Alert.find(query).sort({ createdAt: -1 }).limit(integer(req.query.limit, 200, 1, 500)).lean();
    res.json({ [path]: events, total: events.length });
  } catch (error) { res.status(500).json({ message: error.message }); }
};
router.get('/attachments', facet('attachments', { $and: [{ $or: [{ fileName: { $nin: [null, ''] } }, { fileHash: { $nin: [null, ''] } }, { ruleId: /ATTACH|MACRO|YARA/i }] }] }));
router.get('/urls', facet('urls', { $and: [{ $or: [{ url: { $nin: [null, ''] } }, { domain: { $nin: [null, ''] } }, { ruleId: /URL|LINK|TYPOSQUAT/i }] }] }));
router.get('/authentication', facet('authentication', { ruleId: /SPF|DKIM|DMARC|SPOOF/i }));
router.get('/mailbox', facet('mailboxEvents', { ruleId: /MAILBOX|OAUTH|FORWARD|DELEGAT|BULK_MAIL/i }));
router.get('/threat-intelligence', facet('matches', { $or: [{ vtVerdict: { $in: ['malicious', 'suspicious'] } }, { threatCategory: { $nin: [null, ''] } }, { reputationScore: { $gt: 0 } }] }));
router.get('/quarantine', facet('quarantine', { $or: [{ quarantined: true }, { containmentStatus: 'quarantined' }] }));
router.get('/alerts', facet('alerts', { severity: { $in: ['medium', 'high', 'critical'] } }));
router.get('/settings', (req, res) => res.json({
  capabilityId: 15,
  endpointCollection: {
    enabled: true,
    scope: ['mail client processes', 'mail service processes', 'webmail URL metadata', 'download metadata', 'email-context child processes'],
    excluded: ['message bodies', 'cookies', 'passwords', 'browser form fields'],
    pollingSeconds: Math.max(10, Number(process.env.EMAIL_MONITOR_INTERVAL_SECONDS) || 30),
  },
  integrations: {
    virustotal: virusTotal.isEnabled(),
    abuseIpDb: Boolean(process.env.ABUSEIPDB_KEY),
    alienVaultOtx: Boolean(process.env.OTX_API_KEY),
  },
}));

router.get('/reports', async (req, res) => {
  try {
    const events = await Alert.find(emailQuery(req)).sort({ createdAt: -1 }).limit(integer(req.query.limit, 5000, 1, 10000)).lean();
    res.json({ events, total: events.length, filters: req.query, generatedAt: new Date() });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/scan', requireCompanyAdmin, async (req, res) => {
  const indicator = String(req.body.indicator || '').trim().slice(0, 2048);
  if (!indicator) return res.status(400).json({ message: 'indicator is required' });
  try {
    let result;
    let type;
    if (/^https?:\/\//i.test(indicator)) {
      type = 'url'; result = await virusTotal.scanUrl(indicator);
    } else if (/^[a-f0-9]{32,64}$/i.test(indicator)) {
      type = 'hash'; result = await virusTotal.scanHash(indicator);
    } else if (net.isIP(indicator)) {
      type = 'ip'; result = await threatIntel.enrichIp(indicator);
    } else if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(indicator)) {
      type = 'domain'; result = await threatIntel.enrichDomain(indicator);
    } else {
      return res.status(400).json({ message: 'indicator must be a URL, IP address, domain, MD5, SHA-1, or SHA-256 hash' });
    }
    await writeAudit(req, 'email-threat.indicator.scan', null, { type, indicator });
    res.json({ queued: false, indicator, type, result: result || { verdict: 'unknown', reason: 'No configured provider returned a result' } });
  } catch (error) { res.status(502).json({ message: error.message }); }
});

async function updateThreat(req, res, action) {
  if (!mongoose.isValidObjectId(req.body.alertId)) return res.status(400).json({ message: 'Valid alertId is required' });
  const set = action === 'quarantine' ? { quarantined: true, action: 'quarantined', actionTaken: 'Quarantined', containmentStatus: 'quarantined' }
    : action === 'block' ? { blocked: true, action: 'blocked', actionTaken: 'Blocked', containmentStatus: 'blocked' }
      : { status: 'false_positive', action: 'allowed', actionTaken: 'Allowed', containmentStatus: 'allowed' };
  const event = await Alert.findOneAndUpdate({ _id: req.body.alertId, ...companyScope(req), ...EMAIL_FILTER }, { $set: set }, { new: true });
  if (!event) return res.status(404).json({ message: 'Email threat event not found' });
  let response = null;
  const system = event.systemId
    ? await System.findOne({ _id: event.systemId, companyId: event.companyId }).lean()
    : null;
  if (action === 'quarantine' && event.filePath && system) {
    response = await createResponse({
      companyId: event.companyId, tenantId: event.tenantId, alert: event, system,
      actionType: 'quarantine_file', actionParams: { path: event.filePath },
      triggeredBy: req.user.id || req.user._id, trigger: 'manual', io: req.app.get('io'), forceApproval: true,
    });
  } else if (action === 'block' && system && (event.domain || event.srcip)) {
    const actionType = event.domain ? 'block_domain' : 'block_ip';
    const actionParams = event.domain ? { domain: event.domain } : { ip: event.srcip };
    response = await createResponse({
      companyId: event.companyId, tenantId: event.tenantId, alert: event, system,
      actionType, actionParams, triggeredBy: req.user.id || req.user._id,
      trigger: 'manual', io: req.app.get('io'), forceApproval: true,
    });
  }
  await writeAudit(req, `email-threat.${action}`, event, { responseId: response?._id || null, responseStatus: response?.status || null });
  const leanEvent = event.toObject();
  req.app.get('io')?.to(`company:${req.user.companyId}`).emit('email:event', { action, event: leanEvent });
  res.json({ action, event: leanEvent, response });
}
router.post('/quarantine', requireCompanyAdmin, (req, res) => updateThreat(req, res, 'quarantine').catch(error => res.status(500).json({ message: error.message })));
router.post('/block', requireCompanyAdmin, (req, res) => updateThreat(req, res, 'block').catch(error => res.status(500).json({ message: error.message })));
router.post('/whitelist', requireCompanyAdmin, (req, res) => updateThreat(req, res, 'whitelist').catch(error => res.status(500).json({ message: error.message })));

router.post('/export', async (req, res) => {
  try {
    const format = String(req.body.format || 'csv').toLowerCase();
    const events = await Alert.find(emailQuery({ user: req.user, query: req.body.filters || {} })).sort({ createdAt: -1 }).limit(10000).lean();
    if (format === 'json') return res.json({ events, total: events.length, generatedAt: new Date() });
    const columns = ['Timestamp', 'Host', 'Username', 'Sender', 'Recipient', 'Subject', 'Threat Type', 'Severity', 'Status', 'Source IP', 'Destination IP', 'Attachment', 'URL', 'Hash', 'Risk Score', 'MITRE', 'Action'];
    const rows = events.map(row => [eventTime(row), row.hostname, row.username, row.emailSender, row.emailRecipient, row.emailSubject, field(row, 'threatCategory', 'ruleId'), row.severity, row.status, row.srcip, row.destip, row.fileName, row.url, row.fileHash, row.riskScore, field(row, 'mitreId', 'mitreTechnique'), field(row, 'actionTaken', 'action')]);
    if (format === 'csv') {
      return res.type('text/csv').attachment(`email-threat-report-${Date.now()}.csv`).send([columns.map(csvCell).join(','), ...rows.map(row => row.map(csvCell).join(','))].join('\n'));
    }
    if (['excel', 'xls', 'xlsx'].includes(format)) {
      const table = [columns, ...rows].map(row => `<Row>${row.map(value => `<Cell><Data ss:Type="String">${xmlCell(value)}</Data></Cell>`).join('')}</Row>`).join('');
      const workbook = `<?xml version="1.0"?><Workbook xmlns="urn:schemas-microsoft-com:office:spreadsheet" xmlns:ss="urn:schemas-microsoft-com:office:spreadsheet"><Worksheet ss:Name="Email Threats"><Table>${table}</Table></Worksheet></Workbook>`;
      return res.type('application/vnd.ms-excel').attachment(`email-threat-report-${Date.now()}.xls`).send(workbook);
    }
    if (format === 'pdf') {
      const lines = ['AJNAT SOC - Email Threat Monitoring Report', `Generated: ${new Date().toISOString()}`, `Records: ${events.length}`, '', ...rows.map(row => row.map(value => String(value ?? '')).join(' | '))];
      return res.type('application/pdf').attachment(`email-threat-report-${Date.now()}.pdf`).send(buildPdf(lines));
    }
    return res.status(400).json({ message: 'Supported server export formats: csv, excel, pdf, json' });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

module.exports = router;
