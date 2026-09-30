const zlib = require('zlib');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const Alert = require('../models/Alert.model');
const Log = require('../models/Log.model');
const Company = require('../models/Company.model');
const { DAY_MS, normalizeRetention } = require('../utils/retentionPolicy');

function archiveEnabled() {
  return process.env.ARCHIVE_ENABLED === 'true';
}

function archiveKey({ tenantId, companyId, kind, date, batchId }) {
  const time = new Date(date);
  const parts = [time.getUTCFullYear(), String(time.getUTCMonth() + 1).padStart(2, '0'), String(time.getUTCDate()).padStart(2, '0'), String(time.getUTCHours()).padStart(2, '0')];
  return `tenant=${tenantId}/company=${companyId}/kind=${kind}/year=${parts[0]}/month=${parts[1]}/day=${parts[2]}/hour=${parts[3]}/${batchId}.ndjson.gz`;
}

function s3Client() {
  const options = { region: process.env.ARCHIVE_S3_REGION || 'us-east-1' };
  if (process.env.ARCHIVE_S3_ENDPOINT) options.endpoint = process.env.ARCHIVE_S3_ENDPOINT;
  if (process.env.ARCHIVE_S3_FORCE_PATH_STYLE === 'true') options.forcePathStyle = true;
  return new S3Client(options);
}

async function archiveDocuments({ model, company, kind, timeField, client, now = new Date() }) {
  const policy = normalizeRetention(company.retentionPolicy);
  if (!policy.archiveEnabled || policy.legalHold) return { archived: 0 };
  const cutoff = new Date(now.getTime() - policy.hotDays * DAY_MS);
  const limit = Math.max(1, Math.min(5000, Number(process.env.ARCHIVE_BATCH_SIZE || 1000)));
  const documents = await model.find({
    companyId: company._id,
    archivedAt: null,
    [timeField]: { $lte: cutoff },
  }).sort({ [timeField]: 1, _id: 1 }).limit(limit).lean();
  if (!documents.length) return { archived: 0 };

  const firstTime = documents[0][timeField] || documents[0].createdAt;
  const batchId = `${new Date(firstTime).getTime()}-${documents[0]._id}-${documents.at(-1)._id}`;
  const key = archiveKey({ tenantId: company.tenantId || 'none', companyId: company._id, kind, date: firstTime, batchId });
  const body = zlib.gzipSync(Buffer.from(documents.map(doc => JSON.stringify(doc)).join('\n') + '\n'));
  await client.send(new PutObjectCommand({
    Bucket: process.env.ARCHIVE_S3_BUCKET,
    Key: key,
    Body: body,
    ContentType: 'application/x-ndjson',
    ContentEncoding: 'gzip',
    Metadata: { count: String(documents.length), schema: '1' },
  }));
  await model.updateMany(
    { _id: { $in: documents.map(doc => doc._id) }, archivedAt: null },
    { $set: { archivedAt: now, archiveKey: key } },
  );
  return { archived: documents.length, bytes: body.length, key };
}

async function runArchiveCycle({ client = s3Client(), now = new Date() } = {}) {
  if (!archiveEnabled()) return { disabled: true, archived: 0 };
  if (!process.env.ARCHIVE_S3_BUCKET) throw new Error('ARCHIVE_S3_BUCKET is required when archival is enabled');
  const companies = await Company.find({ 'retentionPolicy.archiveEnabled': true, 'retentionPolicy.legalHold': { $ne: true } })
    .select('_id tenantId retentionPolicy').lean();
  const summary = { companies: companies.length, alerts: 0, logs: 0, bytes: 0 };
  for (const company of companies) {
    const alertResult = await archiveDocuments({ model: Alert, company, kind: 'alert', timeField: 'createdAt', client, now });
    const logResult = await archiveDocuments({ model: Log, company, kind: 'log', timeField: 'receivedAt', client, now });
    summary.alerts += alertResult.archived || 0;
    summary.logs += logResult.archived || 0;
    summary.bytes += (alertResult.bytes || 0) + (logResult.bytes || 0);
  }
  return summary;
}

module.exports = { archiveEnabled, archiveKey, archiveDocuments, runArchiveCycle };
