/* Encrypt a database/config/archive backup with the tenant's active DEK. */
require('dotenv').config();
const path = require('path');
const fs = require('fs/promises');
const connectDB = require('../src/config/db');
const Company = require('../src/models/Company.model');
const EncryptionJob = require('../src/models/EncryptionJob.model');
const { encryptFile } = require('../src/services/evidenceLocker.service');

async function main() {
  const [companyId, sourceArg, destinationArg] = process.argv.slice(2);
  if (!companyId || !sourceArg || !destinationArg) {
    throw new Error('Usage: npm run encrypt:backup -- <companyId> <input-file> <output-file>');
  }
  const sourcePath = path.resolve(sourceArg);
  const destinationPath = path.resolve(destinationArg);
  await connectDB({ maxAttempts: 1 });
  const company = await Company.findById(companyId).select('_id tenantId').lean();
  if (!company?.tenantId) throw new Error('Company/tenant scope not found');
  const job = await EncryptionJob.create({
    tenantId: company.tenantId, companyId: company._id, requestedBy: null,
    operation: 'backup', targetType: 'encrypted-backup', targetId: path.basename(destinationPath),
    sourcePath, destinationPath, totalBytes: 0, status: 'processing', startedAt: new Date(),
  });
  const result = await encryptFile({
    sourcePath, destinationPath, tenantId: company.tenantId, companyId: company._id,
    evidenceId: `backup:${job._id}`, actorId: null,
    onProgress: progress => EncryptionJob.updateOne({ _id: job._id }, { $set: progress }),
  });
  await EncryptionJob.updateOne({ _id: job._id }, { $set: {
    status: 'completed', progress: 100, completedAt: new Date(), keyId: result.keyId,
    keyVersion: result.keyVersion, totalBytes: result.sizeBytes,
  } });
  await fs.writeFile(`${destinationPath}.manifest.json`, JSON.stringify({
    format: result.format, algorithm: result.algorithm, tenantId: String(company.tenantId),
    companyId: String(company._id), evidenceId: `backup:${job._id}`, keyId: result.keyId,
    keyVersion: result.keyVersion, sizeBytes: result.sizeBytes, sha256: result.sha256,
    ciphertextSha256: result.ciphertextSha256, createdAt: new Date().toISOString(),
  }, null, 2), { mode: 0o600 });
  console.log(JSON.stringify({ output: destinationPath, ...result }, null, 2));
  await require('mongoose').disconnect();
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
