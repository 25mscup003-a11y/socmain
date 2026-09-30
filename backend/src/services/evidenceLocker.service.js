const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { activeTenantKey, _unwrapRecord } = require('./tenantKms.service');
const { encryptAes256Gcm, decryptAes256Gcm } = require('../security/cryptoPrimitives');

const MAGIC = Buffer.from('AJNEV001');
const HEADER_BYTES = MAGIC.length + 4;
const FRAME_HEADER_BYTES = 4 + 12 + 16;
const DEFAULT_CHUNK_BYTES = Math.max(64 * 1024, Number(process.env.EVIDENCE_CHUNK_BYTES || 4 * 1024 * 1024));

function evidenceContext(scope, evidenceId, chunkIndex, plainLength) {
  return {
    tenantId: String(scope.tenantId),
    companyId: String(scope.companyId || ''),
    purpose: 'forensic-evidence-file',
    evidenceId: String(evidenceId),
    chunkIndex: String(chunkIndex),
    plainLength: String(plainLength),
  };
}

async function hashFile(filename, algorithm = 'sha256') {
  const digest = crypto.createHash(algorithm);
  for await (const chunk of fs.createReadStream(filename)) digest.update(chunk);
  return digest.digest('hex');
}

async function encryptFile({ sourcePath, destinationPath, tenantId, companyId, evidenceId, actorId, resume = null, onProgress = null }) {
  const source = await fsp.stat(sourcePath);
  if (!source.isFile()) throw new Error('Evidence source must be a regular file');
  await fsp.mkdir(path.dirname(destinationPath), { recursive: true, mode: 0o700 });
  const keyRecord = await activeTenantKey(tenantId, actorId);
  const dek = await _unwrapRecord(keyRecord);
  const chunkSize = DEFAULT_CHUNK_BYTES;
  let sourceOffset = Number(resume?.bytesProcessed || 0);
  let outputOffset = Number(resume?.outputBytes || 0);
  let chunkIndex = Number(resume?.chunksCompleted || 0);
  const canResume = sourceOffset > 0 && outputOffset >= HEADER_BYTES && await fsp.stat(destinationPath).then(s => s.isFile() && s.size >= outputOffset).catch(() => false);
  if (!canResume) {
    sourceOffset = 0;
    outputOffset = 0;
    chunkIndex = 0;
  }
  const input = await fsp.open(sourcePath, 'r');
  const output = await fsp.open(destinationPath, canResume ? 'r+' : 'w', 0o600);
  try {
    if (!canResume) {
      const header = Buffer.alloc(HEADER_BYTES);
      MAGIC.copy(header, 0);
      header.writeUInt32BE(chunkSize, MAGIC.length);
      await output.write(header, 0, header.length, 0);
      outputOffset = header.length;
    } else {
      await output.truncate(outputOffset);
    }
    while (sourceOffset < source.size) {
      const length = Math.min(chunkSize, source.size - sourceOffset);
      const clear = Buffer.allocUnsafe(length);
      const { bytesRead } = await input.read(clear, 0, length, sourceOffset);
      if (!bytesRead) break;
      const chunk = bytesRead === clear.length ? clear : clear.subarray(0, bytesRead);
      const encrypted = encryptAes256Gcm(chunk, dek, evidenceContext({ tenantId, companyId }, evidenceId, chunkIndex, bytesRead));
      const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
      const frame = Buffer.alloc(FRAME_HEADER_BYTES);
      frame.writeUInt32BE(bytesRead, 0);
      Buffer.from(encrypted.iv, 'base64').copy(frame, 4);
      Buffer.from(encrypted.authTag, 'base64').copy(frame, 16);
      await output.write(frame, 0, frame.length, outputOffset);
      outputOffset += frame.length;
      await output.write(ciphertext, 0, ciphertext.length, outputOffset);
      outputOffset += ciphertext.length;
      sourceOffset += bytesRead;
      chunkIndex += 1;
      clear.fill(0);
      if (onProgress) await onProgress({
        bytesProcessed: sourceOffset,
        totalBytes: source.size,
        chunksCompleted: chunkIndex,
        outputBytes: outputOffset,
        progress: source.size ? Math.floor((sourceOffset / source.size) * 100) : 100,
      });
    }
    await output.sync();
    return {
      format: 'AJNAT-EVIDENCE-V1',
      algorithm: 'AES-256-GCM',
      keyId: keyRecord.keyId,
      keyVersion: keyRecord.version,
      chunks: chunkIndex,
      sizeBytes: source.size,
      sha256: await hashFile(sourcePath, 'sha256'),
      ciphertextSha256: await hashFile(destinationPath, 'sha256'),
    };
  } finally {
    dek.fill(0);
    await input.close();
    await output.close();
  }
}

async function decryptFileToWritable({ sourcePath, writable, tenantId, companyId, evidenceId, keyId, expectedSha256 = '' }) {
  const keyRecord = await require('../models/TenantEncryptionKey.model')
    .findOne({ tenantId, keyId }).select('+wrappedKey');
  if (!keyRecord) throw new Error('Evidence encryption key is unavailable in this tenant');
  const dek = await _unwrapRecord(keyRecord);
  const input = await fsp.open(sourcePath, 'r');
  const digest = crypto.createHash('sha256');
  let position = 0;
  let chunkIndex = 0;
  try {
    const header = Buffer.alloc(HEADER_BYTES);
    const headerRead = await input.read(header, 0, HEADER_BYTES, position);
    if (headerRead.bytesRead !== HEADER_BYTES || !header.subarray(0, MAGIC.length).equals(MAGIC)) {
      throw new Error('Invalid encrypted evidence container');
    }
    const chunkSize = header.readUInt32BE(MAGIC.length);
    if (chunkSize < 64 * 1024 || chunkSize > 64 * 1024 * 1024) throw new Error('Unsafe evidence chunk size');
    position += HEADER_BYTES;
    const size = (await input.stat()).size;
    while (position < size) {
      const frame = Buffer.alloc(FRAME_HEADER_BYTES);
      const frameRead = await input.read(frame, 0, frame.length, position);
      if (frameRead.bytesRead !== frame.length) throw new Error('Truncated evidence frame');
      position += frame.length;
      const plainLength = frame.readUInt32BE(0);
      if (plainLength <= 0 || plainLength > chunkSize) throw new Error('Invalid evidence frame length');
      const ciphertext = Buffer.allocUnsafe(plainLength);
      const bodyRead = await input.read(ciphertext, 0, plainLength, position);
      if (bodyRead.bytesRead !== plainLength) throw new Error('Truncated evidence ciphertext');
      position += plainLength;
      const clear = decryptAes256Gcm({
        algorithm: 'AES-256-GCM',
        iv: frame.subarray(4, 16).toString('base64'),
        authTag: frame.subarray(16, 32).toString('base64'),
        ciphertext: ciphertext.toString('base64'),
      }, dek, evidenceContext({ tenantId, companyId }, evidenceId, chunkIndex, plainLength));
      digest.update(clear);
      if (!writable.write(clear)) await new Promise(resolve => writable.once('drain', resolve));
      clear.fill(0);
      ciphertext.fill(0);
      chunkIndex += 1;
    }
    const actualHash = digest.digest('hex');
    if (expectedSha256 && actualHash !== expectedSha256) throw new Error('Evidence plaintext integrity verification failed');
    return { sha256: actualHash, chunks: chunkIndex };
  } finally {
    dek.fill(0);
    await input.close();
  }
}

module.exports = { MAGIC, DEFAULT_CHUNK_BYTES, encryptFile, decryptFileToWritable, hashFile, evidenceContext };
