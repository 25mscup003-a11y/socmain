/* Controlled recovery utility for an AJNAT encrypted backup container. */
require('dotenv').config();
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const connectDB = require('../src/config/db');
const { decryptFileToWritable, hashFile } = require('../src/services/evidenceLocker.service');

async function main() {
  const [encryptedArg, manifestArg, destinationArg] = process.argv.slice(2);
  if (!encryptedArg || !manifestArg || !destinationArg) {
    throw new Error('Usage: npm run decrypt:backup -- <encrypted-file> <manifest.json> <output-file>');
  }
  const sourcePath = path.resolve(encryptedArg);
  const manifest = JSON.parse(await fsp.readFile(path.resolve(manifestArg), 'utf8'));
  const encryptedHash = await hashFile(sourcePath, 'sha256');
  if (encryptedHash !== manifest.ciphertextSha256) throw new Error('Encrypted backup integrity verification failed');
  await connectDB({ maxAttempts: 1 });
  const destinationPath = path.resolve(destinationArg);
  const output = fs.createWriteStream(destinationPath, { mode: 0o600, flags: 'wx' });
  try {
    await decryptFileToWritable({
      sourcePath, writable: output, tenantId: manifest.tenantId, companyId: manifest.companyId,
      evidenceId: manifest.evidenceId, keyId: manifest.keyId, expectedSha256: manifest.sha256,
    });
    output.end();
    await new Promise((resolve, reject) => { output.once('finish', resolve); output.once('error', reject); });
    console.log(`Recovered and verified backup: ${destinationPath}`);
  } catch (error) {
    output.destroy();
    await fsp.unlink(destinationPath).catch(() => {});
    throw error;
  } finally {
    await require('mongoose').disconnect();
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
