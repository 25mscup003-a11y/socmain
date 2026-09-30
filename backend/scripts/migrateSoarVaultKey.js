require('dotenv').config();
const crypto = require('crypto');
const mongoose = require('mongoose');
const SoarCredential = require('../src/models/SoarCredential.model');

const keyFor = value => crypto.createHash('sha256').update(value).digest();

function decrypt(record, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(record.authTag, 'hex'));
  return decipher.update(record.encryptedValue, 'hex', 'utf8') + decipher.final('utf8');
}

function encrypt(value, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encryptedValue = cipher.update(value, 'utf8', 'hex') + cipher.final('hex');
  return { encryptedValue, iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex') };
}

async function main() {
  if (!process.env.MONGO_URI || !process.env.SOAR_VAULT_SECRET) {
    throw new Error('MONGO_URI and SOAR_VAULT_SECRET are required');
  }
  const currentKey = keyFor(process.env.SOAR_VAULT_SECRET);
  const legacyKey = keyFor('soc-soar-vault-secret-key-2026');
  await mongoose.connect(process.env.MONGO_URI);
  const credentials = await SoarCredential.find({}).select('+encryptedValue +iv +authTag');
  let migrated = 0;
  let alreadyCurrent = 0;
  let unreadable = 0;
  for (const credential of credentials) {
    try {
      decrypt(credential, currentKey);
      alreadyCurrent += 1;
      continue;
    } catch {}
    try {
      const plaintext = decrypt(credential, legacyKey);
      Object.assign(credential, encrypt(plaintext, currentKey));
      await credential.save();
      migrated += 1;
    } catch {
      unreadable += 1;
    }
  }
  console.log(JSON.stringify({ total: credentials.length, migrated, alreadyCurrent, unreadable }));
  await mongoose.disconnect();
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
