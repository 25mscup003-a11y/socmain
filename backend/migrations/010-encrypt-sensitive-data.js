/*
 * Rolling migration for legacy plaintext/TOTP and legacy global SOAR vault
 * ciphertext into tenant-scoped AES-256-GCM envelopes.
 *
 * Run only after configuring KMS_PROVIDER and the appropriate KEK provider.
 * The migration is idempotent and deliberately does not delete legacy fields
 * until each replacement envelope has been saved successfully.
 */
require('dotenv').config();
const connectDB = require('../src/config/db');
const User = require('../src/models/User.model');
const SoarCredential = require('../src/models/SoarCredential.model');
const { setTwoFactorSecret } = require('../src/services/userSecrets.service');
const { encryptTenantSecret, decryptSecret } = require('../src/services/soarConnector.service');

async function run() {
  await connectDB({ maxAttempts: 1 });
  let users = 0;
  let credentials = 0;

  for await (const user of User.find({ twoFactorSecret: { $nin: [null, ''] }, twoFactorSecretEncrypted: null })
    .select('+twoFactorSecret +twoFactorSecretEncrypted')) {
    await setTwoFactorSecret(user, user.twoFactorSecret);
    await user.save();
    users += 1;
  }

  for await (const credential of SoarCredential.find({
    encrypted: null,
    encryptedValue: { $nin: [null, ''] },
    tenantId: { $ne: null },
  }).select('+encryptedValue +iv +authTag +encrypted')) {
    const plaintext = decryptSecret(credential.encryptedValue, credential.iv, credential.authTag);
    credential.encrypted = await encryptTenantSecret(plaintext, credential);
    credential.encryptedValue = '';
    credential.iv = '';
    credential.authTag = '';
    credential.version = Number(credential.version || 1) + 1;
    credential.rotatedAt = new Date();
    await credential.save();
    credentials += 1;
  }

  console.log(JSON.stringify({ migratedUsers: users, migratedSoarCredentials: credentials }, null, 2));
  await require('mongoose').disconnect();
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
