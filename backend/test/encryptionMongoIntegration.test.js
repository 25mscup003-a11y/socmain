const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const integrationUri = process.env.MONGO_INTEGRATION_URI;

test('tenant KMS rotation, isolation and immutable audit chain', {
  skip: !integrationUri && 'Set MONGO_INTEGRATION_URI to run the MongoDB cryptography integration test',
}, async () => {
  process.env.NODE_ENV = 'test';
  process.env.KMS_PROVIDER = 'local-file';
  process.env.KMS_MASTER_KEY_B64 = crypto.randomBytes(32).toString('base64');
  process.env.ENCRYPTION_AUDIT_KEY = crypto.randomBytes(32).toString('base64');

  const mongoose = require('mongoose');
  await mongoose.connect(integrationUri, { dbName: `ajnat_crypto_test_${process.pid}` });
  const TenantEncryptionKey = require('../src/models/TenantEncryptionKey.model');
  const EncryptionAudit = require('../src/models/EncryptionAudit.model');
  const EncryptionAuditCounter = require('../src/models/EncryptionAuditCounter.model');
  const { encryptValue, decryptValue, rotateTenantKey, revokeTenantKey } = require('../src/services/tenantKms.service');
  const { appendEncryptionAudit, verifyAuditChain } = require('../src/services/encryptionAudit.service');

  try {
    const tenantA = new mongoose.Types.ObjectId();
    const tenantB = new mongoose.Types.ObjectId();
    const companyA = new mongoose.Types.ObjectId();
    const companyB = new mongoose.Types.ObjectId();
    const recordId = new mongoose.Types.ObjectId();
    const envelope = await encryptValue({
      tenantId: tenantA, companyId: companyA, purpose: 'integration-secret', recordId, value: { token: 'secret' },
    });
    assert.deepEqual(await decryptValue({
      tenantId: tenantA, companyId: companyA, purpose: 'integration-secret', recordId, envelope,
    }), { token: 'secret' });
    await assert.rejects(() => decryptValue({
      tenantId: tenantB, companyId: companyA, purpose: 'integration-secret', recordId, envelope,
    }), /unavailable/);
    await assert.rejects(() => decryptValue({
      tenantId: tenantA, companyId: companyB, purpose: 'integration-secret', recordId, envelope,
    }), /context mismatch|authenticate/i);

    const oldKeyId = envelope.keyId;
    const newKey = await rotateTenantKey({ tenantId: tenantA });
    assert.notEqual(newKey.keyId, oldKeyId);
    assert.deepEqual(await decryptValue({
      tenantId: tenantA, companyId: companyA, purpose: 'integration-secret', recordId, envelope,
    }), { token: 'secret' });
    await revokeTenantKey({ tenantId: tenantA, keyId: oldKeyId, reason: 'integration test' });
    await assert.rejects(() => decryptValue({
      tenantId: tenantA, companyId: companyA, purpose: 'integration-secret', recordId, envelope,
    }), /revoked/);

    await Promise.all(Array.from({ length: 8 }, (_, index) => appendEncryptionAudit({
      tenantId: tenantA,
      actorRole: 'system',
      action: 'integration_test',
      outcome: 'success',
      targetType: 'test',
      targetId: String(index),
    })));
    assert.deepEqual(await verifyAuditChain(tenantA), {
      valid: true,
      checked: 8,
      headHash: (await EncryptionAudit.findOne({ tenantId: tenantA }).sort({ sequence: -1 }).lean()).entryHash,
    });
    await assert.rejects(() => EncryptionAudit.updateOne({ tenantId: tenantA }, { $set: { reason: 'tampered' } }));
  } finally {
    await Promise.all([
      TenantEncryptionKey.deleteMany({}),
      EncryptionAudit.collection.deleteMany({}),
      EncryptionAuditCounter.deleteMany({}),
    ]);
    await mongoose.disconnect();
    delete process.env.KMS_MASTER_KEY_B64;
    delete process.env.ENCRYPTION_AUDIT_KEY;
  }
});
