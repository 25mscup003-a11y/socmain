const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { Writable } = require('node:stream');

const {
  PBKDF2_ITERATIONS,
  decryptAes256Gcm,
  derivePbkdf2Key,
  encryptAes256Gcm,
  hmacSha256,
  sha256,
  sha512,
  verifyPublicKeySignature,
} = require('../src/security/cryptoPrimitives');
const { LocalFileKeyProvider } = require('../src/services/keyProvider.service');
const { ROLE_PERMISSIONS, requireEncryptionPermission } = require('../src/middleware/encryptionAccess');
const argon2 = require('argon2');
const bcrypt = require('bcryptjs');
const User = require('../src/models/User.model');

test('AES-256-GCM round trips and uses a unique 96-bit nonce', () => {
  const key = crypto.randomBytes(32);
  const context = { tenantId: 'tenant-a', companyId: 'company-a', purpose: 'test' };
  const first = encryptAes256Gcm('classified', key, context);
  const second = encryptAes256Gcm('classified', key, context);

  assert.equal(first.algorithm, 'AES-256-GCM');
  assert.equal(Buffer.from(first.iv, 'base64').length, 12);
  assert.notEqual(first.iv, second.iv);
  assert.equal(decryptAes256Gcm(first, key, context).toString(), 'classified');
});

test('AES-256-GCM rejects ciphertext, tag and tenant-context tampering', () => {
  const key = crypto.randomBytes(32);
  const context = { tenantId: 'tenant-a', companyId: 'company-a', purpose: 'secret' };
  const envelope = encryptAes256Gcm('do not alter', key, context);
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  ciphertext[0] ^= 0x01;

  assert.throws(
    () => decryptAes256Gcm({ ...envelope, ciphertext: ciphertext.toString('base64') }, key, context),
  );
  assert.throws(
    () => decryptAes256Gcm(envelope, key, { ...context, tenantId: 'tenant-b' }),
    /context mismatch/,
  );
  const tag = Buffer.from(envelope.authTag, 'base64');
  tag[tag.length - 1] ^= 0x01;
  assert.throws(() => decryptAes256Gcm({ ...envelope, authTag: tag.toString('base64') }, key, context));
});

test('approved hashes, HMAC and PBKDF2-SHA512 produce deterministic output', () => {
  assert.equal(sha256('abc'), crypto.createHash('sha256').update('abc').digest('hex'));
  assert.equal(sha512('abc'), crypto.createHash('sha512').update('abc').digest('hex'));
  assert.equal(hmacSha256('abc', 'key'), crypto.createHmac('sha256', 'key').update('abc').digest('hex'));
  const salt = crypto.randomBytes(16);
  const one = derivePbkdf2Key('correct horse battery staple', salt);
  const two = derivePbkdf2Key('correct horse battery staple', salt, { iterations: PBKDF2_ITERATIONS });
  assert.equal(one.length, 32);
  assert.deepEqual(one, two);
  assert.throws(() => derivePbkdf2Key('password', Buffer.alloc(8), { iterations: 600_000 }), /salt/);
  assert.throws(() => derivePbkdf2Key('password', salt, { iterations: 1000 }), /iteration/);
  one.fill(0); two.fill(0); salt.fill(0);
});

test('RSA-4096 PSS and ECC signatures are validated and tampering is rejected', () => {
  const data = Buffer.from('signed security event');
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 4096, publicExponent: 0x10001 });
  const rsaSignature = crypto.sign('sha512', data, {
    key: rsa.privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
  });
  assert.equal(rsa.publicKey.asymmetricKeyDetails.modulusLength, 4096);
  assert.equal(verifyPublicKeySignature({
    data,
    signature: rsaSignature.toString('base64'),
    publicKey: rsa.publicKey,
    algorithm: 'RSA-PSS-SHA512',
  }), true);
  assert.equal(verifyPublicKeySignature({
    data: 'tampered',
    signature: rsaSignature.toString('base64'),
    publicKey: rsa.publicKey,
    algorithm: 'RSA-PSS-SHA512',
  }), false);

  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  const ecSignature = crypto.sign('sha512', data, ec.privateKey);
  assert.equal(verifyPublicKeySignature({
    data,
    signature: ecSignature.toString('base64'),
    publicKey: ec.publicKey,
    algorithm: 'ECDSA-SHA512',
  }), true);
});

test('local KEK provider wraps DEKs with authenticated context', async () => {
  const master = crypto.randomBytes(32);
  const dek = crypto.randomBytes(32);
  const provider = new LocalFileKeyProvider({
    testingKey: master.toString('base64'),
    keyReference: 'test:kek-1',
  });
  const context = { tenantId: 'tenant-a', keyId: 'dek-1', version: '1' };
  const wrapped = await provider.wrapKey(dek, context);
  const clear = await provider.unwrapKey(wrapped, context);
  assert.deepEqual(clear, dek);
  await assert.rejects(() => provider.unwrapKey(wrapped, { ...context, tenantId: 'tenant-b' }), /context mismatch/);
  master.fill(0); dek.fill(0); clear.fill(0);
});

test('local KEK provider creates and reuses a protected development key when the configured secret mount is absent', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ajnat-kms-development-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const missingMountedKey = path.join(directory, 'missing-mount', 'ajnat-kms-master-key');
  const developmentKeyFile = path.join(directory, 'runtime', 'ajnat-kms-master-key');
  const context = { tenantId: 'tenant-dev', keyId: 'dek-dev', version: '1' };
  const dek = crypto.randomBytes(32);

  const firstProvider = new LocalFileKeyProvider({ keyFile: missingMountedKey, developmentKeyFile });
  const wrapped = await firstProvider.wrapKey(dek, context);
  const secondProvider = new LocalFileKeyProvider({ keyFile: missingMountedKey, developmentKeyFile });
  const clear = await secondProvider.unwrapKey(wrapped, context);

  assert.deepEqual(clear, dek);
  assert.equal((await fs.stat(developmentKeyFile)).mode & 0o077, 0);
  dek.fill(0); clear.fill(0);
});

test('encryption RBAC denies analysts without explicit cryptographic permission', () => {
  assert.ok(ROLE_PERMISSIONS.superadmin.includes('key_manage'));
  assert.ok(ROLE_PERMISSIONS.soc_manager.includes('approve'));
  assert.ok(ROLE_PERMISSIONS.company_admin.includes('decrypt'));
  assert.ok(!ROLE_PERMISSIONS.company_admin.includes('approve'));
  assert.ok(!ROLE_PERMISSIONS.l1_analyst);

  let status;
  let payload;
  const middleware = requireEncryptionPermission('decrypt');
  middleware({ user: { role: 'l1_analyst' } }, {
    status(code) { status = code; return this; },
    json(value) { payload = value; },
  }, () => assert.fail('unauthorized middleware must not call next'));
  assert.equal(status, 403);
  assert.match(payload.message, /permission/);
});

test('password verification supports Argon2id and upgrades a legacy bcrypt hash', async () => {
  const password = 'A-strong-password-2026!';
  const argonHash = await argon2.hash(password, {
    type: argon2.argon2id, memoryCost: 8192, timeCost: 2, parallelism: 1,
  });
  const argonUser = new User({ name: 'Argon User', email: 'argon@example.test', password: argonHash });
  argonUser.$__.activePaths.clearPath('password');
  assert.equal(await argonUser.comparePassword(password), true);
  assert.equal(await argonUser.comparePassword('wrong'), false);

  const legacyHash = await bcrypt.hash(password, 10);
  const legacyUser = new User({ name: 'Legacy User', email: 'legacy@example.test', password: legacyHash });
  legacyUser.$__.activePaths.clearPath('password');
  let saved = false;
  legacyUser.save = async function saveUpgrade() {
    saved = true;
    this.password = await argon2.hash(this.password, {
      type: argon2.argon2id, memoryCost: 8192, timeCost: 2, parallelism: 1,
    });
    return this;
  };
  assert.equal(await legacyUser.comparePassword(password), true);
  assert.equal(saved, true);
  assert.match(legacyUser.password, /^\$argon2id\$/);
  assert.equal(await argon2.verify(legacyUser.password, password), true);
});

test('chunked evidence container round trips and rejects a modified frame', async (t) => {
  const tenantKms = require('../src/services/tenantKms.service');
  const TenantEncryptionKey = require('../src/models/TenantEncryptionKey.model');
  const originalActive = tenantKms.activeTenantKey;
  const originalUnwrap = tenantKms._unwrapRecord;
  const originalFindOne = TenantEncryptionKey.findOne;
  const dek = crypto.randomBytes(32);
  const keyRecord = { keyId: 'dek-evidence-1', version: 1, wrappedKey: {} };
  tenantKms.activeTenantKey = async () => keyRecord;
  tenantKms._unwrapRecord = async () => Buffer.from(dek);
  TenantEncryptionKey.findOne = () => ({ select: async () => keyRecord });
  delete require.cache[require.resolve('../src/services/evidenceLocker.service')];
  const { MAGIC, encryptFile, decryptFileToWritable } = require('../src/services/evidenceLocker.service');

  t.after(() => {
    tenantKms.activeTenantKey = originalActive;
    tenantKms._unwrapRecord = originalUnwrap;
    TenantEncryptionKey.findOne = originalFindOne;
    delete require.cache[require.resolve('../src/services/evidenceLocker.service')];
    dek.fill(0);
  });

  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'ajnat-evidence-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const source = path.join(directory, 'source.bin');
  const encrypted = path.join(directory, 'evidence.ajev');
  const clear = crypto.randomBytes(192 * 1024 + 37);
  await fs.writeFile(source, clear, { mode: 0o600 });
  const result = await encryptFile({
    sourcePath: source,
    destinationPath: encrypted,
    tenantId: '507f1f77bcf86cd799439011',
    companyId: '507f1f77bcf86cd799439012',
    evidenceId: 'EVD-test',
  });
  assert.equal(result.algorithm, 'AES-256-GCM');
  assert.equal(result.sha256, sha256(clear));

  const chunks = [];
  const sink = new Writable({ write(chunk, _encoding, done) { chunks.push(Buffer.from(chunk)); done(); } });
  await decryptFileToWritable({
    sourcePath: encrypted,
    writable: sink,
    tenantId: '507f1f77bcf86cd799439011',
    companyId: '507f1f77bcf86cd799439012',
    evidenceId: 'EVD-test',
    keyId: keyRecord.keyId,
    expectedSha256: result.sha256,
  });
  assert.deepEqual(Buffer.concat(chunks), clear);

  const container = await fs.readFile(encrypted);
  container[MAGIC.length + 4 + 4 + 12 + 16] ^= 0x01;
  await fs.writeFile(encrypted, container);
  await assert.rejects(() => decryptFileToWritable({
    sourcePath: encrypted,
    writable: new Writable({ write(_chunk, _encoding, done) { done(); } }),
    tenantId: '507f1f77bcf86cd799439011',
    companyId: '507f1f77bcf86cd799439012',
    evidenceId: 'EVD-test',
    keyId: keyRecord.keyId,
    expectedSha256: result.sha256,
  }));
  clear.fill(0);
});
