const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  REQUEST_AAD,
  META_AAD,
  RESPONSE_AAD,
  getTransportKeys,
  ensureSharedTransportKeyEnvironment,
  unwrapSessionKey,
  encryptWebPayload,
  decryptWebPayload,
  webPayloadEncryption,
} = require('../src/utils/webPayloadEncryption');

test('cluster primary can publish one transport key for all workers', () => {
  const previous = process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM;
  delete process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM;
  try {
    const expectedKeyId = getTransportKeys().keyId;
    assert.equal(ensureSharedTransportKeyEnvironment(), expectedKeyId);
    assert.match(process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM, /BEGIN PRIVATE KEY/);

    const inheritedPrivateKey = crypto.createPrivateKey(process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM);
    const inheritedPublicPem = crypto.createPublicKey(inheritedPrivateKey)
      .export({ type: 'spki', format: 'pem' }).toString();
    const inheritedKeyId = crypto.createHash('sha256')
      .update(inheritedPublicPem).digest('hex').slice(0, 24);
    assert.equal(inheritedKeyId, expectedKeyId);
  } finally {
    if (previous === undefined) delete process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM;
    else process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM = previous;
  }
});

test('browser session key is RSA-OAEP wrapped and AES-256 sized', () => {
  const sessionKey = crypto.randomBytes(32);
  const { publicKeyPem } = getTransportKeys();
  const wrapped = crypto.publicEncrypt({
    key: publicKeyPem,
    oaepHash: 'sha256',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  }, sessionKey).toString('base64');

  assert.deepEqual(unwrapSessionKey(wrapped), sessionKey);
});

test('web API payload is AES-256-GCM encrypted and context authenticated', () => {
  const key = crypto.randomBytes(32);
  const plaintext = Buffer.from(JSON.stringify({ company: 'rru', secret: 'hidden' }));
  const envelope = encryptWebPayload(plaintext, key, RESPONSE_AAD);

  assert.equal(envelope.alg, 'A256GCM');
  assert.doesNotMatch(JSON.stringify(envelope), /rru|hidden/);
  assert.deepEqual(decryptWebPayload(envelope, key, RESPONSE_AAD), plaintext);
  assert.throws(() => decryptWebPayload(envelope, key, REQUEST_AAD));
});

test('web middleware restores encrypted auth/query/body and seals response JSON', async () => {
  const key = crypto.randomBytes(32);
  const { publicKeyPem } = getTransportKeys();
  const wrappedKey = crypto.publicEncrypt({
    key: publicKeyPem,
    oaepHash: 'sha256',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  }, key).toString('base64');
  const metadata = encryptWebPayload(Buffer.from(JSON.stringify({
    authorization: 'Bearer private-token', params: { windowHours: '24' },
  })), key, META_AAD);
  const body = encryptWebPayload(Buffer.from(JSON.stringify({ value: { secret: 'hidden-body' } })), key, REQUEST_AAD);
  const headers = new Map();
  let wireBody;
  const req = {
    method: 'POST', query: {}, body,
    headers: {
      'x-ajnat-web-encryption': 'aes-256-gcm-rsa-oaep-v1',
      'x-ajnat-wrapped-key': wrappedKey,
      'x-ajnat-encrypted-meta': Buffer.from(JSON.stringify(metadata)).toString('base64'),
      'content-length': '256',
    },
  };
  const res = {
    statusCode: 200,
    setHeader(name, value) { headers.set(name.toLowerCase(), String(value)); },
    getHeader(name) { return headers.get(name.toLowerCase()); },
    status(code) { this.statusCode = code; return this; },
    send(value) { wireBody = value; return this; },
    json(value) {
      this.setHeader('Content-Type', 'application/json; charset=utf-8');
      return this.send(JSON.stringify(value));
    },
  };
  await new Promise((resolve, reject) => {
    Promise.resolve(webPayloadEncryption(req, res, resolve)).catch(reject);
  });

  assert.equal(req.headers.authorization, 'Bearer private-token');
  assert.deepEqual(req.query, { windowHours: '24' });
  assert.deepEqual(req.body, { secret: 'hidden-body' });
  res.json({ company: 'rru', private: true });
  const wireText = Buffer.from(wireBody).toString('utf8');
  assert.doesNotMatch(wireText, /rru|private/);
  assert.deepEqual(
    JSON.parse(decryptWebPayload(JSON.parse(wireText), key, RESPONSE_AAD).toString('utf8')),
    { company: 'rru', private: true },
  );
});

test('web middleware accepts an encrypted metadata-only POST with no wire body', async () => {
  const key = crypto.randomBytes(32);
  const { publicKeyPem } = getTransportKeys();
  const wrappedKey = crypto.publicEncrypt({
    key: publicKeyPem,
    oaepHash: 'sha256',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  }, key).toString('base64');
  const metadata = encryptWebPayload(Buffer.from(JSON.stringify({
    authorization: 'Bearer update-token', params: {},
  })), key, META_AAD);
  const req = {
    method: 'POST', query: {}, body: {},
    headers: {
      'x-ajnat-web-encryption': 'aes-256-gcm-rsa-oaep-v1',
      'x-ajnat-wrapped-key': wrappedKey,
      'x-ajnat-encrypted-meta': Buffer.from(JSON.stringify(metadata)).toString('base64'),
      'content-length': '0',
    },
  };
  const res = {
    statusCode: 200,
    setHeader() {},
    getHeader() { return undefined; },
    status(code) { this.statusCode = code; return this; },
    send() { return this; },
    json() { return this; },
  };
  let continued = false;
  await new Promise((resolve, reject) => {
    Promise.resolve(webPayloadEncryption(req, res, () => {
      continued = true;
      resolve();
    })).catch(reject);
  });

  assert.equal(continued, true);
  assert.equal(req.headers.authorization, 'Bearer update-token');
  assert.deepEqual(req.body, {});
});
