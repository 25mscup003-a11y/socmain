const crypto = require('crypto');

const AES_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const PBKDF2_ITERATIONS = 600_000;

function randomBytes(size) {
  if (!Number.isSafeInteger(size) || size < 1) throw new TypeError('A positive random byte length is required');
  return crypto.randomBytes(size);
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

function normalizeKey(key) {
  const material = Buffer.isBuffer(key) ? Buffer.from(key) : Buffer.from(String(key || ''), 'base64');
  if (material.length !== AES_KEY_BYTES) {
    material.fill(0);
    throw new Error('AES-256 requires exactly 32 bytes of key material');
  }
  return material;
}

function aadBuffer(context) {
  return Buffer.from(typeof context === 'string' ? context : canonicalize(context), 'utf8');
}

function encryptAes256Gcm(plaintext, key, context = {}) {
  const material = normalizeKey(key);
  const iv = randomBytes(GCM_IV_BYTES);
  const aad = aadBuffer(context);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', material, iv, { authTagLength: GCM_TAG_BYTES });
    cipher.setAAD(aad);
    const input = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
    return {
      algorithm: 'AES-256-GCM',
      iv: iv.toString('base64'),
      authTag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      aadSha256: sha256(aad),
    };
  } finally {
    material.fill(0);
  }
}

function decryptAes256Gcm(envelope, key, context = {}) {
  if (!envelope || envelope.algorithm !== 'AES-256-GCM') throw new Error('Unsupported encryption envelope');
  const material = normalizeKey(key);
  const iv = Buffer.from(envelope.iv || '', 'base64');
  const tag = Buffer.from(envelope.authTag || '', 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext || '', 'base64');
  const aad = aadBuffer(context);
  if (iv.length !== GCM_IV_BYTES || tag.length !== GCM_TAG_BYTES) {
    material.fill(0);
    throw new Error('Invalid AES-256-GCM nonce or authentication tag');
  }
  if (envelope.aadSha256 && !timingSafeHexEqual(envelope.aadSha256, sha256(aad))) {
    material.fill(0);
    throw new Error('Encryption context mismatch');
  }
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', material, iv, { authTagLength: GCM_TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } finally {
    material.fill(0);
  }
}

function derivePbkdf2Key(passphrase, salt, options = {}) {
  const iterations = Number(options.iterations || PBKDF2_ITERATIONS);
  if (iterations < 310_000) throw new Error('PBKDF2 iteration count is below the approved minimum');
  const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt || ''), 'base64');
  if (saltBuffer.length < 16) throw new Error('PBKDF2 salt must contain at least 128 bits');
  return crypto.pbkdf2Sync(String(passphrase), saltBuffer, iterations, AES_KEY_BYTES, 'sha512');
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function sha512(data) {
  return crypto.createHash('sha512').update(data).digest('hex');
}

function hmacSha256(data, key) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

function timingSafeHexEqual(left, right) {
  if (!/^[a-f\d]+$/i.test(String(left || '')) || !/^[a-f\d]+$/i.test(String(right || ''))) return false;
  const a = Buffer.from(left, 'hex');
  const b = Buffer.from(right, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function verifyPublicKeySignature({ data, signature, publicKey, algorithm = 'RSA-PSS-SHA512' }) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  const sig = Buffer.from(String(signature || ''), 'base64');
  if (algorithm === 'RSA-PSS-SHA512') {
    return crypto.verify('sha512', input, {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    }, sig);
  }
  if (algorithm === 'ECDSA-SHA512') return crypto.verify('sha512', input, publicKey, sig);
  throw new Error('Only RSA-PSS-SHA512 and ECDSA-SHA512 signatures are supported');
}

module.exports = {
  AES_KEY_BYTES,
  GCM_IV_BYTES,
  GCM_TAG_BYTES,
  PBKDF2_ITERATIONS,
  randomBytes,
  canonicalize,
  encryptAes256Gcm,
  decryptAes256Gcm,
  derivePbkdf2Key,
  sha256,
  sha512,
  hmacSha256,
  timingSafeHexEqual,
  verifyPublicKeySignature,
};
