const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const WEB_TRANSPORT_VERSION = 'aes-256-gcm-rsa-oaep-v1';
const WEB_TRANSPORT_HEADER = 'x-ajnat-web-encryption';
const WRAPPED_KEY_HEADER = 'x-ajnat-wrapped-key';
const ORIGINAL_CONTENT_TYPE_HEADER = 'x-ajnat-original-content-type';
const REQUEST_AAD = Buffer.from('AJNAT-WEB-API-REQUEST-V1', 'utf8');
const META_AAD = Buffer.from('AJNAT-WEB-API-METADATA-V1', 'utf8');
const RESPONSE_AAD = Buffer.from('AJNAT-WEB-API-RESPONSE-V1', 'utf8');

let transportKeys;

function normalizePem(value) {
  return String(value || '').replace(/\\n/g, '\n').trim();
}

function loadOrCreateDevelopmentPrivateKey() {
  const secretDir = path.resolve(__dirname, '../../.runtime-secrets');
  const secretFile = path.join(secretDir, 'web-transport-private.pem');
  fs.mkdirSync(secretDir, { recursive: true, mode: 0o700 });

  try {
    return normalizePem(fs.readFileSync(secretFile, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicExponent: 0x10001,
  });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const temporaryFile = `${secretFile}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;

  // linkSync gives independently started API processes one atomic winner. All
  // other processes then load the same completed key instead of retaining the
  // key they generated during the race.
  fs.writeFileSync(temporaryFile, pem, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  try {
    fs.linkSync(temporaryFile, secretFile);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  } finally {
    fs.unlinkSync(temporaryFile);
  }
  return normalizePem(fs.readFileSync(secretFile, 'utf8'));
}

function getTransportKeys() {
  if (transportKeys) return transportKeys;
  const privateKeyFile = String(process.env.WEB_TRANSPORT_PRIVATE_KEY_FILE || '').trim();
  let configuredPrivateKey = normalizePem(process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM);
  if (!configuredPrivateKey && privateKeyFile) {
    try {
      configuredPrivateKey = normalizePem(fs.readFileSync(privateKeyFile, 'utf8'));
    } catch (error) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error(`Unable to read WEB_TRANSPORT_PRIVATE_KEY_FILE: ${error.message}`);
      }
      console.warn(`[web-transport] Private key file is unavailable; using the local persistent development key (${privateKeyFile})`);
    }
  }
  if (!configuredPrivateKey && process.env.NODE_ENV !== 'production') {
    configuredPrivateKey = loadOrCreateDevelopmentPrivateKey();
  }
  let privateKey;
  let publicKey;
  let ephemeral = false;
  if (configuredPrivateKey) {
    privateKey = crypto.createPrivateKey(configuredPrivateKey);
    publicKey = crypto.createPublicKey(privateKey);
  } else {
    ({ privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 3072,
      publicExponent: 0x10001,
    }));
    ephemeral = true;
  }
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const keyId = crypto.createHash('sha256').update(publicKeyPem).digest('hex').slice(0, 24);
  transportKeys = { privateKey, publicKeyPem, keyId, ephemeral };
  return transportKeys;
}

// Cluster workers must use the same transport private key. Without an
// explicitly configured key, each worker would otherwise generate its own
// ephemeral pair: a browser could fetch the public key from worker A and send
// the encrypted request to worker B, where RSA unwrap would always fail.
// Call this once in the cluster primary before forking so the generated PEM is
// inherited by every worker through the environment.
function ensureSharedTransportKeyEnvironment() {
  if (normalizePem(process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM)) {
    return getTransportKeys().keyId;
  }

  const { privateKey, keyId } = getTransportKeys();
  process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM = privateKey.export({
    type: 'pkcs8',
    format: 'pem',
  }).toString();
  return keyId;
}

function decodeBase64(value, label, expectedLength = 0) {
  if (typeof value !== 'string' || !value) throw new Error(`${label} is missing`);
  const decoded = Buffer.from(value, 'base64');
  if (!decoded.length || decoded.toString('base64') !== value) throw new Error(`${label} is invalid`);
  if (expectedLength && decoded.length !== expectedLength) throw new Error(`${label} has an invalid length`);
  return decoded;
}

function unwrapSessionKey(wrappedValue) {
  const key = crypto.privateDecrypt({
    key: getTransportKeys().privateKey,
    oaepHash: 'sha256',
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
  }, decodeBase64(wrappedValue, 'Wrapped transport key'));
  if (key.length !== 32) throw new Error('Wrapped transport key is not AES-256');
  return key;
}

function encryptWebPayload(plaintext, key, aad = RESPONSE_AAD) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error('AES-256 key must contain 32 bytes');
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  return {
    v: 1,
    alg: 'A256GCM',
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

function decryptWebPayload(envelope, key, aad = REQUEST_AAD) {
  if (!envelope || envelope.v !== 1 || envelope.alg !== 'A256GCM') {
    throw new Error('Unsupported encrypted web payload');
  }
  const nonce = decodeBase64(envelope.nonce, 'Web payload nonce', 12);
  const ciphertext = decodeBase64(envelope.ciphertext, 'Web payload ciphertext');
  const tag = decodeBase64(envelope.tag, 'Web payload tag', 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function installEncryptedResponse(res, key) {
  const originalSend = res.send.bind(res);
  let sendingEncrypted = false;
  res.send = function encryptedWebResponse(body) {
    if (sendingEncrypted || body == null || res.statusCode === 204 || res.statusCode === 304) {
      return originalSend(body);
    }
    // Executables, archives, PDFs, images, and other binary downloads keep
    // their native bytes. This middleware protects structured JSON/text APIs.
    if (Buffer.isBuffer(body)) return originalSend(body);

    const plaintext = Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
    const wire = Buffer.from(JSON.stringify(encryptWebPayload(plaintext, key, RESPONSE_AAD)), 'utf8');
    const originalContentType = String(res.getHeader('Content-Type') || 'application/json; charset=utf-8');
    res.setHeader(WEB_TRANSPORT_HEADER, WEB_TRANSPORT_VERSION);
    res.setHeader(ORIGINAL_CONTENT_TYPE_HEADER, originalContentType);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', wire.length);
    res.setHeader('Cache-Control', 'no-store');
    sendingEncrypted = true;
    return originalSend(wire);
  };
}

async function webPayloadEncryption(req, res, next) {
  if (String(req.headers[WEB_TRANSPORT_HEADER] || '').toLowerCase() !== WEB_TRANSPORT_VERSION) return next();
  try {
    const key = unwrapSessionKey(String(req.headers[WRAPPED_KEY_HEADER] || ''));
    installEncryptedResponse(res, key);

    const encryptedMeta = String(req.headers['x-ajnat-encrypted-meta'] || '');
    if (encryptedMeta) {
      const metaEnvelope = JSON.parse(Buffer.from(encryptedMeta, 'base64').toString('utf8'));
      const meta = JSON.parse(decryptWebPayload(metaEnvelope, key, META_AAD).toString('utf8'));
      if (meta.authorization) req.headers.authorization = String(meta.authorization);
      if (meta.params && typeof meta.params === 'object' && !Array.isArray(meta.params)) {
        req.query = { ...req.query, ...meta.params };
      }
    }

    // body-parser may expose an empty POST as `{}` even when no bytes were sent.
    // Only authenticate/decrypt a body when the HTTP request actually carried
    // one; encrypted metadata (including Authorization) remains mandatory.
    const contentLength = Number(req.headers['content-length'] || 0);
    const hasWireBody = contentLength > 0 || Boolean(req.headers['transfer-encoding']);
    // FormData carries native multipart bytes, with authentication encrypted in
    // metadata above. Express can initialize req.body to {} before multer runs;
    // that placeholder is not a JSON encryption envelope. Leave the stream for
    // the route's upload parser while keeping response encryption installed.
    const contentType = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
    const isMultipart = contentType === 'multipart/form-data';
    if (!isMultipart && !['GET', 'HEAD'].includes(req.method) && hasWireBody && req.body && typeof req.body === 'object') {
      const decrypted = JSON.parse(decryptWebPayload(req.body, key, REQUEST_AAD).toString('utf8'));
      req.body = Object.prototype.hasOwnProperty.call(decrypted, 'value') ? decrypted.value : decrypted;
    }
    return next();
  } catch {
    return res.status(400).json({ message: 'Encrypted API payload authentication failed' });
  }
}

function publicKeyResponse(_req, res) {
  const { publicKeyPem, keyId } = getTransportKeys();
  res.setHeader('Content-Type', 'application/x-pem-file; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-AJNAT-Transport-Key-Id', keyId);
  return res.send(publicKeyPem);
}

module.exports = {
  WEB_TRANSPORT_VERSION,
  WEB_TRANSPORT_HEADER,
  WRAPPED_KEY_HEADER,
  REQUEST_AAD,
  META_AAD,
  RESPONSE_AAD,
  getTransportKeys,
  ensureSharedTransportKeyEnvironment,
  unwrapSessionKey,
  encryptWebPayload,
  decryptWebPayload,
  webPayloadEncryption,
  publicKeyResponse,
};
