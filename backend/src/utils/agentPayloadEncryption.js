const crypto = require('crypto');
const System = require('../models/System.model');

const TRANSPORT_VERSION = 'aes-256-gcm-v1';
const TRANSPORT_HEADER = 'x-ajnat-payload-encryption';
const SYSTEM_HEADER = 'x-agent-system-id';
const ORIGINAL_CONTENT_TYPE_HEADER = 'x-ajnat-original-content-type';
const REQUEST_AAD = Buffer.from('AJNAT-AGENT-API-REQUEST-V1', 'utf8');
const RESPONSE_AAD = Buffer.from('AJNAT-AGENT-API-RESPONSE-V1', 'utf8');
const KEY_DOMAIN = Buffer.from('AJNAT-AGENT-API-AES-256-GCM-V1\0', 'utf8');

function deriveAgentTransportKey(agentKey) {
  const secret = String(agentKey || '');
  if (!secret) throw new Error('Agent transport key is unavailable');
  return crypto.createHash('sha256').update(KEY_DOMAIN).update(secret, 'utf8').digest();
}

function encryptPayload(plaintext, agentKey, aad = RESPONSE_AAD) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveAgentTransportKey(agentKey), nonce, {
    authTagLength: 16,
  });
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

function decodeField(value, name, expectedLength = 0) {
  if (typeof value !== 'string' || !value) throw new Error(`Encrypted payload ${name} is missing`);
  const decoded = Buffer.from(value, 'base64');
  if (!decoded.length || decoded.toString('base64') !== value) {
    throw new Error(`Encrypted payload ${name} is invalid`);
  }
  if (expectedLength && decoded.length !== expectedLength) {
    throw new Error(`Encrypted payload ${name} has an invalid length`);
  }
  return decoded;
}

function decryptPayload(envelope, agentKey, aad = REQUEST_AAD) {
  if (!envelope || envelope.v !== 1 || envelope.alg !== 'A256GCM') {
    throw new Error('Unsupported encrypted agent payload');
  }
  const nonce = decodeField(envelope.nonce, 'nonce', 12);
  const ciphertext = decodeField(envelope.ciphertext, 'ciphertext');
  const tag = decodeField(envelope.tag, 'tag', 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveAgentTransportKey(agentKey), nonce, {
    authTagLength: 16,
  });
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function encryptJsonPayload(value, agentKey) {
  return encryptPayload(Buffer.from(JSON.stringify(value), 'utf8'), agentKey, REQUEST_AAD);
}

function decryptJsonPayload(envelope, agentKey) {
  return JSON.parse(decryptPayload(envelope, agentKey, REQUEST_AAD).toString('utf8'));
}

function installEncryptedResponse(res, agentKey, requestNonce = '') {
  const originalSend = res.send.bind(res);
  let sendingEncrypted = false;
  const authenticateResponse = body => {
    const digest = crypto.createHash('sha256').update(body).digest('hex');
    const signature = crypto.createHmac('sha256', agentKey).update(`AJNAT-RESPONSE-V1.${requestNonce}.${res.statusCode}.${digest}`).digest('hex');
    res.setHeader('X-AJNAT-Response-SHA256', digest);
    res.setHeader('X-AJNAT-Response-Signature', signature);
  };
  res.send = function encryptedAgentResponse(body) {
    if (sendingEncrypted || body == null || res.statusCode === 204 || res.statusCode === 304) {
      return originalSend(body);
    }

    // Installer/dependency downloads are already authenticated with SHA-256 and
    // must remain directly executable. JSON/text control-plane responses are
    // protected by this application-layer envelope in addition to TLS.
    if (Buffer.isBuffer(body)) {
      authenticateResponse(body);
      return originalSend(body);
    }

    const plaintext = Buffer.from(
      typeof body === 'string' ? body : JSON.stringify(body),
      'utf8',
    );
    const encrypted = encryptPayload(plaintext, agentKey, RESPONSE_AAD);
    const wire = Buffer.from(JSON.stringify(encrypted), 'utf8');
    authenticateResponse(wire);
    const originalContentType = String(res.getHeader('Content-Type') || 'application/json; charset=utf-8');
    res.setHeader(TRANSPORT_HEADER, TRANSPORT_VERSION);
    res.setHeader(ORIGINAL_CONTENT_TYPE_HEADER, originalContentType);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', wire.length);
    res.setHeader('Cache-Control', 'no-store');
    sendingEncrypted = true;
    return originalSend(wire);
  };
}

async function agentPayloadEncryption(req, res, next) {
  if (String(req.headers[TRANSPORT_HEADER] || '').toLowerCase() !== TRANSPORT_VERSION) return next();

  try {
    const systemId = String(req.headers[SYSTEM_HEADER] || '').trim();
    if (!systemId || !/^[a-f0-9]{24}$/i.test(systemId)) {
      return res.status(400).json({ message: 'A valid encrypted-agent system id is required' });
    }
    const system = await System.findById(systemId)
      .select('+agentCertificateFingerprint256 +agentCertificateSerial +agentCertificateRevokedAt');
    if (!system?.agentKey) return res.status(404).json({ message: 'Encrypted agent identity was not found' });

    const { validateAgentCertificate } = require('./agentRequestAuth');
    const certificateError = validateAgentCertificate(req, system, {
      allowCertificateEnrollment: req.path === '/agent/certificate/enroll'
        || req.originalUrl?.split('?')[0] === '/api/agent/certificate/enroll',
    });
    if (certificateError) {
      return res.status(certificateError.status).json({ message: certificateError.message });
    }

    req.agentTransportSystem = system;
    req.agentEncryptedEnvelope = req.body;
    installEncryptedResponse(res, system.agentKey, String(req.headers['x-agent-nonce'] || ''));

    if (!['GET', 'HEAD'].includes(req.method)) {
      req.body = decryptJsonPayload(req.body, system.agentKey);
      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        return res.status(400).json({ message: 'Encrypted agent payload must contain a JSON object' });
      }
    }
    return next();
  } catch (error) {
    return res.status(400).json({ message: 'Encrypted agent payload authentication failed' });
  }
}

module.exports = {
  TRANSPORT_VERSION,
  TRANSPORT_HEADER,
  SYSTEM_HEADER,
  REQUEST_AAD,
  RESPONSE_AAD,
  deriveAgentTransportKey,
  encryptPayload,
  decryptPayload,
  encryptJsonPayload,
  decryptJsonPayload,
  agentPayloadEncryption,
};
