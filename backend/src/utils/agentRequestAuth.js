const crypto = require('crypto');
const System = require('../models/System.model');

const WINDOW_MS = Number(process.env.AGENT_SIGNATURE_WINDOW_MS || 5 * 60 * 1000);
const REQUIRE_SIGNED = process.env.AGENT_REQUIRE_SIGNED !== 'false';
const { claimNonce } = require('../infrastructure/nonceStore');

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function captureSignedJsonBody(req, _res, buffer) {
  if (String(req.headers['x-agent-signature-version'] || '') === '2') {
    req.rawAgentBody = buffer;
  }
}

function signedRequestPayload(req, timestamp, nonce) {
  const version = String(req.headers['x-agent-signature-version'] || '1');
  if (version === '1') {
    const signedBody = req.agentEncryptedEnvelope || req.body || {};
    return `${timestamp}.${nonce}.${canonicalize(signedBody)}`;
  }
  if (version === '2') {
    if (!Buffer.isBuffer(req.rawAgentBody)) return null;
    return `${timestamp}.${nonce}.${req.rawAgentBody.toString('utf8')}`;
  }
  return null;
}

function getAgentKeyFromBody(body = {}) {
  return body.agent_key || body.agentKey || body.agent_id || body.agentId || body.alerts?.[0]?.agent_key || body.alerts?.[0]?.agentKey || '';
}

function validateAgentCertificate(req, system, options = {}) {
  const mtlsEnabled = process.env.AGENT_MTLS_ENABLED === 'true'
    || process.env.AGENT_MTLS_REQUIRED === 'true';
  if (!mtlsEnabled) return null;

  const certificate = req.socket?.getPeerCertificate?.();
  const fingerprint = String(certificate?.fingerprint256 || '').replace(/:/g, '').toLowerCase();
  const pinned = String(system.agentCertificateFingerprint256 || '').replace(/:/g, '').toLowerCase();
  if (!req.socket?.encrypted || !fingerprint) {
    return { status: 401, message: 'An AJNAT agent client certificate is required' };
  }
  if (system.agentCertificateRevokedAt) {
    return { status: 401, message: 'AJNAT agent certificate has been revoked' };
  }
  if (process.env.AGENT_MTLS_REQUIRE_CA_VALIDATION === 'true' && !req.socket.authorized) {
    return { status: 401, message: 'AJNAT agent certificate chain is not trusted' };
  }
  const peerExpiry = certificate?.valid_to ? new Date(certificate.valid_to) : null;
  if (peerExpiry && (!Number.isFinite(peerExpiry.getTime()) || peerExpiry <= new Date())) {
    return { status: 401, message: 'AJNAT agent certificate has expired' };
  }
  if (options.allowCertificateEnrollment === true) {
    if (pinned && fingerprint !== pinned) {
      return { status: 409, message: 'A different AJNAT certificate is already enrolled' };
    }
    return null;
  }
  if (!pinned) {
    return { status: 401, message: 'AJNAT agent certificate is not enrolled' };
  }
  const fingerprintBuffer = Buffer.from(fingerprint, 'utf8');
  const pinnedBuffer = Buffer.from(pinned, 'utf8');
  if (fingerprintBuffer.length !== pinnedBuffer.length
      || !crypto.timingSafeEqual(fingerprintBuffer, pinnedBuffer)) {
    return { status: 401, message: 'Agent certificate pin validation failed' };
  }
  return null;
}

async function verifySignedAgentRequest(req, options = {}) {
  const encryptedSystem = req.agentTransportSystem || null;
  const agentKey = encryptedSystem?.agentKey || options.agentKey || getAgentKeyFromBody(req.body);
  if (!agentKey) return { ok: false, status: 400, message: 'agent_key required' };

  const system = encryptedSystem || await System.findOne({ agentKey })
    .select('+agentCertificateFingerprint256 +agentCertificateSerial +agentCertificateRevokedAt');
  if (!system) return { ok: false, status: 404, message: 'Unknown agent key' };

  const certificateError = validateAgentCertificate(req, system, options);
  if (certificateError) return { ok: false, ...certificateError };

  const signature = String(req.headers['x-agent-signature'] || '');
  const timestamp = String(req.headers['x-agent-timestamp'] || '');
  const nonce = String(req.headers['x-agent-nonce'] || '');

  if (!signature || !timestamp || !nonce) {
    if (!REQUIRE_SIGNED) return { ok: true, system, legacy: true };
    return { ok: false, status: 401, message: 'Signed agent request required' };
  }

  const tsMs = Number(timestamp) * 1000;
  const now = Date.now();
  if (!Number.isFinite(tsMs) || Math.abs(now - tsMs) > WINDOW_MS) {
    return { ok: false, status: 401, message: 'Agent request timestamp expired' };
  }

  const nonceKey = `${agentKey}:${nonce}`;

  const payload = signedRequestPayload(req, timestamp, nonce);
  if (payload == null) {
    return { ok: false, status: 400, message: 'Unsupported or unavailable agent signature version' };
  }
  const expected = crypto.createHmac('sha256', agentKey).update(payload).digest('hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  const actualBuf = Buffer.from(signature, 'hex');
  if (actualBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(actualBuf, expectedBuf)) {
    return { ok: false, status: 401, message: 'Invalid agent signature' };
  }

  try {
    const claimed = await claimNonce(nonceKey, WINDOW_MS, now);
    if (!claimed) return { ok: false, status: 409, message: 'Replay detected' };
  } catch {
    return { ok: false, status: 503, message: 'Replay protection unavailable' };
  }
  return { ok: true, system };
}

module.exports = {
  captureSignedJsonBody,
  canonicalize,
  signedRequestPayload,
  validateAgentCertificate,
  verifySignedAgentRequest,
};
