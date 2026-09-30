const test = require('node:test');
const assert = require('node:assert/strict');

const {
  canonicalize,
  captureSignedJsonBody,
  signedRequestPayload,
  validateAgentCertificate,
} = require('../src/utils/agentRequestAuth');

function withMtlsEnvironment(run) {
  const previousEnabled = process.env.AGENT_MTLS_ENABLED;
  const previousRequired = process.env.AGENT_MTLS_REQUIRED;
  process.env.AGENT_MTLS_ENABLED = 'true';
  delete process.env.AGENT_MTLS_REQUIRED;
  try { run(); } finally {
    if (previousEnabled === undefined) delete process.env.AGENT_MTLS_ENABLED;
    else process.env.AGENT_MTLS_ENABLED = previousEnabled;
    if (previousRequired === undefined) delete process.env.AGENT_MTLS_REQUIRED;
    else process.env.AGENT_MTLS_REQUIRED = previousRequired;
  }
}

test('legacy signature payload remains backward compatible', () => {
  const req = {
    body: { z: [3, 'x'], risk: 80, a: { b: true, a: null } },
    headers: {},
  };
  assert.equal(
    signedRequestPayload(req, '100', 'nonce'),
    '100.nonce.{"a":{"a":null,"b":true},"risk":80,"z":[3,"x"]}',
  );
});

test('v2 signature authenticates exact JSON bytes without 64-bit integer rounding', () => {
  const raw = Buffer.from('{"version_code":9223372036854775807,"agent_key":"key"}', 'utf8');
  const req = {
    headers: { 'x-agent-signature-version': '2' },
    // JSON.parse necessarily rounds this value. V2 must not sign the parsed form.
    body: JSON.parse(raw.toString('utf8')),
  };
  captureSignedJsonBody(req, null, raw);

  assert.equal(
    signedRequestPayload(req, '100', 'nonce'),
    `100.nonce.${raw.toString('utf8')}`,
  );
  assert.notEqual(canonicalize(req.body), raw.toString('utf8'));
});

test('v2 signature fails closed when raw body capture is unavailable', () => {
  const req = { headers: { 'x-agent-signature-version': '2' }, body: { ok: true } };
  assert.equal(signedRequestPayload(req, '100', 'nonce'), null);
});

test('mTLS certificate must match the fingerprint pinned to the agent', () => {
  withMtlsEnvironment(() => {
    const fingerprint = 'ab'.repeat(32);
    const request = {
      socket: {
        encrypted: true,
        authorized: false,
        getPeerCertificate: () => ({
          fingerprint256: fingerprint.match(/.{2}/g).join(':'),
          valid_to: new Date(Date.now() + 86_400_000).toISOString(),
        }),
      },
    };
    assert.equal(validateAgentCertificate(request, {
      agentCertificateFingerprint256: fingerprint,
      agentCertificateRevokedAt: null,
    }), null);
    assert.equal(validateAgentCertificate(request, {
      agentCertificateFingerprint256: 'cd'.repeat(32),
      agentCertificateRevokedAt: null,
    }).status, 401);
  });
});

test('revoked mTLS certificate is denied and cannot silently re-enroll', () => {
  withMtlsEnvironment(() => {
    const request = {
      socket: {
        encrypted: true,
        getPeerCertificate: () => ({
          fingerprint256: 'ef'.repeat(32),
          valid_to: new Date(Date.now() + 86_400_000).toISOString(),
        }),
      },
    };
    const result = validateAgentCertificate(request, {
      agentCertificateFingerprint256: 'ef'.repeat(32),
      agentCertificateRevokedAt: new Date(),
    }, { allowCertificateEnrollment: true });
    assert.equal(result.status, 401);
    assert.match(result.message, /revoked/i);
  });
});
