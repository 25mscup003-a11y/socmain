const test = require('node:test');
const assert = require('node:assert/strict');
const {
  normalizeHashSignatureEvent,
  enrichHashSignatureEvent,
  scoreHashSignature,
} = require('../src/services/hashSignature.service');
const HashSignaturePolicy = require('../src/models/HashSignaturePolicy.model');
const HashSignatureBaseline = require('../src/models/HashSignatureBaseline.model');

const SHA256_A = 'a'.repeat(64);
const SHA256_B = 'b'.repeat(64);

test('unknown hash is telemetry, not malware', () => {
  const event = normalizeHashSignatureEvent({
    sha256: SHA256_A,
    file_path: '/opt/example/app',
    signatureStatus: 'UNKNOWN',
  });
  assert.equal(event.sha256, SHA256_A);
  assert.equal(event.threatIntelMatch, false);
  assert.equal(event.hashSignatureRule, 'HASH_SIGNATURE_OBSERVED');
  assert.equal(event.hashSignatureRiskScore, 0);
  assert.equal(event.hashSignatureSeverity, 'low');
});

test('malicious unsigned executable correlation becomes critical', () => {
  const event = normalizeHashSignatureEvent({
    sha256: SHA256_A,
    file_path: 'C:\\Users\\analyst\\Downloads\\payload.exe',
    signatureStatus: 'UNSIGNED',
    vtVerdict: 'malicious',
    suspiciousNetwork: true,
  });
  assert.equal(event.hashSignatureRule, 'KNOWN_MALICIOUS_HASH');
  assert.equal(event.hashSignatureRiskScore, 100);
  assert.equal(event.hashSignatureSeverity, 'critical');
});

test('nested VirusTotal and raw snake_case evidence is normalized', () => {
  const event = normalizeHashSignatureEvent({
    raw: {
      file_hash: SHA256_A,
      file_path: '/usr/local/bin/suspicious-tool',
      signature_status: 'unknown',
      certificate_issuer: 'Example Issuer',
      virustotal: { verdict: 'malicious', malicious: 9, total_engines: 72, score: 91 },
    },
  });
  assert.equal(event.sha256, SHA256_A);
  assert.equal(event.threatIntelMatch, true);
  assert.equal(event.reputation, 'malicious');
  assert.equal(event.threatIntelSource, 'VirusTotal');
  assert.equal(event.certificateIssuer, 'Example Issuer');
  assert.equal(event.hashSignatureRule, 'KNOWN_MALICIOUS_HASH');
});

test('signed baseline change is detected without automatically calling it malware', () => {
  const event = normalizeHashSignatureEvent({
    sha256: SHA256_B,
    old_hash: SHA256_A,
    file_path: 'C:\\Program Files\\Vendor\\app.exe',
    signatureStatus: 'VALID',
    publisher: 'Trusted Vendor',
  });
  assert.equal(event.hashMismatch, true);
  assert.equal(event.hashSignatureRule, 'SIGNED_FILE_HASH_CHANGED');
  assert.equal(event.threatIntelMatch, false);
});

test('allowlisted SHA-256 reduces risk and malformed hashes are discarded', () => {
  const allowed = normalizeHashSignatureEvent({ sha256: SHA256_A, file_path: '/tmp/tool.elf' }, { approvedHashes: [SHA256_A] });
  assert.equal(allowed.allowlisted, true);
  assert.equal(allowed.hashSignatureRiskScore, 0);
  const malformed = normalizeHashSignatureEvent({ sha256: 'not-a-hash' });
  assert.deepEqual(malformed, {});
});

test('risk weights are configurable and normalized to 100', () => {
  const result = scoreHashSignature(
    { knownMaliciousHash: true, invalidSignature: true },
    { knownMaliciousHash: 90, invalidSignature: 40 },
  );
  assert.equal(result.riskScore, 100);
  assert.equal(result.severity, 'critical');
});

test('process executable hash aliases are normalized for capability 25', () => {
  const event = normalizeHashSignatureEvent({
    executable_sha256: SHA256_A,
    executable_sha1: 'c'.repeat(40),
    executable_md5: 'd'.repeat(32),
    exe: '/tmp/agent-child',
    signature_status: 'unsigned',
  });
  assert.equal(event.sha256, SHA256_A);
  assert.equal(event.sha1, 'c'.repeat(40));
  assert.equal(event.md5, 'd'.repeat(32));
  assert.equal(event.signatureStatus, 'UNSIGNED');
  assert.equal(event.hashSignatureRule, 'UNSIGNED_EXECUTABLE');
});

test('server baseline enrichment detects drift without replacing the baseline', async t => {
  t.mock.method(HashSignaturePolicy, 'findOne', () => ({
    lean: async () => ({ enabled: true, riskThreshold: 30 }),
  }));
  t.mock.method(HashSignatureBaseline, 'findOne', () => ({
    lean: async () => ({ sha256: SHA256_A, lastSeen: new Date() }),
  }));
  const create = t.mock.method(HashSignatureBaseline, 'create', async () => {
    throw new Error('existing baseline must not be replaced');
  });

  const event = await enrichHashSignatureEvent({
    sha256: SHA256_B,
    file_path: '/tmp/payload.exe',
    signature_status: 'UNSIGNED',
  }, {
    tenantId: 'tenant-a',
    companyId: 'baseline-test-company',
    endpointId: 'endpoint-a',
    filePath: '/tmp/payload.exe',
    observedAt: new Date(),
  });

  assert.equal(event.baselineHash, SHA256_A);
  assert.equal(event.currentHash, SHA256_B);
  assert.equal(event.hashMismatch, true);
  assert.equal(event.hashSignatureAlertEligible, true);
  assert.equal(create.mock.callCount(), 0);
});
