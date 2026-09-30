const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const workspace = path.resolve(__dirname, '..', '..');
const read = relativePath => fs.readFileSync(path.join(workspace, relativePath), 'utf8');

test('superadmin AJNAT security inventory exposes certificate and encryption posture', () => {
  const route = read('backend/src/routes/superadmin.routes.js');
  const page = read('superadmin/src/pages/AgentSecurityPage.jsx');

  assert.match(route, /\+agentCertificateFingerprint256/);
  assert.match(route, /certificate:\s*certificatePosture/);
  assert.match(route, /configurationEncrypted/);
  assert.match(route, /apiPayloadEncryption/);
  assert.match(route, /serverSecurity/);
  assert.match(route, /identityMode/);
  assert.match(route, /aes256-hmac/);
  assert.match(page, /AJNAT identity & encryption/);
  assert.match(page, /company_config\.json/);
  assert.match(page, /Encrypted HTTP compatibility mode enabled/);
});

test('superadmin certificate response actions are audited and require fresh install after reset', () => {
  const route = read('backend/src/routes/superadmin.routes.js');
  const page = read('superadmin/src/pages/AgentSecurityPage.jsx');

  assert.match(route, /revokeCertificate/);
  assert.match(route, /CERTIFICATE_REVOKED/);
  assert.match(route, /resetCertificateIdentity/);
  assert.match(route, /crypto\.randomBytes\(32\)\.toString\('hex'\)/);
  assert.match(route, /CERTIFICATE_IDENTITY_RESET/);
  assert.match(route, /freshPackageRequired:\s*true/);
  assert.match(page, /Revoke certificate/);
  assert.match(page, /Rotate identity for fresh install/);
});

test('encrypted heartbeat status is observed by the server rather than trusted from agent input', () => {
  const route = read('backend/src/routes/agent.routes.js');

  assert.match(route, /if \(req\.agentEncryptedEnvelope\)/);
  assert.match(route, /transportSecurity\.api_payload_encryption = AGENT_PAYLOAD_ENCRYPTION_VERSION/);
});
