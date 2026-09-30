const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const User = require('../src/models/User.model');

test('TOTP setup produces a scannable QR code and a verifiable six-digit token', async () => {
  const secret = speakeasy.generateSecret({ name: 'SOC4 Test', issuer: 'SOC4 Security Platform' });
  const token = speakeasy.totp({ secret: secret.base32, encoding: 'base32' });
  const qrCode = await qrcode.toDataURL(secret.otpauth_url);
  assert.match(token, /^\d{6}$/);
  assert.equal(speakeasy.totp.verify({ secret: secret.base32, encoding: 'base32', token, window: 1 }), true);
  assert.match(qrCode, /^data:image\/png;base64,/);
});

test('user JSON never exposes authentication secrets', () => {
  const user = new User({
    name: 'SOC Analyst', email: 'soc-analyst@example.com', password: 'not-serialized',
    twoFactorSecret: 'TOPSECRET', otp: '123456', otpExpires: new Date(), otpAttempts: 2,
  });
  const json = user.toJSON();
  assert.equal(json.password, undefined);
  assert.equal(json.twoFactorSecret, undefined);
  assert.equal(json.otp, undefined);
  assert.equal(json.otpExpires, undefined);
  assert.equal(json.otpAttempts, undefined);
});

test('2FA routes validate numeric codes, support cancellation, and do not set company posture for SOC analysts', () => {
  const routeSource = fs.readFileSync(path.join(__dirname, '../src/routes/twofa.routes.js'), 'utf8');
  const authSource = fs.readFileSync(path.join(__dirname, '../src/routes/auth.routes.js'), 'utf8');
  const settingsSource = fs.readFileSync(path.join(__dirname, '../../company/src/pages/SettingsPage.jsx'), 'utf8');
  assert.match(routeSource, /router\.post\('\/cancel',\s*authenticate/);
  assert.match(routeSource, /router\.post\('\/validate',\s*authenticate/);
  assert.match(routeSource, /async function loadTwoFactorUser/);
  assert.match(routeSource, /Company\.findById\(user\.companyId\)\.select\('tenantId partnerId'\)/);
  assert.match(routeSource, /user\.tenantId = tenantId/);
  assert.match(routeSource, /user\.role === 'company_admin' && user\.companyId/);
  assert.match(routeSource, /\^\\d\{6\}\$/);
  assert.match(authSource, /router\.post\('\/verify-2fa-login'/);
  assert.match(authSource, /speakeasy\.totp\.verify/);
  assert.match(settingsSource, /Scan this QR code in your authenticator app/);
  assert.match(settingsSource, /Manual setup key/);
  assert.match(settingsSource, /Cancel Setup/);
  assert.match(settingsSource, /Disable 2-Step Verification/);
});
