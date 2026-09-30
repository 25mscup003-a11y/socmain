const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const LoginActivity = require('../src/models/LoginActivity.model');
const Device = require('../src/models/Device.model');
const { parseUserAgent } = require('../src/utils/userAgent');

const workspace = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(workspace, relative), 'utf8');

test('authentication audit captures client and location fields', () => {
  for (const field of ['ipAddress', 'userAgent', 'browser', 'os', 'device', 'geoCountry', 'geoCity', 'geoRegion', 'geoTimezone', 'geoISP', 'geoLat', 'geoLon']) {
    assert.ok(LoginActivity.schema.path(field), `${field} must be available on login activity`);
  }
  assert.ok(LoginActivity.schema.path('browserLocation.latitude'));
  assert.ok(LoginActivity.schema.path('browserLocation.longitude'));
  assert.ok(LoginActivity.schema.path('browserLocation.accuracyMeters'));
  assert.ok(Device.schema.path('gpsLat'));
  assert.ok(Device.schema.path('gpsLon'));
  assert.ok(Device.schema.path('gpsAccuracyMeters'));

  assert.deepEqual(
    parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0'),
    { browser: 'Microsoft Edge 126.0.0.0', os: 'Windows 10/11', device: 'Desktop' },
  );
  assert.deepEqual(
    parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Version/17.5 Mobile/15E148 Safari/604.1'),
    { browser: 'Safari 17.5', os: 'iOS 17.5', device: 'Mobile' },
  );
});

test('fraud intelligence exposes scoped account cards and details', () => {
  const routes = read('backend/src/routes/fraud.routes.js');
  const controller = read('backend/src/controllers/fraud.controller.js');
  const auth = read('backend/src/routes/auth.routes.js');
  const page = read('superadmin/src/pages/FraudDashboardPage.jsx');
  const panel = read('superadmin/src/components/fraud/AccountActivityPanel.jsx');
  const companyLogin = read('company/src/pages/LoginPage.jsx');
  const superadminLogin = read('superadmin/src/pages/LoginPage.jsx');
  const companyLocation = read('company/src/utils/browserLocation.js');
  const fraudService = read('backend/src/services/fraud.service.js');

  assert.match(routes, /router\.get\('\/accounts',\s+ctrl\.getAccounts\)/);
  assert.match(routes, /router\.get\('\/account\/:id',\s+ctrl\.getAccountById\)/);
  assert.match(controller, /getAccountScopingFilter/);
  assert.match(controller, /User\.findOne\(\{ \.\.\.scope, _id: req\.params\.id \}\)/);
  assert.match(controller, /LoginActivity\.find\(activityMatch\)/);
  assert.match(controller, /buildSessions\(rawActivities, now\)/);
  assert.match(auth, /scheduleLoginLocationEnrichment\(activity\)/);
  assert.match(auth, /browserLocation: browserLocationFromRequest\(req\)/);
  assert.match(page, /useState\('accounts'\)/);
  assert.match(panel, /Login \/ logout sessions/);
  assert.match(panel, /Complete authentication timeline/);
  assert.match(panel, /Fraud and risk checks/);
  assert.match(panel, /Browser GPS/);
  assert.match(companyLogin, /captureBrowserLocation\(\)/);
  assert.match(superadminLogin, /captureBrowserLocation\(\)/);
  assert.match(companyLocation, /navigator\.geolocation\.getCurrentPosition/);
  assert.match(companyLocation, /soc_location_consent/);
  assert.match(page, /fraud:auth-event/);
  assert.match(page, /fraud:device:new/);
  assert.match(page, /fraud:device:blocked/);
  assert.match(page, /fraud:rule-changed/);
  assert.match(page, /auto-refresh 15s/);
  assert.match(controller, /emitRuleChange\(req, 'created'/);
  assert.match(fraudService, /const \{ \$inc, \$addToSet, \.\.\.setFields \} = update/);
  assert.doesNotMatch(fraudService, /\$set:\s*\{ \.\.\.update \}/);
  assert.match(fraudService, /authenticationTelemetry\(ipAddress, userAgent, lookupError\.message\)/);
  assert.match(fraudService, /allowAuthFallback = false/);
  assert.match(fraudService, /gpsLat: browserLocation\.latitude/);
  assert.match(controller, /observedAuthenticationDevices\(loginFilter/);
  assert.match(controller, /authenticationSignals24h/);
});
