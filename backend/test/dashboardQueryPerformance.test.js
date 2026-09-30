const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const dashboard = fs.readFileSync(
  path.join(__dirname, '../src/routes/dashboard.routes.js'),
  'utf8',
);

test('frequently-polled email and insider dashboards use indexed capability tags', () => {
  assert.match(dashboard, /case 15: return \{ \$or: exact\(\) \};/);
  assert.match(dashboard, /case 16: return \{ \$or: exact\(\) \};/);
});

test('geolocation detail query narrows candidates by indexed capability tags', () => {
  assert.match(
    dashboard,
    /case 23:\s*[\s\S]*?return \{ \$and: \[\{ \$or: exact\(\) \}, geolocationEvidenceFilter\(\)\] \};/,
  );
});

test('dashboard detail queries enforce bounded result and execution limits', () => {
  assert.match(dashboard, /Math\.min\(500, requestedLimit\)/);
  assert.match(dashboard, /limit\(pageLimit\)\.maxTimeMS\(5000\)/);
  assert.match(dashboard, /countDocuments\(query\)\.maxTimeMS\(5000\)/);
});
