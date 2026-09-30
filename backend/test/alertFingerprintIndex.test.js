const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Alert = require('../src/models/Alert.model');

test('alert fingerprint uniqueness excludes missing and null fingerprints', () => {
  const index = Alert.schema.indexes().find(([, options]) => (
    options.name === 'company_event_fingerprint_unique'
  ));

  assert.ok(index);
  assert.equal(index[1].unique, true);
  assert.deepEqual(index[1].partialFilterExpression, {
    eventFingerprint: { $type: 'string' },
  });
  assert.equal(index[1].sparse, undefined);
});

test('Suricata ingestion fingerprints events and treats duplicate-key races as duplicates', () => {
  const route = fs.readFileSync(path.join(__dirname, '../src/routes/ids.routes.js'), 'utf8');
  const suricata = route.slice(
    route.indexOf("router.post('/suricata'"),
    route.indexOf("router.post('/zeek'"),
  );

  assert.match(suricata, /doc\.eventFingerprint = normalizeSecurityEvent/);
  assert.match(suricata, /error\?\.code === 11000/);
  assert.match(suricata, /Skipping concurrently duplicated alert/);
});
