const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Alert = require('../src/models/Alert.model');

test('IDS duplicate alerts have an aggregate occurrence counter', () => {
  const occurrence = Alert.schema.path('occurrenceCount');
  assert.ok(occurrence);
  assert.equal(occurrence.options.default, 1);
  assert.equal(occurrence.options.min, 1);
});

test('IDS ingestion coalesces semantic duplicates before socket and AI fan-out', () => {
  const route = fs.readFileSync(path.join(__dirname, '../src/routes/ids.routes.js'), 'utf8');
  assert.match(route, /IDS_ALERT_COOLDOWN_MS/);
  assert.match(route, /async function coalesceRecentIdsAlert/);
  assert.match(route, /occurrenceCount: Number\(duplicate\.occurrenceCount \|\| 1\) \+ 1/);

  const unified = route.slice(route.indexOf("router.post('/events'"), route.indexOf("router.post('/suricata'"));
  assert.match(unified, /coalesceRecentIdsAlert\(doc, doc\.createdAt\)/);
  assert.ok(unified.indexOf('coalesceRecentIdsAlert') < unified.indexOf("emit('alert:new'"));

  const generic = route.slice(route.indexOf("router.post('/generic'"), route.indexOf("router.post('/firewall'"));
  assert.match(generic, /note: 'duplicate coalesced'/);
});

test('known capture diagnostics are filtered while real sensor alerts remain eligible', () => {
  const route = fs.readFileSync(path.join(__dirname, '../src/routes/ids.routes.js'), 'utf8');
  for (const sid of ['2200003', '2210045', '2210046']) assert.match(route, new RegExp(`'${sid}'`));
  assert.match(route, /truncated_tcp_payload/);
  assert.match(route, /events\.filter\(event => !isSensorInformationalNoise\(event\)\)/);
  assert.match(route, /SURICATA_DECODER_NOISE_SIDS\.has\(sid\)/);
  assert.match(route, /2200003, 2210044, 2210045, 2210046, 2210054/);
  assert.match(route, /reason: 'capture_diagnostic'/);
});

test('all IDS read APIs hide historical capture diagnostics', () => {
  const idsRoute = fs.readFileSync(path.join(__dirname, '../src/routes/ids.routes.js'), 'utf8');
  const idsIpsRoute = fs.readFileSync(path.join(__dirname, '../src/routes/idsips.routes.js'), 'utf8');
  for (const source of [idsRoute, idsIpsRoute]) {
    for (const ruleId of ['SURICATA_2200003', 'SURICATA_2210045', 'SURICATA_2210046', 'ZEEK_truncated_tcp_payload']) {
      assert.match(source, new RegExp(ruleId));
    }
    assert.match(source, /signatureName: \/\^truncated_tcp_payload\$\/i/);
  }
});

test('IDS frontend requests detection logs only and applies a defensive noise filter', () => {
  const page = fs.readFileSync(path.join(__dirname, '../../company/src/pages/IDSPage.jsx'), 'utf8');
  assert.match(page, /includeTelemetry: 'false'/);
  assert.match(page, /IDS_SENSOR_NOISE_RULES/);
  assert.match(page, /Source IP : Port/);
  assert.match(page, /occurrenceCount/);
});
