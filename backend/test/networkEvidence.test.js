const test = require('node:test');
const assert = require('node:assert/strict');
const { isNetworkEvidenceAlert, networkEvidenceAlertIds } = require('../src/utils/networkEvidence');

test('detects only genuine network evidence signals', () => {
  assert.equal(isNetworkEvidenceAlert({ eventCategory: 'network' }), true);
  assert.equal(isNetworkEvidenceAlert({ sourceType: 'ZEEK' }), true);
  assert.equal(isNetworkEvidenceAlert({ source: 'firewall' }), true);
  assert.equal(isNetworkEvidenceAlert({ srcip: '10.0.0.8' }), true);
  assert.equal(isNetworkEvidenceAlert({ domain: 'example.test' }), true);
  assert.equal(isNetworkEvidenceAlert({ eventCategory: 'file', ruleId: 'YARA_MATCH' }), false);
  assert.equal(isNetworkEvidenceAlert({ eventCategory: 'malware', ruleId: 'MALWARE_QUARANTINED' }), false);
});

test('returns unique IDs for network-participating alerts', () => {
  const ids = networkEvidenceAlertIds([
    { _id: 'network-1', eventCategory: 'network' },
    { _id: 'network-1', srcip: '10.0.0.8' },
    { _id: 'file-1', eventCategory: 'file' },
    { _id: 'network-2', sourceType: 'IDS' },
  ]);
  assert.deepEqual(ids, ['network-1', 'network-2']);
});
