import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeWhitelistValue, parseWhitelistImport, MAX_WHITELIST_IMPORT } from '../src/utils/whitelistImport.js';

test('bulk import recognizes IP families, valid CIDRs and normalized domains', () => {
  for (const [input, expected] of [
    ['192.168.1.100', { value: '192.168.1.100', type: 'ip' }],
    ['2001:0db8:0:0::1', { value: '2001:db8::1', type: 'ip' }],
    ['10.0.0.0/8', { value: '10.0.0.0/8', type: 'cidr' }],
    ['2001:db8::/128', { value: '2001:db8::/128', type: 'cidr' }],
    [' Trusted.Example.COM. ', { value: 'trusted.example.com', type: 'domain' }],
    ['*.trusted.example.com', { value: '*.trusted.example.com', type: 'domain' }],
  ]) assert.deepEqual(normalizeWhitelistValue(input), expected);
});

test('malformed addresses, invalid masks and URLs never become ready entries', () => {
  for (const input of ['999.1.1.1', '01.2.3.4', '2001:::1', '10.0.0.0/33', '2001:db8::/129',
    '10.0.0.0/-1', '10.0.0.0/', '10.0.0.0/8/9', 'https://example.com', 'example.com:443',
    'user@example.com', 'bad domain.com', '-bad.com', 'fe80::1%eth0']) {
    assert.ok(normalizeWhitelistValue(input).error, input);
    assert.equal(parseWhitelistImport(input).rows[0].status, 'invalid', input);
  }
});

test('commas, CRLF, blank lines and equivalent inputs deduplicate before any write', () => {
  const { rows } = parseWhitelistImport('192.168.1.100,\r\nTRUSTED.EXAMPLE.COM\ntrusted.example.com.\n2001:db8::1,2001:0db8:0::1\n\n', [
    { value: '192.168.1.100', type: 'ip' },
  ]);
  assert.deepEqual(rows.map(row => row.status), ['existing', 'ready', 'duplicate', 'ready', 'duplicate']);
  assert.equal(parseWhitelistImport(' ,\n ').rows.length, 0);
});

test('over-limit input is explicit and preview work is bounded', () => {
  const { rows, tooMany } = parseWhitelistImport(Array.from({ length: MAX_WHITELIST_IMPORT + 1 }, (_, i) => `host${i}.example.com`).join('\n'));
  assert.equal(tooMany, true);
  assert.equal(rows.length, MAX_WHITELIST_IMPORT);
});
