const test = require('node:test');
const assert = require('node:assert/strict');
const { ONLINE_THRESHOLD_MS, isSystemOnline, systemConnectionState } = require('../src/utils/systemPresence');

const now = Date.parse('2026-10-05T05:35:00Z');
const active = { status: 'active', isActive: true, agentVersion: '0.1.10', lastSeen: new Date(now - 48000) };

test('inventory and country sync share a ten minute online window', () => {
  assert.equal(ONLINE_THRESHOLD_MS, 600000);
  assert.equal(isSystemOnline(active, now), true);
  assert.equal(systemConnectionState(active, now), 'online');
  assert.equal(isSystemOnline({ ...active, lastSeen: new Date(now - 4 * 60000) }, now), true);
  assert.equal(isSystemOnline({ ...active, lastSeen: new Date(now - ONLINE_THRESHOLD_MS) }, now), false);
  assert.equal(systemConnectionState({ ...active, lastSeen: new Date(now - 11 * 60000) }, now), 'offline');
});

test('recent timestamps do not mark explicitly disconnected or inactive agents online', () => {
  assert.equal(isSystemOnline({ ...active, status: 'disconnected' }, now), false);
  assert.equal(isSystemOnline({ ...active, isActive: false }, now), false);
  assert.equal(isSystemOnline({ ...active, agentVersion: null }, now), false);
  assert.equal(isSystemOnline({ ...active, status: 'online' }, now), true);
});

test('new systems show not connected yet; invalid or future timestamps never prove online status', () => {
  assert.equal(systemConnectionState({ status: 'pending', isActive: true }, now), 'not_connected');
  for (const lastSeen of [undefined, null, 'invalid-date', new Date(now + 3600000)]) {
    assert.equal(isSystemOnline({ ...active, lastSeen }, now), false);
  }
});
