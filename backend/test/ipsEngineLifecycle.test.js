const test = require('node:test');
const assert = require('node:assert/strict');

const ipsEngine = require('../src/services/ipsEngine.service');
const ipsService = require('../src/services/ips.service');
const System = require('../src/models/System.model');
const Alert = require('../src/models/Alert.model');
const User = require('../src/models/User.model');
const IpsAuditEvent = require('../src/models/IpsAuditEvent.model');
const { _test } = ipsEngine;

test('IPS does not treat a durable endpoint queue as confirmed enforcement', () => {
  assert.equal(_test.isAcceptedBlockResult({ dbSaved: true, agentAccepted: true }), false);
  assert.equal(_test.isAcceptedBlockResult({ dbSaved: true, webhookOk: false }), false);
});

test('IPS accepts only a firewall or endpoint ACK', () => {
  assert.equal(_test.isAcceptedBlockResult({ dbSaved: true, agentConfirmed: true }), true);
  assert.equal(_test.isAcceptedBlockResult({ dbSaved: true, webhookOk: true }), true);
});

test('IPS treats an already active endpoint block as idempotent success', () => {
  assert.equal(_test.isAcceptedBlockResult({ note: 'already blocked' }), true);
  assert.equal(_test.isAcceptedBlockResult({ reason: 'already blocked' }), true);
});

async function withRecoveryStubs({ systems, latestThreat }, callback) {
  const originals = {
    findSystems: System.find,
    findSystem: System.findOne,
    findUsers: User.find,
    updateSystem: System.updateOne,
    findAlert: Alert.findOne,
    persistAudit: IpsAuditEvent.updateOne,
    queueCommand: ipsService.queueEndpointCommand,
  };
  System.findOne = () => ({ select: () => ({ lean: async () => null }) });
  User.find = () => ({ select: () => ({ lean: async () => [] }) });
  const updates = [];
  const commands = [];
  const systemQueries = [];
  const alertQueries = [];
  System.find = query => {
    systemQueries.push(query);
    return { limit: () => ({ lean: async () => systems.map(system => ({
      isOnline: true, lastSeen: new Date('2026-09-09T10:00:00.000Z'), ...system,
    })) }) };
  };
  System.updateOne = async (filter, update) => {
    updates.push({ filter, update });
    return { modifiedCount: 1 };
  };
  Alert.findOne = query => {
    alertQueries.push(query);
    return { sort: () => ({ select: () => ({ lean: async () => latestThreat }) }) };
  };
  IpsAuditEvent.updateOne = async () => ({ acknowledged: true });
  ipsService.queueEndpointCommand = async command => {
    commands.push(command);
    return { queued: 1, confirmed: false, status: 'pending', commandId: 'reconnect-1' };
  };
  try {
    await callback({ updates, commands, systemQueries, alertQueries });
  } finally {
    System.find = originals.findSystems;
    System.findOne = originals.findSystem;
    User.find = originals.findUsers;
    System.updateOne = originals.updateSystem;
    Alert.findOne = originals.findAlert;
    IpsAuditEvent.updateOne = originals.persistAudit;
    ipsService.queueEndpointCommand = originals.queueCommand;
  }
}

test('durable recovery queues reconnect after backend restart', async () => {
  const now = new Date('2026-09-09T10:00:00.000Z');
  const system = {
    _id: 'system-1', companyId: 'company-1', ip: '10.0.0.5',
    isIsolated: true, isolationStatus: 'isolated',
    isolatedAt: new Date(now.getTime() - ipsEngine.AUTO_RECOVER_DELAY_MS),
    isolationAutoRecoverAt: now,
  };
  await withRecoveryStubs({ systems: [system], latestThreat: null }, async ({ commands }) => {
    const result = await ipsEngine.sweepPendingAutoRecoveries(now);
    assert.equal(result.checked, 1);
    assert.equal(result.pending, 1);
    assert.equal(commands.length, 1);
    assert.equal(commands[0].command, 'reconnect');
    assert.equal(commands[0].systemId, system._id);
  });
});

test('durable recovery defers when a recent high-severity threat exists', async () => {
  const now = new Date('2026-09-09T10:00:00.000Z');
  const threatAt = new Date(now.getTime() - 5 * 60 * 1000);
  const system = {
    _id: 'system-2', companyId: 'company-1', ip: '10.0.0.6',
    isIsolated: true, isolationStatus: 'isolated',
    isolatedAt: new Date(now.getTime() - ipsEngine.AUTO_RECOVER_DELAY_MS),
    isolationAutoRecoverAt: now,
  };
  await withRecoveryStubs({
    systems: [system],
    latestThreat: { createdAt: threatAt, srcip: '203.0.113.9' },
  }, async ({ updates, commands }) => {
    const result = await ipsEngine.sweepPendingAutoRecoveries(now);
    assert.equal(result.deferred, 1);
    assert.equal(commands.length, 0);
    assert.equal(updates.length, 1);
    assert.equal(
      updates[0].update.$set.isolationAutoRecoverAt.toISOString(),
      new Date(threatAt.getTime() + ipsEngine.AUTO_RECOVER_DELAY_MS).toISOString(),
    );
  });
});

test('recovery after a long backend outage checks only the latest quiet window', async () => {
  const now = new Date('2026-09-09T10:00:00.000Z');
  const system = {
    _id: 'system-3', companyId: 'company-1', ip: '10.0.0.7',
    isIsolated: true, isolationStatus: 'failed',
    isolatedAt: new Date(now.getTime() - 2 * ipsEngine.AUTO_RECOVER_DELAY_MS),
    isolationAutoRecoverAt: new Date(now.getTime() - ipsEngine.AUTO_RECOVER_DELAY_MS),
  };
  await withRecoveryStubs({ systems: [system], latestThreat: null }, async ({ commands, systemQueries, alertQueries }) => {
    const result = await ipsEngine.sweepPendingAutoRecoveries(now);
    assert.equal(result.pending, 1);
    assert.equal(commands.length, 1);
    assert.deepEqual(systemQueries[0].isolationStatus.$in, ['isolated', 'failed']);
    assert.equal(
      alertQueries[0].createdAt.$gt.toISOString(),
      new Date(now.getTime() - ipsEngine.AUTO_RECOVER_DELAY_MS).toISOString(),
    );
  });
});

test('auto recovery does not treat an offline endpoint as clean', async () => {
  const now = new Date('2026-09-09T10:00:00.000Z');
  await withRecoveryStubs({ systems: [{ _id: 'offline', companyId: 'company-1',
    isOnline: false, lastSeen: new Date('2026-09-09T09:00:00.000Z'),
    isIsolated: true, isolationStatus: 'isolated', isolatedAt: new Date(now - 1200000),
  }], latestThreat: null }, async ({ commands, alertQueries }) => {
    const result = await ipsEngine.sweepPendingAutoRecoveries(now);
    assert.equal(result.deferred, 1);
    assert.equal(commands.length, 0);
    assert.equal(alertQueries.length, 0);
  });
});

test('recovery keeps attacker IP blocks separate from lifting endpoint isolation', async () => {
  const now = new Date('2026-09-09T10:00:00.000Z');
  const original = ipsService.unblockIP;
  ipsService.unblockIP = async () => { throw new Error('recovery must not unblock attacker IP'); };
  try {
    await withRecoveryStubs({ systems: [{ _id: 'one', companyId: 'company-1',
      isIsolated: true, isolationStatus: 'isolated', isolatedAt: new Date(now - 1200000),
      isolationSourceIp: '203.0.113.9',
    }], latestThreat: null }, async ({ commands, alertQueries }) => {
      await ipsEngine.sweepPendingAutoRecoveries(now);
      assert.deepEqual(commands.map(c => c.command), ['reconnect']);
      assert.equal(alertQueries[0].companyId, 'company-1');
    });
  } finally { ipsService.unblockIP = original; }
});

test('the same attacker on two endpoints creates distinct incident identities', () => {
  assert.notEqual(_test.incidentKey('company', '203.0.113.9', 'attack', 'a'),
    _test.incidentKey('company', '203.0.113.9', 'attack', 'b'));
});
