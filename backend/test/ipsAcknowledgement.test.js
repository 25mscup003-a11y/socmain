const test = require('node:test');
const assert = require('node:assert/strict');
const service = require('../src/services/ips.service');
const engine = require('../src/services/ipsEngine.service');
const System = require('../src/models/System.model');

test('late or unknown command ACK cannot change endpoint state', async t => {
  let filter;
  t.mock.method(System, 'findOne', query => {
    filter = query;
    return { select: () => ({ lean: async () => null }) };
  });
  t.mock.method(System, 'findOneAndUpdate', () => { throw new Error('must not mutate'); });
  assert.equal(await service.recordAgentCommandResult({ systemId: 's', commandId: 'old', command: 'isolate', ok: true }), null);
  assert.equal(filter.pendingCommands.$elemMatch.command, 'isolate');
  assert.equal(filter.pendingCommands.$elemMatch.$or[0].id, 'old');
});

test('failed re-isolation retains the last confirmed isolated state', async t => {
  const pending = { id: 'new', command: 'isolate', reason: 'Automatic IPS isolation' };
  t.mock.method(System, 'findOne', () => ({ select: () => ({ lean: async () => ({
    pendingCommands: [pending], isIsolated: true,
  }) }) }));
  let update;
  t.mock.method(System, 'findOneAndUpdate', (filter, value) => {
    update = value;
    assert.equal(filter.pendingCommands.$elemMatch.command, 'isolate');
    return { select: async () => ({ _id: 's', companyId: 'c', ...value.$set }) };
  });
  t.mock.method(engine, 'handleAgentCommandResult', async () => {});
  const result = await service.recordAgentCommandResult({ systemId: 's', commandId: 'new', command: 'isolate', ok: false });
  assert.equal(result.isIsolated, true);
  assert.equal(update.$set.isolationStatus, 'failed');
});

test('expired automatic isolation is audited as deferred and clears pending state', async t => {
  const pending = { id: 'stale', command: 'isolate', reason: 'Automatic IPS isolation: Port Scan', srcIp: '203.0.113.10' };
  t.mock.method(System, 'findOne', () => ({ select: () => ({ lean: async () => ({
    pendingCommands: [pending], isIsolated: false,
  }) }) }));
  t.mock.method(System, 'findOneAndUpdate', (query, update) => {
    assert.equal(query.completedIpsCommandIds.$ne, 'stale');
    assert.equal(update.$set.isolationStatus, 'none');
    assert.equal(update.$set.isolationCommandId, null);
    assert.equal(update.$set.isIsolated, false);
    return { select: async () => ({ _id: 's', companyId: 'c', ...update.$set }) };
  });
  let event;
  t.mock.method(engine, 'handleAgentCommandResult', async value => { event = value; });
  await service.recordAgentCommandResult({ systemId: 's', commandId: 'stale', command: 'isolate', ok: false,
    message: 'Automatic isolation deferred: fresh-threat verification expired' });
  assert.equal(event.deferred, true);
  assert.equal(event.srcIp, pending.srcIp);
});

test('manual reconnect supersedes an undelivered isolate command', async t => {
  t.mock.method(System, 'findOne', async () => ({ _id: 's', companyId: 'c',
    isIsolated: false, isolationStatus: 'pending',
    pendingCommands: [{ id: 'old-isolate', command: 'isolate' }],
  }));
  const updates = [];
  t.mock.method(System, 'updateOne', async (query, value) => {
    updates.push(value); return { modifiedCount: 1 };
  });
  const result = await service.queueEndpointCommand({ companyId: 'c', systemId: 's', command: 'reconnect' });
  assert.equal(result.status, 'pending');
  assert.equal(updates[0].$pull.pendingCommands.$or[0].id.$in[0], 'old-isolate');
  assert.equal(updates[1].$push.pendingCommands.$each[0].command, 'reconnect');
});

test('explicit manual isolation replaces an expiring automatic request', async t => {
  t.mock.method(System, 'findOne', async () => ({ _id: 's', companyId: 'c', isIsolated: false,
    pendingCommands: [{ id: 'old-auto', command: 'isolate', reason: 'Automatic IPS isolation: Port Scan' }],
  }));
  const updates = [];
  t.mock.method(System, 'updateOne', async (query, value) => { updates.push(value); return { modifiedCount: 1 }; });
  const result = await service.queueEndpointCommand({ companyId: 'c', systemId: 's', command: 'isolate', reason: 'Manual IPS isolation' });
  assert.equal(result.queued, 1);
  assert.deepEqual(updates[0].$pull.pendingCommands.$or[0].id.$in, ['old-auto']);
  const command = updates[1].$push.pendingCommands.$each[0];
  assert.equal(command.reason, 'Manual IPS isolation');
  assert.equal(command.autoIsolation, undefined);
});

test('a pending reconnect must still be reversed when DB says isolated', async t => {
  t.mock.method(System, 'findOne', async () => ({ _id: 's', companyId: 'c',
    isIsolated: true, isolationStatus: 'reconnecting',
    pendingCommands: [{ id: 'old-reconnect', command: 'reconnect' }],
  }));
  const updates = [];
  t.mock.method(System, 'updateOne', async (query, value) => {
    updates.push(value); return { modifiedCount: 1 };
  });
  const result = await service.queueEndpointCommand({ companyId: 'c', systemId: 's', command: 'isolate' });
  assert.equal(result.queued, 1);
  assert.equal(updates[1].$set.isIsolated, true);
  assert.equal(updates[1].$push.pendingCommands.$each[0].command, 'isolate');
});

test('expiry retains a retryable audit record when no firewall accepts removal', async t => {
  t.mock.method(service.BlockedIP, 'find', () => ({ select: () => ({ lean: async () => [{
    _id: 'b', companyId: 'c', ip: '203.0.113.9', expiresAt: new Date(0),
  }] }) }));
  t.mock.method(System, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  t.mock.method(service.BlockedIP, 'deleteMany', () => { throw new Error('audit must not be deleted'); });
  t.mock.method(service.BlockedIP, 'updateOne', () => { throw new Error('unaccepted expiry must remain retryable'); });
  assert.equal(await service.sweepExpiredBlocks(), 1);
});

test('invalid host strings never qualify as blockable IP addresses', () => {
  for (const ip of ['not-an-ip', '1.2.3.999', 'fe80::1', 'fd00::1', '::', '0:0:0:0:0:0:0:1', '0:0:0:0:0:ffff:127.0.0.1']) assert.equal(service.isPrivateIP(ip), true);
  assert.equal(service.isPrivateIP('8.8.8.8'), false);
});

test('reblocking reverses pending unblock even if last confirmed state is blocked', async t => {
  t.mock.method(System, 'findOne', async () => ({ _id: 's', companyId: 'c',
    blockedIps: ['203.0.113.9'], pendingCommands: [{ id: 'old', command: 'unblock_ip', ip: '203.0.113.9' }],
  }));
  const updates = [];
  t.mock.method(System, 'updateOne', async (query, value) => { updates.push({ query, value }); return { modifiedCount: 1 }; });
  const result = await service.queueEndpointCommand({ companyId: 'c', systemId: 's', command: 'block_ip', ip: '203.0.113.9' });
  assert.equal(result.queued, 1);
  assert.equal(updates[1].query.blockedIps, undefined);
  assert.equal(updates[1].value.$push.pendingCommands.$slice, undefined, 'must not discard unrelated pending commands');
});

test('full command queue fails explicitly without discarding an older command', async t => {
  const pendingCommands = Array.from({ length: 200 }, (_, i) => ({ id: String(i), command: 'other' }));
  t.mock.method(System, 'findOne', async () => ({ _id: 's', pendingCommands }));
  t.mock.method(System, 'updateOne', async query => { assert.ok(query.$expr); return { modifiedCount: 0 }; });
  t.mock.method(System, 'findById', () => ({ select: () => ({ lean: async () => ({ pendingCommands }) }) }));
  const result = await service.queueEndpointCommand({ companyId: 'c', systemId: 's', command: 'isolate' });
  assert.equal(result.status, 'failed');
  assert.match(result.message, /queue is full/);
});

test('completed heartbeat unblock is recognized by a later TTL sweep', async t => {
  t.mock.method(System, 'findOne', async () => ({ _id: 's', companyId: 'c', blockedIps: [], pendingCommands: [],
    lastIpsCommand: { command: 'unblock_ip', ip: '203.0.113.9', status: 'success' },
  }));
  t.mock.method(System, 'updateOne', () => { throw new Error('must not requeue an already confirmed removal'); });
  const result = await service.queueEndpointCommand({ companyId: 'c', systemId: 's', command: 'unblock_ip', ip: '203.0.113.9' });
  assert.equal(result.confirmed, true);
  assert.equal(result.queued, 0);
});
