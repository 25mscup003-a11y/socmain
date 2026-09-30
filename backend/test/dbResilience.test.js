const test = require('node:test');
const assert = require('node:assert/strict');
const connectDB = require('../src/config/db');
const { retryDelay } = require('../src/config/db');
const { backfillFimBaselines } = require('../src/services/fimBaseline.service');

const silentLogger = { log() {}, warn() {}, error() {} };

test('Mongoose command buffering is disabled to prevent outage query buildup', () => {
  const mongoose = require('mongoose');
  assert.equal(mongoose.get('bufferCommands'), false);
});

test('Mongo startup retries a transient timeout instead of exiting the process', async () => {
  let attempts = 0;
  const delays = [];
  const result = await connectDB({
    uri: 'mongodb://example.invalid/test',
    installEvents: false,
    logger: silentLogger,
    maxAttempts: 3,
    baseDelayMs: 10,
    maxDelayMs: 100,
    sleep: async ms => delays.push(ms),
    connect: async () => {
      attempts += 1;
      if (attempts < 3) throw new Error('connection timed out');
      return { connection: 'ready' };
    },
  });
  assert.equal(attempts, 3);
  assert.deepEqual(delays, [10, 20]);
  assert.deepEqual(result, { connection: 'ready' });
});

test('finite Mongo retry policy rejects only after the configured attempts', async () => {
  let attempts = 0;
  await assert.rejects(connectDB({
    uri: 'mongodb://example.invalid/test',
    installEvents: false,
    logger: silentLogger,
    maxAttempts: 2,
    sleep: async () => {},
    connect: async () => {
      attempts += 1;
      throw new Error('offline');
    },
  }), /offline/);
  assert.equal(attempts, 2);
  assert.equal(retryDelay(6, 1000, 10000), 10000);
});

test('FIM baseline backfill does not buffer while Mongo is disconnected', async () => {
  let called = false;
  const result = await backfillFimBaselines({
    connection: { readyState: 0 },
    updateMany: async () => { called = true; },
  });
  assert.equal(called, false);
  assert.deepEqual(result, {
    ok: false,
    skipped: true,
    reason: 'database_not_ready',
    matched: 0,
    modified: 0,
  });
});

test('FIM baseline backfill runs only after Mongo is ready', async () => {
  const calls = [];
  const result = await backfillFimBaselines({
    connection: { readyState: 1 },
    updateMany: async (filter, update) => {
      calls.push({ filter, update });
      return { matchedCount: 3, modifiedCount: 2 };
    },
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].filter.fimStartAt, null);
  assert.deepEqual(calls[0].update, [{ $set: { fimStartAt: '$installDate' } }]);
  assert.deepEqual(result, { ok: true, skipped: false, matched: 3, modified: 2 });
});
