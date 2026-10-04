const test = require('node:test');
const assert = require('node:assert/strict');
const { decodeMessage, retryCount, processAlertBatch } = require('../src/workers/alertIngestion.worker');
const fs = require('node:fs');
const path = require('node:path');

test('worker validates a versioned tenant-scoped envelope', () => {
  const document = { tenantId: 't', companyId: 'c', eventId: 'e' };
  const message = { value: Buffer.from(JSON.stringify({ schemaVersion: 1, kind: 'alert', document })) };
  assert.deepEqual(decodeMessage(message), document);
});

test('worker rejects envelopes without tenant idempotency fields', () => {
  const message = { value: Buffer.from(JSON.stringify({ schemaVersion: 1, kind: 'alert', document: { companyId: 'c' } })) };
  assert.throws(() => decodeMessage(message), /tenantId, companyId and eventId/);
});

test('retry count is read from broker headers', () => {
  assert.equal(retryCount({ headers: { 'retry-count': Buffer.from('3') } }), 3);
});

test('worker bounds backlog processing and heartbeats between chunks', () => {
  const worker = fs.readFileSync(path.join(__dirname, '../src/workers/alertIngestion.worker.js'), 'utf8');
  assert.match(worker, /BROKER_PERSIST_BATCH_SIZE \|\| 50/);
  assert.match(worker, /persistWithStorageRetry\(chunk\.map\(item => item\.document\)/);
  assert.match(worker, /await commitOffsetsIfNecessary\(\);\s*await heartbeat\(\);/);
});

test('worker preserves source event time while draining a backlog', () => {
  const worker = fs.readFileSync(path.join(__dirname, '../src/workers/alertIngestion.worker.js'), 'utf8');
  assert.match(worker, /update: \{ \$setOnInsert: document \},\s*upsert: true,\s*\/\/[^]*timestamps: false,/);
});

test('broker ingestion materializes detailed network connection rows', () => {
  const worker = fs.readFileSync(path.join(__dirname, '../src/workers/alertIngestion.worker.js'), 'utf8');
  assert.match(worker, /alert\.ruleId !== 'NET_CONNECTION_SUMMARY'/);
  assert.match(worker, /await ingestNetworkTelemetry\(alert, null\)/);
});

function mixedBatch() {
  const resolved = [];
  return {
    resolved,
    batch: { messages: [
      { offset: '10', value: Buffer.from(JSON.stringify({ schemaVersion: 1, kind: 'alert', document: { tenantId: 't', companyId: 'c', eventId: 'e' } })) },
      { offset: '11', value: Buffer.from('invalid-json') },
    ] },
    resolveOffset: offset => resolved.push(offset),
    heartbeat: async () => {},
    commitOffsetsIfNecessary: async () => {},
    isRunning: () => true,
    isStale: () => false,
  };
}

test('invalid later records cannot advance offsets past a valid record during rebalance', async () => {
  const context = mixedBatch();
  let stale = false;
  context.isStale = () => stale;
  await processAlertBatch(context, {
    broker: { publishDeadLetter: async () => {} },
    persist: async () => { stale = true; },
  });
  assert.deepEqual(context.resolved, []);
});

test('mixed valid and invalid records resolve in order only after durable handling', async () => {
  const context = mixedBatch();
  let deadLetters = 0;
  await processAlertBatch(context, {
    broker: { publishDeadLetter: async () => { deadLetters += 1; } },
    persist: async documents => {
      assert.equal(documents.length, 1);
      assert.deepEqual(context.resolved, []);
    },
  });
  assert.equal(deadLetters, 1);
  assert.deepEqual(context.resolved, ['10', '11']);
});

test('retry publish failure leaves the entire mixed chunk uncommitted', async () => {
  const context = mixedBatch();
  await assert.rejects(processAlertBatch(context, {
    broker: {
      publishDeadLetter: async () => {},
      publishAlerts: async () => { throw new Error('Kafka unavailable'); },
    },
    persist: async () => { throw new Error('Invalid company'); },
  }), /Kafka unavailable/);
  assert.deepEqual(context.resolved, []);
});
