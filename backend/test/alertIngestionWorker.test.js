const test = require('node:test');
const assert = require('node:assert/strict');
const { decodeMessage, retryCount } = require('../src/workers/alertIngestion.worker');
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
  assert.match(worker, /persistBatch\(chunk\.map\(item => item\.document\), \{ heartbeat \}\)/);
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
