const zlib = require('zlib');
const { performance } = require('perf_hooks');
const { eventMessage } = require('../src/services/eventBroker.service');

const count = Math.max(100, Number(process.env.BENCHMARK_EVENTS || 10000));
const batchSize = Math.max(1, Number(process.env.BENCHMARK_BATCH_SIZE || 50));
const events = Array.from({ length: count }, (_, index) => ({
  tenantId: 'tenant-benchmark', companyId: 'company-benchmark', systemId: `system-${index % 100}`,
  eventId: `event-${index}`, createdAt: '2026-07-19T12:00:00.000Z', severity: 'high',
  ruleId: 'BENCHMARK_EVENT', description: 'Representative security event '.repeat(8),
  rawEvent: { index, process: 'benchmark', path: '/var/log/application.log' },
}));

function time(fn) {
  const started = performance.now();
  const result = fn();
  return { result, milliseconds: performance.now() - started };
}

const raw = time(() => {
  let bytes = 0;
  for (let i = 0; i < events.length; i += batchSize) {
    bytes += Buffer.byteLength(JSON.stringify({ alerts: events.slice(i, i + batchSize) }));
  }
  return bytes;
});

const compressed = time(() => {
  let bytes = 0;
  for (let i = 0; i < events.length; i += batchSize) {
    const body = Buffer.from(JSON.stringify({ alerts: events.slice(i, i + batchSize) }));
    bytes += zlib.gzipSync(body).length;
  }
  return bytes;
});

const envelope = time(() => events.map(event => eventMessage(event)));
console.log(JSON.stringify({
  benchmark: 'ingestion-codecs-local-cpu-only', count, batchSize,
  before: { transport: 'plain-json', bytes: raw.result, encodeMs: Number(raw.milliseconds.toFixed(3)) },
  after: { transport: 'gzip-json', bytes: compressed.result, encodeMs: Number(compressed.milliseconds.toFixed(3)) },
  reductionPercent: Number(((1 - compressed.result / raw.result) * 100).toFixed(2)),
  brokerEnvelope: { messages: envelope.result.length, encodeMs: Number(envelope.milliseconds.toFixed(3)) },
  disclaimer: 'No network, broker, database, disk or server throughput is measured.',
}, null, 2));
