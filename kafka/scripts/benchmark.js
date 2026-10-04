// Bounded broker-only check on a temporary topic; never writes alert records.
const crypto = require('node:crypto');
const { Kafka, CompressionTypes, Partitioners, logLevel } = require('../../backend/node_modules/kafkajs');
const { localConfig } = require('./local-config');

async function benchmark() {
  const config = localConfig();
  const agents = Number(process.env.BENCHMARK_AGENTS || 30000);
  const eventsPerAgent = Number(process.env.BENCHMARK_EVENTS_PER_AGENT || 1);
  const total = agents * eventsPerAgent;
  if (!Number.isInteger(agents) || agents < 1 || agents > 30000
    || !Number.isInteger(eventsPerAgent) || eventsPerAgent < 1 || total > 300000) {
    throw new Error('Use 1-30000 agents and at most 300000 total events for this local check');
  }
  const id = crypto.randomUUID();
  const topic = `soc.benchmark.${id}`;
  const groupId = `soc-benchmark-${id}`;
  const kafka = new Kafka({ clientId: 'ajnat-benchmark', brokers: [`localhost:${config.KAFKA_HOST_PORT}`], logLevel: logLevel.WARN, retry: { retries: 3 } });
  const admin = kafka.admin();
  const producer = kafka.producer({ idempotent: true, maxInFlightRequests: 5, allowAutoTopicCreation: false, retry: { retries: Number.MAX_SAFE_INTEGER }, createPartitioner: Partitioners.DefaultPartitioner });
  const consumer = kafka.consumer({ groupId, allowAutoTopicCreation: false });
  let timer;
  let created = false;
  try {
    await admin.connect();
    await admin.createTopics({ waitForLeaders: true, topics: [{ topic, numPartitions: 6, replicationFactor: 1, configEntries: [{ name: 'retention.ms', value: '3600000' }] }] });
    created = true;
    const seen = new Set();
    let duplicates = 0;
    let finish;
    const done = new Promise((resolve, reject) => {
      finish = resolve;
      timer = setTimeout(() => reject(new Error(`Timed out: received ${seen.size}/${total} unique events`)), 120000);
    });
    const checked = done.then(() => null, error => error);
    await consumer.connect();
    await consumer.subscribe({ topic, fromBeginning: true });
    await consumer.run({ partitionsConsumedConcurrently: 3, eachBatch: async ({ batch, resolveOffset, heartbeat }) => {
      for (const message of batch.messages) {
        const event = JSON.parse(message.value.toString());
        if (event.run !== id || event.seq < 0 || event.seq >= total || message.key.toString() !== `agent-${event.seq % agents}`) throw new Error('Invalid benchmark record');
        if (seen.has(event.seq)) duplicates += 1;
        seen.add(event.seq);
        resolveOffset(message.offset);
      }
      await heartbeat();
      if (seen.size === total) finish();
    } });
    await producer.connect();
    const start = performance.now();
    let cursor = 0;
    let bytes = 0;
    const send = async () => {
      while (cursor < total) {
        const first = cursor;
        cursor += 250;
        const messages = [];
        for (let seq = first; seq < Math.min(first + 250, total); seq += 1) {
          const value = JSON.stringify({ run: id, seq, payload: crypto.randomBytes(1024).toString('hex') });
          bytes += Buffer.byteLength(value);
          messages.push({ key: `agent-${seq % agents}`, value });
        }
        await producer.send({ topic, acks: -1, compression: CompressionTypes.GZIP, messages });
      }
    };
    await Promise.all(Array.from({ length: 4 }, send));
    const publishSeconds = (performance.now() - start) / 1000;
    const failure = await checked;
    if (failure) throw failure;
    const roundTripSeconds = (performance.now() - start) / 1000;
    console.log(JSON.stringify({ kind: 'broker-only-bounded-check', agents, published: total, consumedUnique: seen.size, duplicates, rawBytes: bytes, partitions: 6, replicationFactor: 1, publishSeconds, roundTripSeconds, observedRoundTripEventsPerSecond: Math.round(total / roundTripSeconds), productionCapacityValidated: false }, null, 2));
  } finally {
    clearTimeout(timer);
    await consumer.disconnect().catch(() => {});
    await producer.disconnect().catch(() => {});
    if (created) await admin.deleteTopics({ topics: [topic] });
    await admin.deleteGroups([groupId]).catch(() => {});
    await admin.disconnect();
  }
}
benchmark().catch(error => { console.error(error.message); process.exitCode = 1; });
