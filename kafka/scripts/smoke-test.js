const crypto = require('node:crypto');
const { Kafka, Partitioners } = require('../../backend/node_modules/kafkajs');
const { localConfig } = require('./local-config');

async function smoke() {
  const config = localConfig();
  const kafka = new Kafka({
    clientId: 'ajnat-health', brokers: [`localhost:${config.KAFKA_HOST_PORT}`],
    connectionTimeout: 10000, retry: { retries: 2 }, logLevel: 2,
  });
  const id = crypto.randomUUID();
  const groupId = `ajnat-health-${id}`;
  const admin = kafka.admin();
  const producer = kafka.producer({ idempotent: true, allowAutoTopicCreation: false, retry: { retries: Number.MAX_SAFE_INTEGER }, createPartitioner: Partitioners.DefaultPartitioner });
  const consumer = kafka.consumer({ groupId, allowAutoTopicCreation: false });
  let timer;
  try {
    await admin.connect();
    const topics = await admin.listTopics();
    if (!topics.includes(config.KAFKA_HEALTH_TOPIC)) throw new Error('Health topic missing; run manage.sh up');
    await consumer.connect();
    await consumer.subscribe({ topic: config.KAFKA_HEALTH_TOPIC, fromBeginning: false });
    let receivedMessage;
    const received = new Promise((resolve, reject) => {
      receivedMessage = resolve;
      timer = setTimeout(() => reject(new Error('Kafka round-trip timed out')), 20000);
    });
    // Attach the rejection handler before any connect/send can fail.
    const checked = received.then(() => null, error => error);
    await consumer.run({ eachMessage: async ({ message }) => {
      if (message.key?.toString() === id) receivedMessage();
    } });
    await producer.connect();
    await producer.send({ topic: config.KAFKA_HEALTH_TOPIC, acks: -1, messages: [{ key: id, value: JSON.stringify({ kind: 'health', id }) }] });
    const error = await checked;
    if (error) throw error;
    console.log('PASS: Kafka publish/consume with durable acknowledgment on the health topic.');
  } finally {
    clearTimeout(timer);
    await consumer.disconnect().catch(() => {});
    await producer.disconnect().catch(() => {});
    await admin.deleteGroups([groupId]).catch(() => {});
    await admin.disconnect().catch(() => {});
  }
}

smoke().catch(error => { console.error(error.message); process.exitCode = 1; });
