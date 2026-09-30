require('dotenv').config();
const { Kafka } = require('kafkajs');
const { TOPICS, kafkaConfig } = require('../src/services/eventBroker.service');

async function provision() {
  const kafka = new Kafka(kafkaConfig());
  const admin = kafka.admin();
  await admin.connect();
  const partitions = Math.max(3, Number(process.env.KAFKA_ALERT_PARTITIONS || 48));
  const replicationFactor = Math.max(1, Number(process.env.KAFKA_REPLICATION_FACTOR || 3));
  const retentionMs = String(Math.max(86_400_000, Number(process.env.KAFKA_RETENTION_MS || 604_800_000)));
  await admin.createTopics({
    waitForLeaders: true,
    topics: [TOPICS.alerts, TOPICS.retry, TOPICS.deadLetter].map(topic => ({
      topic,
      numPartitions: partitions,
      replicationFactor,
      configEntries: [
        { name: 'cleanup.policy', value: 'delete' },
        { name: 'retention.ms', value: topic === TOPICS.deadLetter ? '-1' : retentionMs },
        { name: 'min.insync.replicas', value: replicationFactor >= 3 ? '2' : '1' },
      ],
    })),
  });
  console.log(JSON.stringify({ topics: Object.values(TOPICS), partitions, replicationFactor }));
  await admin.disconnect();
}

if (require.main === module) provision().catch(error => {
  console.error(error.message);
  process.exit(1);
});

module.exports = { provision };
