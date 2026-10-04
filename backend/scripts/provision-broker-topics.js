require('dotenv').config({ path: process.env.DOTENV_CONFIG_PATH || require('path').resolve(__dirname, '../.env') });
const { Kafka } = require('kafkajs');
const { TOPICS, kafkaConfig } = require('../src/services/eventBroker.service');

function integer(name, fallback, minimum = 1) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < minimum) throw new Error(`${name} must be an integer >= ${minimum}`);
  return value;
}

function topicPlan() {
  const replicationFactor = integer('KAFKA_REPLICATION_FACTOR', 1);
  const partitions = integer('KAFKA_ALERT_PARTITIONS', 6);
  const retention = integer('KAFKA_RETENTION_MS', 604800000);
  const minISR = integer('KAFKA_MIN_INSYNC_REPLICAS', replicationFactor >= 3 ? 2 : 1);
  if (minISR > replicationFactor) throw new Error('Minimum in-sync replicas cannot exceed replication factor');
  if (process.env.NODE_ENV === 'production' && (replicationFactor < 3 || minISR < 2)) {
    throw new Error('Production ingestion requires replication factor >= 3 and min.insync.replicas >= 2');
  }
  return [
    [TOPICS.alerts, partitions, retention],
    [TOPICS.retry, integer('KAFKA_RETRY_PARTITIONS', partitions), retention],
    [TOPICS.deadLetter, integer('KAFKA_DLQ_PARTITIONS', partitions), integer('KAFKA_DLQ_RETENTION_MS', 2592000000)],
  ].map(([topic, numPartitions, retentionMs]) => ({
    topic, numPartitions, replicationFactor,
    configEntries: [
      { name: 'cleanup.policy', value: 'delete' },
      { name: 'retention.ms', value: String(retentionMs) },
      { name: 'min.insync.replicas', value: String(minISR) },
      { name: 'unclean.leader.election.enable', value: 'false' },
    ],
  }));
}

async function provision() {
  const topics = topicPlan();
  const admin = new Kafka(kafkaConfig()).admin();
  try {
    await admin.connect();
    const cluster = await admin.describeCluster();
    if (cluster.brokers.length < topics[0].replicationFactor) {
      throw new Error(`Need ${topics[0].replicationFactor} brokers, found ${cluster.brokers.length}`);
    }
    const existing = new Set(await admin.listTopics());
    const missing = topics.filter(topic => !existing.has(topic.topic));
    if (missing.length) await admin.createTopics({ waitForLeaders: true, topics: missing });
    const metadata = await admin.fetchTopicMetadata({ topics: topics.map(topic => topic.topic) });
    for (const wanted of topics) {
      const actual = metadata.topics.find(topic => topic.name === wanted.topic);
      if (actual.partitions.length !== wanted.numPartitions
        || actual.partitions.some(partition => partition.replicas.length !== wanted.replicationFactor)) {
        throw new Error(`${wanted.topic} partition/replica layout differs from configuration. Plan a migration; existing data and partition ordering were preserved.`);
      }
    }
    const configs = await admin.describeConfigs({
      includeSynonyms: false,
      resources: topics.map(topic => ({ type: 2, name: topic.topic, configNames: topic.configEntries.map(entry => entry.name) })),
    });
    for (const wanted of topics) {
      const actual = configs.resources.find(resource => resource.resourceName === wanted.topic);
      for (const entry of wanted.configEntries) {
        const value = actual?.configEntries.find(config => config.configName === entry.name)?.configValue;
        if (value !== entry.value) throw new Error(`${wanted.topic}: ${entry.name} is ${value}, expected ${entry.value}. Existing settings were preserved; review before changing retention/durability.`);
      }
    }
    console.log(JSON.stringify({ status: 'ready', brokers: cluster.brokers.length, topics }));
  } finally {
    await admin.disconnect();
  }
}

if (require.main === module) provision().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});

module.exports = { provision, topicPlan };
