const test = require('node:test');
const assert = require('node:assert/strict');
const { topicPlan } = require('../scripts/provision-broker-topics');

function withEnv(values, callback) {
  const keys = ['NODE_ENV', 'KAFKA_REPLICATION_FACTOR', 'KAFKA_MIN_INSYNC_REPLICAS', 'KAFKA_ALERT_PARTITIONS', 'KAFKA_RETRY_PARTITIONS', 'KAFKA_DLQ_PARTITIONS', 'KAFKA_RETENTION_MS', 'KAFKA_DLQ_RETENTION_MS'];
  const before = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  keys.forEach(key => delete process.env[key]);
  Object.assign(process.env, values);
  try { callback(); } finally {
    for (const key of keys) {
      if (before[key] === undefined) delete process.env[key];
      else process.env[key] = before[key];
    }
  }
}

test('30k production profile provisions distinct partition counts with quorum durability', () => {
  withEnv({ NODE_ENV: 'production', KAFKA_ALERT_PARTITIONS: '96', KAFKA_RETRY_PARTITIONS: '24', KAFKA_DLQ_PARTITIONS: '12', KAFKA_REPLICATION_FACTOR: '3', KAFKA_RETENTION_MS: '86400000', KAFKA_DLQ_RETENTION_MS: '259200000' }, () => {
    const topics = topicPlan();
    assert.deepEqual(topics.map(topic => topic.numPartitions), [96, 24, 12]);
    for (const topic of topics) {
      assert.equal(topic.replicationFactor, 3);
      assert.equal(topic.configEntries.find(entry => entry.name === 'min.insync.replicas').value, '2');
    }
    assert.equal(topics[2].configEntries.find(entry => entry.name === 'retention.ms').value, '259200000');
  });
});

test('production refuses a single replica or unsafe minimum ISR', () => {
  withEnv({ NODE_ENV: 'production', KAFKA_REPLICATION_FACTOR: '1' }, () => assert.throws(topicPlan, /Production ingestion requires/));
  withEnv({ NODE_ENV: 'production', KAFKA_REPLICATION_FACTOR: '3', KAFKA_MIN_INSYNC_REPLICAS: '1' }, () => assert.throws(topicPlan, /Production ingestion requires/));
});

test('invalid counts and unbounded retention are rejected before contacting Kafka', () => {
  withEnv({ KAFKA_ALERT_PARTITIONS: 'invalid' }, () => assert.throws(topicPlan, /KAFKA_ALERT_PARTITIONS/));
  withEnv({ KAFKA_DLQ_RETENTION_MS: '-1' }, () => assert.throws(topicPlan, /KAFKA_DLQ_RETENTION_MS/));
});
