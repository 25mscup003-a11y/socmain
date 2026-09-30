const test = require('node:test');
const assert = require('node:assert/strict');
const { EventBroker, eventMessage, kafkaConfig } = require('../src/services/eventBroker.service');

function withKafkaEnv(values, callback) {
  const keys = [
    'KAFKA_BROKERS', 'KAFKA_CLIENT_ID', 'KAFKA_LOG_LEVEL', 'KAFKA_SSL',
    'KAFKA_SSL_CA_FILE', 'KAFKA_SSL_CERT_FILE', 'KAFKA_SSL_KEY_FILE',
    'KAFKA_SSL_REJECT_UNAUTHORIZED', 'KAFKA_SASL_MECHANISM',
    'KAFKA_SASL_USERNAME', 'KAFKA_SASL_PASSWORD',
  ];
  const previous = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  keys.forEach(key => delete process.env[key]);
  Object.assign(process.env, values);
  try {
    return callback();
  } finally {
    keys.forEach(key => {
      if (previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    });
  }
}

test('broker messages are tenant keyed and carry idempotency metadata', () => {
  const message = eventMessage({ tenantId: 'tenant-a', companyId: 'company-a', systemId: 'system-a', eventId: 'evt-1' });
  assert.equal(message.key, 'tenant-a:company-a:system-a');
  assert.equal(message.headers['event-id'], 'evt-1');
  assert.equal(JSON.parse(message.value).document.companyId, 'company-a');
});

test('producer uses durable acknowledgement and compressed batches', async () => {
  const sent = [];
  class FakeKafka {
    producer(options) {
      assert.equal(options.idempotent, true);
      return { connect: async () => {}, send: async value => sent.push(value), disconnect: async () => {} };
    }
  }
  const broker = new EventBroker({ KafkaClass: FakeKafka, config: { brokers: ['unused:9092'] } });
  const result = await broker.publishAlerts([{ tenantId: 't', companyId: 'c', eventId: 'e' }]);
  assert.equal(result.published, 1);
  assert.equal(sent[0].acks, -1);
  assert.ok(sent[0].compression);
});

test('Kafka config supports strict TLS and SCRAM authentication', () => {
  withKafkaEnv({
    KAFKA_BROKERS: 'kafka-1:9093,kafka-2:9093',
    KAFKA_SSL: 'true',
    KAFKA_SASL_USERNAME: 'ajnat-backend',
    KAFKA_SASL_PASSWORD: 'secret',
    KAFKA_SASL_MECHANISM: 'scram-sha-512',
  }, () => {
    const config = kafkaConfig();
    assert.deepEqual(config.brokers, ['kafka-1:9093', 'kafka-2:9093']);
    assert.equal(config.ssl.rejectUnauthorized, true);
    assert.deepEqual(config.sasl, {
      mechanism: 'scram-sha-512',
      username: 'ajnat-backend',
      password: 'secret',
    });
    assert.equal(config.retry.retries, 8);
  });
});

test('Kafka config rejects partial SASL credentials', () => {
  withKafkaEnv({ KAFKA_BROKERS: 'localhost:19092', KAFKA_SASL_USERNAME: 'ajnat' }, () => {
    assert.throws(() => kafkaConfig(), /must be configured together/);
  });
});

test('Kafka config rejects TLS files unless TLS is enabled', () => {
  withKafkaEnv({ KAFKA_BROKERS: 'localhost:19092', KAFKA_SSL_CA_FILE: '/missing/ca.pem' }, () => {
    assert.throws(() => kafkaConfig(), /KAFKA_SSL_CA_FILE is not readable/);
  });
});
