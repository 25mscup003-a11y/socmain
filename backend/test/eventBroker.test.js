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
      assert.equal(options.retry.retries, Number.MAX_SAFE_INTEGER);
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

test('concurrent publishes share one connection and reject overload before sending', async () => {
  let connected;
  let connections = 0;
  const sends = [];
  class FakeKafka {
    producer() {
      return {
        connect: () => { connections += 1; return new Promise(resolve => { connected = resolve; }); },
        send: async value => { sends.push(value); },
      };
    }
  }
  const broker = new EventBroker({ KafkaClass: FakeKafka, config: {}, maxPendingPublishes: 2 });
  const first = broker.publishAlerts([{ eventId: '1' }]);
  const second = broker.publishAlerts([{ eventId: '2' }]);
  await assert.rejects(broker.publishAlerts([{ eventId: '3' }]), { code: 'BROKER_BACKPRESSURE', statusCode: 503 });
  assert.equal(connections, 1);
  assert.equal(sends.length, 0);
  connected();
  await Promise.all([first, second]);
  assert.equal(sends.length, 2);
  assert.equal(broker.pendingPublishes, 0);
  assert.equal(broker.pendingBytes, 0);
});

test('failed delivery releases producer capacity and returns a retryable response', async () => {
  class FakeKafka {
    producer() { return { connect: async () => {}, send: async () => { throw new Error('broker offline'); } }; }
  }
  const broker = new EventBroker({ KafkaClass: FakeKafka, config: {}, maxPendingPublishes: 1 });
  await assert.rejects(broker.publishAlerts([{ eventId: '1' }]), { code: 'BROKER_UNAVAILABLE', statusCode: 503 });
  assert.equal(broker.pendingPublishes, 0);
  assert.equal(broker.pendingBytes, 0);
});

test('publisher bounds serialized bytes even when request count is low', async () => {
  let calls = 0;
  class FakeKafka {
    producer() { return { connect: async () => { calls += 1; } }; }
  }
  const broker = new EventBroker({ KafkaClass: FakeKafka, config: {}, maxPendingBytes: 16 });
  await assert.rejects(broker.publishAlerts([{ eventId: '1', raw: 'x'.repeat(100) }]), { code: 'BROKER_BACKPRESSURE' });
  assert.equal(calls, 0);
  assert.equal(broker.pendingBytes, 0);
});

test('caller deadline returns 503 while outstanding delivery retains its queue budget', async () => {
  let acknowledge;
  class FakeKafka {
    producer() { return { connect: async () => {}, send: () => new Promise(resolve => { acknowledge = resolve; }) }; }
  }
  const broker = new EventBroker({ KafkaClass: FakeKafka, config: {}, deliveryTimeoutMs: 20, maxPendingPublishes: 1 });
  await assert.rejects(broker.publishAlerts([{ eventId: 'late-ack' }]), { code: 'BROKER_ACK_TIMEOUT', statusCode: 503 });
  assert.equal(broker.pendingPublishes, 1);
  assert.ok(broker.pendingBytes > 0);
  await assert.rejects(broker.publishAlerts([{ eventId: 'same-id-retry' }]), { code: 'BROKER_BACKPRESSURE' });
  acknowledge();
  await Promise.all([...broker.deliveries]);
  assert.equal(broker.pendingPublishes, 0);
  assert.equal(broker.pendingBytes, 0);
});

test('a late producer failure is handled and frees capacity after the caller times out', async () => {
  let fail;
  class FakeKafka {
    producer() { return { connect: async () => {}, send: () => new Promise((_, reject) => { fail = reject; }) }; }
  }
  const broker = new EventBroker({ KafkaClass: FakeKafka, config: {}, deliveryTimeoutMs: 20 });
  await assert.rejects(broker.publishAlerts([{ eventId: 'late-failure' }]), { code: 'BROKER_ACK_TIMEOUT' });
  const pending = [...broker.deliveries];
  fail(new Error('offline'));
  await Promise.allSettled(pending);
  assert.equal(broker.pendingBytes, 0);
  assert.equal(broker.deliveries.size, 0);
});
