const fs = require('fs');
const { Kafka, CompressionTypes, Partitioners, logLevel } = require('kafkajs');

const TOPICS = Object.freeze({
  alerts: process.env.BROKER_ALERT_TOPIC || 'soc.alerts.v1',
  retry: process.env.BROKER_ALERT_RETRY_TOPIC || 'soc.alerts.retry.v1',
  deadLetter: process.env.BROKER_ALERT_DLQ_TOPIC || 'soc.alerts.dlq.v1',
});

function brokerEnabled() {
  return process.env.INGESTION_MODE === 'broker';
}

function readKafkaSecretFile(variableName) {
  const filename = String(process.env[variableName] || '').trim();
  if (!filename) return undefined;
  try {
    return fs.readFileSync(filename, 'utf8');
  } catch (error) {
    throw new Error(`${variableName} is not readable: ${error.message}`);
  }
}

function kafkaConfig() {
  const brokers = String(process.env.KAFKA_BROKERS || '').split(',').map(v => v.trim()).filter(Boolean);
  if (!brokers.length) throw new Error('KAFKA_BROKERS is required in broker ingestion mode');
  const configuredLogLevel = String(process.env.KAFKA_LOG_LEVEL || 'warn').toLowerCase();
  const kafkaLogLevels = {
    nothing: logLevel.NOTHING,
    error: logLevel.ERROR,
    warn: logLevel.WARN,
    info: logLevel.INFO,
    debug: logLevel.DEBUG,
  };
  if (!(configuredLogLevel in kafkaLogLevels)) {
    throw new Error('KAFKA_LOG_LEVEL must be one of: nothing, error, warn, info, debug');
  }
  const config = {
    clientId: process.env.KAFKA_CLIENT_ID || 'soc-ingestion',
    brokers,
    connectionTimeout: Number(process.env.KAFKA_CONNECTION_TIMEOUT_MS || 10000),
    requestTimeout: Number(process.env.KAFKA_REQUEST_TIMEOUT_MS || 30000),
    logLevel: kafkaLogLevels[configuredLogLevel],
    retry: {
      initialRetryTime: Number(process.env.KAFKA_RETRY_INITIAL_MS || 300),
      maxRetryTime: Number(process.env.KAFKA_RETRY_MAX_MS || 30000),
      retries: Number(process.env.KAFKA_RETRY_ATTEMPTS || 8),
    },
  };
  const sslEnabled = process.env.KAFKA_SSL === 'true';
  const ca = readKafkaSecretFile('KAFKA_SSL_CA_FILE');
  const cert = readKafkaSecretFile('KAFKA_SSL_CERT_FILE');
  const key = readKafkaSecretFile('KAFKA_SSL_KEY_FILE');
  if ((ca || cert || key) && !sslEnabled) {
    throw new Error('KAFKA_SSL=true is required when Kafka TLS files are configured');
  }
  if (Boolean(cert) !== Boolean(key)) {
    throw new Error('KAFKA_SSL_CERT_FILE and KAFKA_SSL_KEY_FILE must be configured together');
  }
  if (sslEnabled) {
    config.ssl = {
      rejectUnauthorized: process.env.KAFKA_SSL_REJECT_UNAUTHORIZED !== 'false',
      ...(ca && { ca: [ca] }),
      ...(cert && { cert }),
      ...(key && { key }),
    };
  }

  const saslUsername = String(process.env.KAFKA_SASL_USERNAME || '').trim();
  const saslPassword = String(process.env.KAFKA_SASL_PASSWORD || '');
  if (Boolean(saslUsername) !== Boolean(saslPassword)) {
    throw new Error('KAFKA_SASL_USERNAME and KAFKA_SASL_PASSWORD must be configured together');
  }
  if (saslUsername && saslPassword) {
    const mechanism = process.env.KAFKA_SASL_MECHANISM || 'scram-sha-512';
    if (!['plain', 'scram-sha-256', 'scram-sha-512'].includes(mechanism)) {
      throw new Error('Unsupported KAFKA_SASL_MECHANISM');
    }
    config.sasl = {
      mechanism,
      username: saslUsername,
      password: saslPassword,
    };
  }
  return config;
}

function eventMessage(document, retryCount = 0) {
  const tenant = String(document.tenantId || 'unassigned');
  const company = String(document.companyId || 'missing');
  const system = String(document.systemId || document.agentId || 'unknown');
  return {
    key: `${tenant}:${company}:${system}`,
    value: JSON.stringify({ schemaVersion: 1, kind: 'alert', document }),
    headers: {
      'event-id': String(document.eventId || ''),
      'tenant-id': tenant,
      'company-id': company,
      'retry-count': String(retryCount),
    },
  };
}

class EventBroker {
  constructor({ KafkaClass = Kafka, config = null, maxPendingPublishes, maxPendingBytes, deliveryTimeoutMs } = {}) {
    this.kafka = new KafkaClass(config || kafkaConfig());
    this.producer = this.kafka.producer({
      idempotent: true, maxInFlightRequests: 5, allowAutoTopicCreation: false,
      createPartitioner: Partitioners.DefaultPartitioner,
      // Do not let the general client's finite retry count break an in-flight
      // idempotent sequence. Callers have a separate bounded wait below.
      retry: { retries: Number.MAX_SAFE_INTEGER },
    });
    this.connected = false;
    this.connecting = null;
    this.pendingPublishes = 0;
    this.pendingBytes = 0;
    this.deliveries = new Set();
    this.closing = false;
    this.deliveryTimeoutMs = Number(deliveryTimeoutMs ?? process.env.KAFKA_PUBLISH_WAIT_MS ?? 15000);
    this.maxPendingPublishes = Number(maxPendingPublishes ?? process.env.KAFKA_PRODUCER_MAX_PENDING ?? 128);
    this.maxPendingBytes = Number(maxPendingBytes ?? process.env.KAFKA_PRODUCER_MAX_PENDING_BYTES ?? 67108864);
    for (const limit of [this.maxPendingPublishes, this.maxPendingBytes, this.deliveryTimeoutMs]) {
      if (!Number.isSafeInteger(limit) || limit < 1) throw new Error('Kafka producer limits must be positive integers');
    }
  }

  async connect() {
    if (this.connected) return;
    if (!this.connecting) {
      this.connecting = this.producer.connect()
        .then(() => { this.connected = true; })
        .finally(() => { this.connecting = null; });
    }
    await this.connecting;
  }

  async publishAlerts(documents, { topic = TOPICS.alerts, retryCount = 0 } = {}) {
    if (!Array.isArray(documents) || !documents.length) return { published: 0 };
    if (this.closing) throw Object.assign(new Error('Kafka publisher is shutting down'), { code: 'BROKER_UNAVAILABLE', statusCode: 503, retriable: true });
    const messages = documents.map(document => eventMessage(document, retryCount));
    const bytes = messages.reduce((total, message) => total
      + Buffer.byteLength(message.key) + Buffer.byteLength(message.value)
      + Object.entries(message.headers).reduce((size, [key, value]) => size + Buffer.byteLength(key) + Buffer.byteLength(value), 0), 0);
    if (this.pendingPublishes >= this.maxPendingPublishes || this.pendingBytes + bytes > this.maxPendingBytes) {
      const error = new Error('Kafka publisher is busy; retry this batch with the same event IDs');
      error.code = 'BROKER_BACKPRESSURE';
      error.statusCode = 503;
      error.retriable = true;
      throw error;
    }
    this.pendingPublishes += 1;
    this.pendingBytes += bytes;
    const delivery = (async () => {
      try {
        await this.connect();
        await this.producer.send({ topic, acks: -1, compression: CompressionTypes.GZIP, messages });
        return { published: documents.length, topic };
      } catch (cause) {
        throw Object.assign(new Error('Kafka could not acknowledge this batch; retry with the same event IDs', { cause }), {
          code: 'BROKER_UNAVAILABLE', statusCode: 503, retriable: true,
        });
      } finally {
        this.pendingPublishes -= 1;
        this.pendingBytes -= bytes;
      }
    })();
    this.deliveries.add(delivery);
    delivery.then(() => this.deliveries.delete(delivery), () => this.deliveries.delete(delivery));
    let timer;
    try {
      return await Promise.race([
        delivery,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(Object.assign(new Error('Kafka acknowledgement timed out; retry with the same event IDs'), {
            code: 'BROKER_ACK_TIMEOUT', statusCode: 503, retriable: true,
          })), this.deliveryTimeoutMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
      // A timed-out send can still be acknowledged later. It continues counting
      // against the memory/queue budget until it settles, preventing overload.
    }
  }

  async publishDeadLetter(document, reason, retryCount) {
    const dead = { ...document, deadLetter: { reason: String(reason).slice(0, 1000), retryCount } };
    return this.publishAlerts([dead], { topic: TOPICS.deadLetter, retryCount });
  }

  async disconnect() {
    this.closing = true;
    let timer;
    try {
      await Promise.race([
        Promise.allSettled([...this.deliveries]),
        new Promise(resolve => { timer = setTimeout(resolve, 5000); }),
      ]);
    } finally { clearTimeout(timer); }
    if (this.connected) await this.producer.disconnect();
    this.connected = false;
  }
}

let singleton;
function getEventBroker() {
  if (!singleton) singleton = new EventBroker();
  return singleton;
}

async function disconnectEventBroker() {
  if (singleton) await singleton.disconnect();
}

module.exports = { TOPICS, brokerEnabled, kafkaConfig, eventMessage, EventBroker, getEventBroker, disconnectEventBroker };
