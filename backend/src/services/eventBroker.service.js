const fs = require('fs');
const { Kafka, CompressionTypes, logLevel } = require('kafkajs');

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
  const configuredLogLevel = String(process.env.KAFKA_LOG_LEVEL || 'nothing').toLowerCase();
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
  constructor({ KafkaClass = Kafka, config = null } = {}) {
    this.kafka = new KafkaClass(config || kafkaConfig());
    this.producer = this.kafka.producer({ idempotent: true, maxInFlightRequests: 5, allowAutoTopicCreation: false });
    this.connected = false;
  }

  async connect() {
    if (!this.connected) {
      await this.producer.connect();
      this.connected = true;
    }
  }

  async publishAlerts(documents, { topic = TOPICS.alerts, retryCount = 0 } = {}) {
    if (!Array.isArray(documents) || !documents.length) return { published: 0 };
    await this.connect();
    await this.producer.send({
      topic,
      acks: -1,
      compression: CompressionTypes.GZIP,
      messages: documents.map(document => eventMessage(document, retryCount)),
    });
    return { published: documents.length, topic };
  }

  async publishDeadLetter(document, reason, retryCount) {
    const dead = { ...document, deadLetter: { reason: String(reason).slice(0, 1000), retryCount } };
    return this.publishAlerts([dead], { topic: TOPICS.deadLetter, retryCount });
  }

  async disconnect() {
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
