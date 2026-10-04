const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dotenv = require('../../backend/node_modules/dotenv');
const { localConfig } = require('./local-config');

const root = path.resolve(__dirname, '../..');
const filename = path.join(root, 'backend/.env');
const original = fs.readFileSync(filename, 'utf8');
const current = dotenv.parse(original);
const config = localConfig();
if (current.NODE_ENV === 'production') {
  throw new Error('This command configures local plaintext Kafka; use a secured Kafka cluster for production.');
}
if (current.KAFKA_SSL === 'true' || current.KAFKA_SASL_USERNAME || current.KAFKA_SASL_PASSWORD
  || current.KAFKA_SSL_CA_FILE || current.KAFKA_SSL_CERT_FILE || current.KAFKA_SSL_KEY_FILE) {
  throw new Error('Existing Kafka TLS/SASL settings were preserved. Configure that secured cluster separately.');
}

const localOnly = new Set(['KAFKA_IMAGE', 'KAFKA_HOST_BIND', 'KAFKA_HOST_PORT', 'KAFKA_UI_HOST_PORT', 'KAFKA_EXPORTER_HOST_PORT']);
const desired = {
  ...Object.fromEntries(Object.entries(config).filter(([key]) => !localOnly.has(key) && !key.startsWith('KAFKA_UI_'))),
  INGESTION_MODE: 'broker',
  KAFKA_BROKERS: `localhost:${config.KAFKA_HOST_PORT}`,
  KAFKA_REPLICATION_FACTOR: '1',
  KAFKA_SSL: 'false',
};
if (Object.entries(desired).every(([key, value]) => current[key] === value)) {
  console.log('Backend Kafka settings already match kafka/.env.');
  process.exit(0);
}

const pending = new Map(Object.entries(desired));
const lines = original.split(/\r?\n/).map(line => {
  const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/);
  if (!match || !(match[1] in desired)) return line;
  pending.delete(match[1]);
  return `${match[1]}=${JSON.stringify(desired[match[1]])}`;
});
const contents = lines.join('\n').replace(/\n*$/, '\n')
  + [...pending].map(([key, value]) => `${key}=${JSON.stringify(value)}\n`).join('');
const backupDir = path.join(root, 'backend/.runtime-secrets/config-backups');
fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
fs.chmodSync(backupDir, 0o700);
const backup = path.join(backupDir, `backend.env.${Date.now()}.${crypto.randomUUID()}`);
fs.writeFileSync(backup, original, { flag: 'wx', mode: 0o600 });
fs.writeFileSync(filename, contents);
fs.chmodSync(filename, 0o600);
console.log(`Backend Kafka settings configured. Private backup: ${backup}`);
console.log('Restart the backend to apply the updated producer and worker settings.');
