const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const dotenv = require('../../backend/node_modules/dotenv');
const { mailConfigFromBackend } = require('../ui-auth/mailer');

const directory = path.resolve(__dirname, '../.runtime-secrets');
const filename = path.join(directory, 'ui.env');
fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
fs.chmodSync(directory, 0o700);
if (!fs.existsSync(filename)) {
  fs.writeFileSync(filename, [
    '# Private Kafka UI credentials. Do not commit or share this file.',
    'AUTH_TYPE=LOGIN_FORM',
    'SPRING_SECURITY_USER_NAME=admin',
    `SPRING_SECURITY_USER_PASSWORD=${crypto.randomBytes(24).toString('hex')}`,
    '',
  ].join('\n'), { flag: 'wx', mode: 0o600 });
  console.log(`Kafka UI login configured. Credentials: ${filename}`);
} else {
  console.log(`Existing Kafka UI credentials preserved: ${filename}`);
}
fs.chmodSync(filename, 0o600);

// Copy only SMTP settings into a private mount; never expose the full backend
// environment (database, JWT, cloud credentials) to the UI container.
const backendPath = path.resolve(__dirname, '../../backend/.env');
const backendEnv = fs.existsSync(backendPath) ? dotenv.parse(fs.readFileSync(backendPath)) : {};
const localPath = path.resolve(__dirname, '../.env');
const localEnv = fs.existsSync(localPath) ? dotenv.parse(fs.readFileSync(localPath)) : {};
const recipient = process.env.KAFKA_UI_OTP_EMAIL || localEnv.KAFKA_UI_OTP_EMAIL || backendEnv.SMTP_USER;
const mailConfig = mailConfigFromBackend(backendEnv, recipient);
const mailPath = path.join(directory, 'ui-mail.json');
fs.writeFileSync(`${mailPath}.tmp`, JSON.stringify(mailConfig), { mode: 0o600 });
fs.renameSync(`${mailPath}.tmp`, mailPath);
fs.chmodSync(mailPath, 0o600);
console.log('Kafka UI email OTP configuration synced from backend/.env.');
