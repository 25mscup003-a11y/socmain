const fs = require('node:fs');

function mailConfigFromBackend(env, recipient) {
  const port = Number(env.SMTP_PORT || 587);
  const secure = env.SMTP_SECURE ? env.SMTP_SECURE === 'true' : port === 465;
  return {
    host: env.SMTP_HOST || 'smtp.gmail.com', port, secure,
    user: env.SMTP_USER || '', password: env.SMTP_PASS || '',
    from: env.SMTP_FROM || env.SMTP_USER || '',
    recipient: recipient || env.SMTP_USER || '',
  };
}

function readMailConfig(filename) {
  const config = JSON.parse(fs.readFileSync(filename, 'utf8'));
  if (!config.host || !config.user || !config.password || !config.from || !config.recipient || !Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    throw new Error('Configure backend Gmail SMTP settings and the Kafka UI OTP recipient, then run setup-ui.js');
  }
  return config;
}

function createEmailSender(config, transport) {
  const mailer = transport || require('nodemailer').createTransport({
    host: config.host, port: config.port, secure: config.secure,
    requireTLS: !config.secure,
    auth: { user: config.user, pass: config.password },
    connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000,
    disableFileAccess: true, disableUrlAccess: true,
  });
  return async ({ to, code }) => {
    if (to !== config.recipient || !/^\d{6}$/.test(code)) throw new Error('Invalid OTP email request');
    const result = await mailer.sendMail({
      from: config.from, to,
      subject: 'Your AJNAT Kafka login verification code',
      text: `Your Kafka UI login OTP is: ${code}\n\nThis code expires in 10 minutes and can only be used once for this login.\nDo not share it with anyone.\n\nIf you did not request this login, you can ignore this email.`,
    });
    if (!result.accepted?.some(address => String(address).toLowerCase() === to.toLowerCase())) {
      throw new Error('SMTP did not accept the OTP recipient');
    }
  };
}

module.exports = { mailConfigFromBackend, readMailConfig, createEmailSender };
