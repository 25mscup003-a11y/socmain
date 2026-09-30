'use strict';

require('dotenv').config();
const mongoose = require('mongoose');

async function run() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  await mongoose.connect(process.env.MONGO_URI);
  const alerts = mongoose.connection.collection('alerts');
  const indexes = [
    [{ companyId: 1, capabilityId: 1, createdAt: -1 }, { name: 'email_capability_time' }],
    [{ companyId: 1, capabilityId: 1, emailDirection: 1, createdAt: -1 }, { name: 'email_direction_time' }],
    [{ companyId: 1, capabilityId: 1, threatCategory: 1, createdAt: -1 }, { name: 'email_threat_type_time' }],
    [{ companyId: 1, capabilityId: 1, mailboxEventType: 1, createdAt: -1 }, { name: 'email_mailbox_event_time', sparse: true }],
    [{ companyId: 1, capabilityId: 1, emailSender: 1, createdAt: -1 }, { name: 'email_sender_time', sparse: true }],
    [{ companyId: 1, capabilityId: 1, emailRecipient: 1, createdAt: -1 }, { name: 'email_recipient_time', sparse: true }],
  ];
  for (const [keys, options] of indexes) await alerts.createIndex(keys, options);
  console.log(`Email threat indexes ready: ${indexes.length}`);
  await mongoose.disconnect();
}

run().catch(async error => {
  console.error(error.message);
  try { await mongoose.disconnect(); } catch (_) { /* no-op */ }
  process.exitCode = 1;
});
