const test = require('node:test');
const assert = require('node:assert/strict');
const nodemailer = require('nodemailer');
const engine = require('../src/services/ipsEngine.service');
const System = require('../src/models/System.model');
const User = require('../src/models/User.model');
const Audit = require('../src/models/IpsAuditEvent.model');

test('direct/restart recovery ACK notifies scoped admins and records the actual outcome', async t => {
  const old = { SMTP_USER: process.env.SMTP_USER, SMTP_PASS: process.env.SMTP_PASS };
  process.env.SMTP_USER = 'sender@example.test'; process.env.SMTP_PASS = 'test-only';
  const sent = [], audits = [], recipientQueries = [];
  let rejectMail = false;
  t.mock.method(nodemailer, 'createTransport', () => ({ sendMail: async message => { sent.push(message); return { accepted: rejectMail ? [] : message.to, rejected: rejectMail ? message.to : [] }; } }));
  t.mock.method(System, 'findOne', query => {
    assert.equal(query.companyId, 'company-a');
    return { select: () => ({ lean: async () => ({ departmentId: 'dept-a' }) }) };
  });
  t.mock.method(User, 'find', query => {
    recipientQueries.push(query);
    return { select: () => ({ lean: async () => [{ email: 'ADMIN@example.test' }, { email: 'dept@example.test' }, { email: 'admin@example.test' }] }) };
  });
  t.mock.method(Audit, 'updateOne', async (query, update) => { audits.push(update.$setOnInsert); return {}; });
  try {
    await engine.handleAgentCommandResult({ companyId: 'company-a', systemId: 'system-a', commandId: 'ack-a',
      command: 'reconnect', ok: true, reason: 'Automatic recovery after 20 minutes without new high/critical activity' });
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0].to.sort(), ['admin@example.test', 'dept@example.test', 'sender@example.test']);
    assert.equal(recipientQueries[0].companyId, 'company-a');
    assert.deepEqual(recipientQueries[0].$or[1], { role: 'department_admin', departmentId: 'dept-a' });
    assert.ok(audits.some(a => a.action === 'Server Restored'));
    assert.ok(audits.some(a => a.action === 'Email Sent'));
    assert.match(sent[0].html, /IP blocking is managed separately/);
    await engine.handleAgentCommandResult({ companyId: 'company-a', systemId: 'system-a', commandId: 'ack-b',
      command: 'isolate', ok: false, message: '<img src=x onerror=alert(1)>' });
    assert.match(sent[1].subject, /Isolation Failed/);
    assert.ok(!sent[1].html.includes('<img'));
    rejectMail = true;
    await engine.handleAgentCommandResult({ companyId: 'company-a', systemId: 'system-a', commandId: 'ack-c', command: 'reconnect', ok: false });
    assert.ok(audits.some(a => a.action === 'Email Failed'), 'SMTP rejection must not be reported as Email Sent');
  } finally {
    for (const [key, value] of Object.entries(old)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});
