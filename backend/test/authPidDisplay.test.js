const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../company/src/pages/edrdashbordpage/User & Authentication Monitoring.jsx'), 'utf8');
const helper = source.slice(source.indexOf('function authPid('), source.indexOf('function alertStatus('));
const { authPid } = vm.runInNewContext(`${helper}\n({ authPid })`);

test('structured authentication PID takes precedence over the log emitter PID', () => {
  assert.equal(authPid({ pid: 512, full_log: 'host sshd[100]: Accepted password' }), 512);
  assert.equal(authPid({ rawEvent: { raw: { ProcessId: '0x2A' } } }), 42);
  assert.equal(authPid({ raw: { raw: { process_id: '1234' } } }), 1234);
  assert.equal(authPid({ rawEvent: { SYSLOG_PID: '82' } }), 82);
  assert.equal(authPid({ pid: 0, rawEvent: { pid: 25 } }), 0);
});

test('legacy authentication rows recover PID from ISO syslog headers', () => {
  assert.equal(authPid({ full_log: '2026-10-09T21:51:59.222164+05:30 HOST python3[3229]: Remote access event' }), 3229);
  assert.equal(authPid({ rawEvent: { raw_log: '2026-10-09T10:20:30+00:00 host gdm-session-worker[2180]: authentication failure' } }), 2180);
});

test('traditional syslog and journal headers preserve the reported PID', () => {
  assert.equal(authPid({ full_log: 'Oct  9 10:20:30 host sshd[510]: Accepted publickey for alice' }), 510);
  assert.equal(authPid({ raw: { raw_log: '<86>Oct  9 10:20:30 host sudo[702]: session opened' } }), 702);
  assert.equal(authPid({ rawEvent: { raw: { raw_log: 'host login[32]: authentication failure' } } }), 32);
  assert.equal(authPid({ full_log: 'sshd[97]: Failed password' }), 97);
});

test('Windows event process fields support decimal and hexadecimal PID', () => {
  assert.equal(authPid({ full_log: 'EventID=4625\nProcess Information:\n\tCaller Process ID: 0x2a\nCaller Process Name: C:\\Windows\\app.exe' }), 42);
  assert.equal(authPid({ full_log: 'EventID=4624\r\n\tProcess ID:\t1200\r\n' }), 1200);
  assert.equal(authPid({ rawEvent: { raw_log: 'ProcessId=0' } }), 0);
});

test('missing or invalid PIDs remain absent without substituting another identity', () => {
  for (const pid of [null, undefined, '', ' ', 'unknown', false, {}, -2, 3.5, Infinity, '9007199254740992']) {
    assert.equal(authPid({ pid, parentPid: 120, sessionId: '0x3e7', windowsEventId: 4624 }), null);
  }
  assert.equal(authPid({ pid: 'unknown', rawEvent: { pid: 125 } }), 125);
  assert.equal(authPid({ full_log: 'EventID=4625\nParent Process ID: 77\nLogon ID: 0x4a' }), null);
  assert.equal(authPid({ full_log: '2026-10-09T21:31:24+05:30 host sudo: alice : a password is required' }), null);
});

test('PID-like command text and malformed log headers are not treated as telemetry', () => {
  assert.equal(authPid({ full_log: '2026-10-09T21:31:24+05:30 host sudo: COMMAND=/usr/bin/echo sshd[123]: accepted password' }), null);
  assert.equal(authPid({ full_log: 'AUTH:WEB_LOGIN_RESULT title=python3[3229]: login' }), null);
  assert.equal(authPid({ full_log: 'host sshd[9007199254740992]: Failed password' }), null);
  assert.equal(authPid({ full_log: 'EventID=4625\nProcess ID: 1200garbage' }), null);
});
