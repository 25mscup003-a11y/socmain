const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.join(__dirname, '../../company/src/pages/edrdashbordpage/File Activity Monitoring (FIM).jsx'), 'utf8');
const helpers = source.slice(source.indexOf('function fimUserIdentity('), source.indexOf('function alertStatus('));
const { alertUser } = vm.runInNewContext(`${helpers}\n({ alertUser })`);

test('FIM logs read changed_by_user from the outer payload even when nested raw exists', () => {
  assert.equal(alertUser({ rawEvent: { changed_by_user: 'root', raw: { event_type: 'deleted' } } }), 'root');
  assert.equal(alertUser({ rawEvent: { raw: { changed_by_user: 'analyst' } } }), 'analyst');
});

test('unknown placeholders cannot hide a reported account', () => {
  assert.equal(alertUser({ username: 'unknown', user: 'N/A', rawEvent: { username: 'ACME\\alice' } }), 'ACME\\alice');
  assert.equal(alertUser({ actor: { username: 'unknown', name: 'alice' } }), 'alice');
  assert.equal(alertUser({ username: 'undefined', raw: { raw: { user_name: 'bob' } } }), 'bob');
});

test('reported account takes precedence over file ownership and owner-only records are labelled', () => {
  assert.equal(alertUser({ fileUser: 'file-owner', rawEvent: { changed_by_user: 'reported-account' } }), 'reported-account');
  assert.equal(alertUser({ fileUser: 'file-owner' }), 'file-owner (file owner)');
  assert.equal(alertUser({ rawEvent: { raw: { file_user: 'file-owner' } } }), 'file-owner (file owner)');
});

test('events with no user evidence do not acquire an invented actor', () => {
  assert.equal(alertUser({ username: 'unknown', fileUser: '-', rawEvent: { actor: 'Not reported' } }), 'Not reported');
  assert.equal(alertUser({ hostname: 'alice-laptop', processName: 'auditd' }), 'Not reported');
});
