const test = require('node:test');
const assert = require('node:assert/strict');
const {
  enrichFimHashFields,
  enrichFimPermissionFields,
} = require('../src/security/agentTelemetry');

test('server never derives hashes from an agent-supplied filesystem path', () => {
  const body = { file_path: '/etc/shadow', file_action: 'modified' };
  const result = enrichFimHashFields(body);
  assert.equal(result.fileHash, undefined);
  assert.equal(result.fileHashMd5, undefined);
  assert.equal(body.file_hash, undefined);
});

test('agent-supplied hashes are normalized without reading local files', () => {
  const body = { sha256: 'a'.repeat(64), md5: 'b'.repeat(32) };
  const result = enrichFimHashFields(body);
  assert.equal(result.fileHash, 'a'.repeat(64));
  assert.equal(result.fileHashMd5, 'b'.repeat(32));
  assert.equal(body.hash_algorithm, 'sha256');
});

test('permission metadata uses event data and does not inspect server paths', () => {
  const body = {
    file_path: '/etc/passwd',
    description: 'permission changed',
    file_user: 'endpoint-user',
  };
  enrichFimPermissionFields(body, 'FILE_PERMISSION_CHANGED');
  assert.equal(body.fim_module, 'permission');
  assert.equal(body.changed_by_user, 'endpoint-user');
  assert.equal(body.new_permission, undefined);
});
