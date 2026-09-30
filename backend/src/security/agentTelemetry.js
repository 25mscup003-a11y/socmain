function enrichFimHashFields(body = {}) {
  const existingSha = body.file_hash || body.fileHash || body.new_hash || body.newHash || body.sha256 || '';
  const existingMd5 = body.file_hash_md5 || body.fileHashMd5 || body.md5 || '';
  if (existingSha && !body.file_hash) body.file_hash = existingSha;
  if (existingMd5 && !body.file_hash_md5) body.file_hash_md5 = existingMd5;
  if (existingSha && !body.new_hash && !body.newHash) body.new_hash = existingSha;
  if (existingSha && !body.hash_algorithm && !body.hashAlgorithm) body.hash_algorithm = 'sha256';
  return {
    fileHash: existingSha || undefined,
    fileHashMd5: existingMd5 || undefined,
  };
}

function enrichFimPermissionFields(body = {}, ruleId = '') {
  const text = `${ruleId} ${body.rule_id || ''} ${body.ruleId || ''} ${body.module_type || ''} ${body.fim_module || ''} ${body.file_action || ''} ${body.fileAction || ''} ${body.description || ''}`.toLowerCase();
  const isPermissionEvent = /(permission|chmod|acl|suid|sgid|world-writable|mode\s+(change|changed|modified))/i.test(text);
  if (!isPermissionEvent) return;
  if (!body.module_type && !body.fim_module) body.module_type = 'permission';
  if (!body.fim_module) body.fim_module = 'permission';
  if (!body.changed_by_user && !body.changedByUser) {
    body.changed_by_user = body.file_user || body.fileUser || body.user || body.username || body.actor || 'unknown';
  }
}

module.exports = {
  enrichFimHashFields,
  enrichFimPermissionFields,
};
