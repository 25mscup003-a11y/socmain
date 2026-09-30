function expandFimCategoryScope(base, category, capabilityId) {
  const query = { ...base };
  if (category === 'file' && Number(capabilityId) === 2) {
    // A FIM event may be promoted to malware/system by enrichment. File evidence,
    // not its final severity category, determines whether it belongs in FIM.
    delete query.eventCategory;
  }
  return query;
}

function fimCapabilityFilter() {
  return { capabilityId: 2 };
}

module.exports = { expandFimCategoryScope, fimCapabilityFilter };
