function hasValue(value) {
  return value !== undefined && value !== null && String(value).trim() !== '';
}

function isNetworkEvidenceAlert(alert = {}) {
  const category = String(alert.eventCategory || '').toLowerCase();
  const sourceType = String(alert.sourceType || '').toLowerCase();
  const source = String(alert.source || '').toLowerCase();
  return ['network', 'dns', 'connection'].includes(category)
    || ['ids', 'ips', 'zeek'].includes(sourceType)
    || /^(network|ids|ips|zeek|firewall|suricata)$/.test(source)
    || hasValue(alert.srcip)
    || hasValue(alert.destip)
    || hasValue(alert.domain)
    || hasValue(alert.dnsQuery)
    || hasValue(alert.protocol)
    || hasValue(alert.communityId);
}

function networkEvidenceAlertIds(alerts = []) {
  const seen = new Set();
  return alerts.reduce((ids, alert) => {
    const id = alert?._id || alert?.id;
    const key = id ? String(id) : '';
    if (!key || seen.has(key) || !isNetworkEvidenceAlert(alert)) return ids;
    seen.add(key);
    ids.push(id);
    return ids;
  }, []);
}

module.exports = { isNetworkEvidenceAlert, networkEvidenceAlertIds };
