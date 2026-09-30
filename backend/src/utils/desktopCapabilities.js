const DESKTOP_CAPABILITIES = Object.freeze([
  { id: 1, collector: 'process', support: 'native', reason: 'Process lifecycle and inventory collector' },
  { id: 2, collector: 'edr', support: 'native', reason: 'File integrity and file lifecycle collector' },
  { id: 3, collector: 'network', support: 'native', reason: 'Connection, listener and network exposure collector' },
  { id: 4, collector: 'edr', support: 'native', reason: 'Authentication, login, sudo and account activity collector' },
  { id: 5, collector: 'memory', support: 'native', reason: 'Memory pressure and suspicious memory activity collector' },
  { id: 6, collector: 'edr', support: 'platform', reason: 'Windows Registry or security-critical Linux configuration monitoring' },
  { id: 7, collector: 'edr', support: 'native', reason: 'Service, driver, package and system-change telemetry' },
  { id: 8, collector: 'edr', support: 'derived', reason: 'Persistence signals derived from startup, service, registry and scheduled-task telemetry' },
  { id: 9, collector: 'network', support: 'native', reason: 'DNS resolver, domain and supported web metadata collector' },
  { id: 10, collector: 'usb', support: 'native', reason: 'USB and removable-device collector' },
  { id: 11, collector: 'edr', support: 'derived', reason: 'Behavioral analytics generated from endpoint baselines' },
  { id: 12, collector: 'edr', support: 'native', reason: 'Automatic data-security collector plus sensitive-file, USB, network-transfer and ransomware telemetry' },
  { id: 13, collector: 'edr', support: 'native', reason: 'Credential-security collector plus authentication, process and credential-store metadata detections' },
  { id: 14, collector: 'network', support: 'derived', reason: 'Lateral-movement detections from process, authentication and network telemetry' },
  { id: 15, collector: 'email', support: 'integration', reason: 'Requires an authorized mail-security or email-provider connector; endpoint agents cannot inspect mailbox content' },
  { id: 16, collector: 'edr', support: 'derived', reason: 'Insider-risk signals generated from authorized endpoint activity baselines' },
  { id: 17, collector: 'edr', support: 'native', reason: 'OS/package patch and vulnerability posture collector' },
  { id: 18, collector: 'yara', support: 'native', reason: 'YARA and configured malware-analysis integrations' },
  { id: 19, collector: 'kernel', support: 'platform', reason: 'Linux audit/kernel telemetry or an approved Windows ETW/kernel sensor' },
  { id: 20, collector: 'edr', support: 'platform', reason: 'Approved audit, ETW and application-security API telemetry' },
  { id: 21, collector: 'edr', support: 'native', reason: 'PowerShell, shell and script execution detections' },
  { id: 22, collector: 'edr', support: 'derived', reason: 'Time-based anomaly analytics over endpoint events' },
  { id: 23, collector: 'geo', support: 'derived', reason: 'Geo-anomaly analytics require IP geolocation and an enabled policy' },
  { id: 24, collector: 'edr', support: 'native', reason: 'Service and security-control health monitoring' },
  { id: 25, collector: 'yara', support: 'native', reason: 'File hash, signature, YARA and configured threat-intelligence analysis' },
  { id: 26, collector: 'network', support: 'derived', reason: 'Beaconing analytics over connection metadata' },
  { id: 27, collector: 'edr', support: 'native', reason: 'Ransomware and mass-encryption behavior detection' },
  { id: 28, collector: 'edr', support: 'native', reason: 'Living-off-the-land executable and command-line detection' },
  { id: 29, collector: 'memory', support: 'native', reason: 'Memory-overflow, crash and exploit-symptom detection' },
  { id: 30, collector: 'network', support: 'native', reason: 'DNS cache-poisoning and resolver anomaly detection' },
  { id: 31, collector: 'dns_sinkhole', support: 'policy', reason: 'Requires a configured DNS sinkhole policy and supported resolver control' },
]);

function desktopOs(system = {}) {
  const value = `${system.osType || ''} ${system.os || ''}`.toLowerCase();
  if (value.includes('windows')) return 'windows';
  if (value.includes('linux') || value.includes('ubuntu') || value.includes('debian') || value.includes('kali')) return 'linux';
  if (value.includes('darwin') || value.includes('mac')) return 'darwin';
  return 'unknown';
}

function collectorEnabled(system, collector, os) {
  switch (collector) {
    case 'process': return system.processMonitorEnabled !== false;
    case 'network': return system.networkMonitorEnabled !== false;
    case 'usb': return system.usbMonitorEnabled !== false;
    case 'memory': return system.memoryMonitorEnabled !== false;
    case 'yara': return system.yaraEnabled !== false;
    case 'geo': return system.geoEnrichmentEnabled !== false;
    case 'kernel': return os === 'linux' && system.edrEnabled !== false;
    case 'edr': return system.edrEnabled !== false;
    case 'email':
    case 'dns_sinkhole':
    default: return false;
  }
}

function capabilityRuntimeState(system, definition, eventCount, totalCount = eventCount) {
  const os = desktopOs(system);
  if (!['linux', 'windows', 'darwin'].includes(os)) {
    return { status: 'unsupported', configured: false, reason: 'Desktop capability matrix is available for Linux, Windows and macOS agents' };
  }
  if (eventCount > 0) return { status: 'reporting', configured: true, reason: definition.reason };
  if (totalCount > 0) return { status: 'stale', configured: true, reason: `${definition.reason}; historical telemetry exists but none arrived in the selected window` };
  if (definition.support === 'integration') {
    return { status: 'dependency_required', configured: false, reason: definition.reason };
  }
  if (definition.collector === 'kernel' && os === 'windows') {
    return { status: 'dependency_required', configured: false, reason: definition.reason };
  }
  if (definition.collector === 'dns_sinkhole') {
    return { status: 'dependency_required', configured: false, reason: definition.reason };
  }
  const configured = collectorEnabled(system, definition.collector, os);
  return configured
    ? { status: 'enabled_no_telemetry', configured: true, reason: definition.reason }
    : { status: 'disabled', configured: false, reason: `${definition.reason} is disabled or unavailable on this endpoint` };
}

module.exports = { DESKTOP_CAPABILITIES, capabilityRuntimeState, desktopOs };
