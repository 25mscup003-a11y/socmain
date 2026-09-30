const CAPABILITY_IDS = Object.freeze(Array.from({ length: 31 }, (_, index) => index + 1));
const CAPABILITY_ID_SET = new Set(CAPABILITY_IDS);

function valueText(value) {
  if (value === undefined || value === null) return '';
  if (Array.isArray(value)) return value.map(valueText).join(' ');
  if (typeof value === 'object') return '';
  return String(value);
}

function telemetryText(event = {}) {
  const rawEvent = event.rawEvent && typeof event.rawEvent === 'object' ? event.rawEvent : {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
  const fields = [
    'ruleId', 'rule_id', 'type', 'description', 'full_log', 'source', 'log_source',
    'eventCategory', 'event_category', 'category', 'subCategory', 'sub_category',
    'eventType', 'event_type', 'userAction', 'user_action', 'attackType', 'attack_type',
    'signatureName', 'signature_name', 'processName', 'process_name', 'processCmdline',
    'command_line', 'fileAction', 'file_action', 'filePath', 'file_path', 'malwareType',
    'malware_type', 'domain', 'query', 'threatCategory', 'threat_category', 'technique',
    'mitreId', 'mitre_id', 'actionTaken', 'action_taken', 'containmentStatus',
    'containment_status', 'detectionSource', 'detection_source',
    'insiderSignalType', 'insider_signal_type',
  ];
  return fields
    .flatMap(field => [event[field], rawEvent[field], raw[field]])
    .map(valueText)
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

function focusedTelemetryText(event = {}) {
  const rawEvent = event.rawEvent && typeof event.rawEvent === 'object' ? event.rawEvent : {};
  const fields = [
    'ruleId', 'rule_id', 'type', 'description', 'source', 'log_source',
    'eventCategory', 'event_category', 'category', 'subCategory', 'sub_category',
    'eventType', 'event_type', 'userAction', 'user_action', 'attackType', 'attack_type',
    'signatureName', 'signature_name', 'detectionSource', 'detection_source',
  ];
  return fields
    .flatMap(field => [event[field], rawEvent[field]])
    .map(valueText)
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
}

function explicitCapabilityIds(event = {}) {
  const rawEvent = event.rawEvent && typeof event.rawEvent === 'object' ? event.rawEvent : {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
  return [
    event.capabilityId,
    event.capability_id,
    rawEvent.capabilityId,
    rawEvent.capability_id,
    raw.capabilityId,
    raw.capability_id,
    ...(Array.isArray(event.capabilityIds) ? event.capabilityIds : []),
    ...(Array.isArray(event.capability_ids) ? event.capability_ids : []),
    ...(Array.isArray(rawEvent.capabilityIds) ? rawEvent.capabilityIds : []),
    ...(Array.isArray(rawEvent.capability_ids) ? rawEvent.capability_ids : []),
    ...(Array.isArray(raw.capabilityIds) ? raw.capabilityIds : []),
    ...(Array.isArray(raw.capability_ids) ? raw.capability_ids : []),
  ]
    .map(Number)
    .filter(id => Number.isInteger(id) && CAPABILITY_ID_SET.has(id));
}

function hasValue(event, ...fields) {
  const rawEvent = event.rawEvent && typeof event.rawEvent === 'object' ? event.rawEvent : {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
  return fields.some(field => {
    const value = event[field] ?? rawEvent[field] ?? raw[field];
    if (value === undefined || value === null || value === '' || value === false) return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === 'object') return Object.values(value).some(item => {
      if (Array.isArray(item)) return item.length > 0;
      return item !== undefined && item !== null && item !== '' && item !== false;
    });
    return true;
  });
}

function isRegistryTelemetry(event = {}) {
  const rawEvent = event.rawEvent && typeof event.rawEvent === 'object' ? event.rawEvent : {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
  const category = String(event.eventCategory || event.category || rawEvent.category || raw.category || '').toLowerCase();
  const source = String(event.source || event.log_source || rawEvent.source || raw.source || '').toLowerCase();
  if (category === 'registry' || source === 'registry_monitor') return true;

  const evidence = [
    focusedTelemetryText(event),
    event.registryKey, event.registry_key, event.keyPath, event.key_path,
    event.filePath, event.file_path, event.sourcePath, event.source_path,
    rawEvent.registryKey, rawEvent.registry_key, rawEvent.keyPath, rawEvent.key_path,
    raw.registryKey, raw.registry_key, raw.keyPath, raw.key_path,
  ].map(valueText).filter(Boolean).join(' ').toLowerCase();

  return /\b(?:windows\s+registry|registry\s+(?:key|value|change|modified|monitor|persistence)|regedit|hklm|hkcu|hkcr|hku|hkey(?:_|\b)|runonce?\s+key)\b/.test(evidence)
    || /\/(?:etc\/(?:passwd|shadow|group|gshadow|sudoers(?:\.d)?|ssh\/|cron(?:\.d|\.daily|\.hourly|\.weekly|\.monthly)?\/|systemd\/|security\/|pam\.d\/|fstab|hosts|resolv\.conf|sysctl(?:\.conf|\.d\/)|audit\/)|etc\/ssh\/sshd_config)\b/.test(evidence);
}

/**
 * A single endpoint event can prove several EDR capabilities (for example a
 * malicious DNS connection proves network, DNS, threat-intel and correlation
 * telemetry). Store every deterministic match so overview counts never depend
 * on UI copy, installed source files, or category-level fallbacks.
 */
function deriveCapabilityIds(event = {}) {
  const ids = new Set(explicitCapabilityIds(event));
  const text = telemetryText(event);
  const focusedText = focusedTelemetryText(event);
  const category = String(event.eventCategory || event.category || event.rawEvent?.category || '').toLowerCase();
  const source = String(event.source || event.rawEvent?.source || '').toLowerCase();
  const matches = pattern => pattern.test(text);
  const focusedMatches = pattern => pattern.test(focusedText);

  const processSignal = hasValue(event, 'processName', 'process_name', 'pid', 'processCmdline', 'command_line', 'processCount', 'process_count')
    || matches(/\bproc(?:ess)?[_ -]|process (?:started|terminated|inventory|execution|cpu|memory)|parent pid|cmdline/);
  const fileSignal = category === 'file' || source === 'file_watch'
    || hasValue(event, 'filePath', 'file_path', 'fileAction', 'file_action', 'fimModule', 'fim_module')
    || matches(/\bfile[_ -](?:created|modified|deleted|integrity|permission|ownership)|\bfim\b|hash changed/);
  const networkSignal = category === 'network' || source === 'network'
    || hasValue(event, 'destip', 'destPort', 'dst_port', 'srcPort', 'domain', 'queryType', 'query_type')
    || matches(/\bnet[_ -]|network (?:connection|activity)|outbound connection|inbound connection|\b(?:tcp|udp)\b/);
  const authSignal = matches(/\bauth[_ -]|authentication|failed login|login (?:success|failure)|account lock|mfa|password change|sudo|ssh key/);
  const processLifecycleSignal = focusedMatches(/proc[_ -](?:started|terminated|inventory)|process (?:started|terminated|inventory)/);
  const memorySignal = category === 'memory' || matches(/high memory|memory (?:activity|pressure|scan|spike|leak|injection)|lsass|mimikatz|shellcode|rwx memory|process hollow|dll injection|remote thread injection|kernel process access/);
  const registrySignal = isRegistryTelemetry(event);
  const systemChangeSignal = category === 'systemchanges'
    || matches(/system change|service (?:start|stop|fail|install)|driver (?:load|install)|software (?:install|uninstall|update)|boot config|scheduled task/);
  const persistenceSignal = category === 'persistence'
    || matches(/persistence|startup|autorun|run key|scheduled task|cron|systemd|authorized_keys|wmi persistence|com hijack|dll hijack/);
  const dnsWebSignal = hasValue(event, 'domain', 'queryType', 'query_type', 'responseCode', 'response_code')
    || matches(/\bdns\b|domain|https? request|url|web traffic|dga|onion/);
  const usbSignal = category === 'usb' || hasValue(event, 'device') || event.usbBlocked === true || matches(/\busb\b|removable (?:device|storage)/);
  const behaviorSignal = matches(/\bueba\b|behavio(?:u)?r|anomal|impossible travel|unusual activity|risk score|baseline deviation/);
  const dataClassification = String(
    event.dataClassification ?? event.data_classification
      ?? event.rawEvent?.dataClassification ?? event.rawEvent?.data_classification
      ?? event.rawEvent?.raw?.dataClassification ?? event.rawEvent?.raw?.data_classification
      ?? '',
  ).trim().toLowerCase();
  // `Unknown` is the schema default and is present on unrelated alerts. It is
  // not evidence of data-security telemetry by itself.
  const meaningfulDataClassification = Boolean(dataClassification && dataClassification !== 'unknown');
  const dataSecuritySignal = hasValue(event, 'dataEventType', 'data_event_type', 'dlpPattern', 'dlp_pattern', 'transferChannel', 'transfer_channel')
    || meaningfulDataClassification
    || matches(/\bdlp\b|data exfil|sensitive file|confidential|restricted data|large (?:upload|transfer)|credential file|database export|archive staging|copied.to.usb/);
  const credentialSignal = matches(/credential|mimikatz|lsass|password dump|pass.the.hash|kerberoast|hash dump/);
  const lateralSignal = matches(/lateral movement|psexec|\brdp\b|\bsmb\b|winrm|admin share|remote wmi/);
  const cloudSignal = source === 'cloud' || focusedMatches(/\bcloud[_ -]|cloudtrail|\baws\b|\bazure\b|\bgcp\b|\bs3\b|iam abuse|saas/);
  const emailSignal = source === 'email' || focusedMatches(/\bemail[_ -]|phishing|spear.?phish|malicious attachment|business email compromise|\bbec\b|spam|mail gateway/);
  const insiderSignal = matches(/insider|after.hours|off.hours|impossible travel|unusual (?:login|download|access)|data exfil|privilege abuse|privilege escalation|privileged command|admin(?:istrative)? rights|group membership changed|sensitive file|copied.to.usb|security (?:tool|log).*(?:tamper|clear)|archive staging|outbound transfer anomaly/)
    || /^(?:AUTH_(?:ROOT_LOGIN|SUDO|GROUP_CHANGE|ADMIN_RIGHTS|USER_CREATED|USER_DELETED)|EDR_(?:PRIV_ESC|GROUP_MOD)|PROC_(?:PRIVILEGED_COMMAND|PRIVILEGE_ESCALATION|SECURITY_TOOL_TAMPER|SECURITY_TOOL_TERMINATED|SECURITY_LOG_CLEARED|ARCHIVE_STAGING)|SCRIPT_(?:CREDENTIAL_ACCESS|DATA_EXFILTRATION|MASS_FILE_OPERATION|REMOTE_EXECUTION)|NET_(?:OUTBOUND_TRANSFER_ANOMALY|EXFIL|LATERAL_MOVEMENT_PATTERN)|USB_(?:SENSITIVE_FILE_COPIED|POLICY_BLOCKED|POLICY_VIOLATION)|FILE_SENSITIVE|GEO_IMPOSSIBLE_TRAVEL)$/i.test(String(event.ruleId || event.rule_id || event.type || ''));
  const vulnerabilitySignal = matches(/vulnerab|unpatched|patch status|cve-|exploit detected|package update/);
  const sandboxSignal = focusedMatches(/sandbox|detonation|yara|virustotal|\bvt[_ -]|malware analysis/)
    || (fileSignal && hasValue(event, 'yaraRules', 'vtVerdict', 'vtScore'));
  const kernelSignal = matches(/kernel|rootkit|syscall|auditd|module load|ebpf|driver load/);
  // API Call Monitoring covers API/WAF/request telemetry. Generic auditd or
  // syscall records belong to kernel/process monitoring and must not inflate
  // this capability merely because the operating system exposed a syscall.
  const apiSignal = category === 'api'
    || ['waf', 'api_monitor', 'api_gateway', 'reverse_proxy'].includes(source)
    || focusedMatches(/\bapi[_ -]?(?:call|request|response|abuse|attack|monitor)|\bwaf[_ -]|web[_ -]attack|api gateway|reverse proxy/);
  const scriptSignal = matches(/powershell|encoded command|invoke-expression|\bwscript\b|\bcscript\b|\bmshta\b|script execution|shell script/);
  const timeSignal = matches(/time.based|after.hours|baseline deviation|activity spike|brute (?:force )?surge|unusual time/);
  // Geo-IP enrichment fields can exist on every alert. Capability 23 means a
  // policy-backed geolocation detection, not merely an enriched process/file row.
  const geoSignal = /^GEO_/i.test(String(event.ruleId || event.rule_id || event.type || ''))
    || String(event.eventCategory || event.category || '').toLowerCase() === 'geolocation';
  const serviceSignal = source === 'service_monitor' || hasValue(event, 'serviceName', 'service_name', 'serviceEventType', 'service_event_type')
    || matches(/\bservice[_ -](?:created|deleted|started|stopped|restarted|failed|config|binary|account|startup|health|status|failure|disabled)|service (?:created|deleted|started|health|status|failure|stopped|disabled|configuration changed)|firewall (?:off|disabled)|defender (?:off|disabled)|antivirus (?:off|stopped)/);
  const hashSignal = hasValue(event, 'fileHash', 'fileHashMd5', 'hash', 'oldHash', 'newHash', 'yaraRules',
    'sha256', 'sha1', 'md5', 'executable_sha256', 'processExecutableSha256',
    'signatureStatus', 'signature_status', 'processSignatureStatus')
    || matches(/hash (?:match|analysis|changed)|signature (?:match|analysis)|yara|sha256|md5/);
  const beaconSignal = matches(/beacon|command.and.control|\bc2\b|callback pattern/);
  const ransomwareSignal = matches(/ransom|mass encrypt|shadow copy|\.locked|\.wncry|\.ryuk/);
  const lolbinSignal = source === 'lolbins'
    || focusedMatches(/\blolbin[_ -]|living.off.the.land/)
    || matches(/certutil|regsvr32|mshta|bitsadmin|wmic|rundll32|installutil|msbuild|syncappvpublishingserver/);
  const correlationSignal = matches(/correlat|incident group|multi.stage attack/);
  const responseState = String(event.actionTaken || event.containmentStatus || '').toLowerCase();
  const responseSignal = Boolean(event.isolated || event.quarantined || event.blocked)
    || !['', 'none', 'allowed'].includes(responseState)
    || matches(/automated response|soar|isolate|quarantin|auto.?block|kill process|disable user/);
  const overflowSignal = matches(/memory[_ -]?overflow|buffer overflow|heap overflow|stack overflow|sigsegv|sigabrt|segmentation fault|stack smash|heap spray|asan|nx violation|dep violation|kernel bug/);
  const poisonSignal = matches(/cache poison|dns.*poison|ttl drop|txid mismatch|multiple dns responses|unexpected ip|dns anomaly/);
  const sinkholeSource = source === 'dns_sinkhole';
  const sinkholeSignal = sinkholeSource
    || hasValue(event, 'sinkholeIp', 'sinkhole_ip')
    || (!fileSignal && focusedMatches(/dns.?sinkhole|sinkhole hit|sinkholed|dns domain block/));

  // Old desktop payload normalization used several internal IDs as public
  // card IDs. Prefer the event's proven category so those legacy aliases do
  // not inflate unrelated capability cards.
  if (processLifecycleSignal && category !== 'memory') ids.delete(5);
  if (networkSignal && category === 'network' && !systemChangeSignal) ids.delete(7);
  if (kernelSignal && !timeSignal) ids.delete(22);
  // Older Android network-status payloads advertised every network-adjacent
  // card even though they contained no DNS query, URL or poison/sinkhole
  // evidence. Keep them on Network Activity only.
  const ruleId = String(event.ruleId || event.rule_id || event.type || '').toUpperCase();
  if (/^ANDROID_NETWORK_(?:STATUS|CHANGE)$/.test(ruleId) && !dnsWebSignal) {
    ids.delete(9);
    ids.delete(30);
    ids.delete(31);
  }

  if (processSignal) ids.add(1);
  if (fileSignal) ids.add(2);
  if (networkSignal) ids.add(3);
  if (authSignal) ids.add(4);
  if (memorySignal || overflowSignal) ids.add(5);
  if (registrySignal) ids.add(6);
  if (systemChangeSignal) ids.add(7);
  if (persistenceSignal) ids.add(8);
  if (dnsWebSignal) ids.add(9);
  if (usbSignal) ids.add(10);
  if (behaviorSignal) ids.add(11);
  if (dataSecuritySignal) ids.add(12);
  if (credentialSignal) ids.add(13);
  if (lateralSignal) ids.add(14);
  if (emailSignal) ids.add(15);
  if (insiderSignal) ids.add(16);
  if (vulnerabilitySignal) ids.add(17);
  if (sandboxSignal) ids.add(18);
  if (kernelSignal) ids.add(19);
  if (apiSignal) ids.add(20);
  if (scriptSignal) ids.add(21);
  if (timeSignal) ids.add(22);
  if (geoSignal) ids.add(23);
  if (serviceSignal) ids.add(24);
  // Capability 25 is Hash & Signature Analysis. IP/domain reputation alone is
  // threat-intelligence enrichment, not file/hash/signature evidence.
  if (hashSignal) ids.add(25);
  if (beaconSignal) ids.add(26);
  if (ransomwareSignal) ids.add(27);
  if (lolbinSignal) ids.add(28);
  if (overflowSignal) ids.add(29);
  if (poisonSignal) ids.add(30);
  if (sinkholeSignal) ids.add(31);

  return [...ids].filter(id => CAPABILITY_ID_SET.has(id)).sort((a, b) => a - b);
}

/**
 * Prefer capability ownership already normalized by the agent/ingestion
 * pipeline. Text inference remains available for legacy rows that have no
 * capability tags, but must not make a normalized event inflate unrelated
 * system-monitoring cards.
 */
function canonicalCapabilityIds(event = {}) {
  const explicitIds = [...new Set(explicitCapabilityIds(event))].sort((a, b) => a - b);
  return explicitIds.length ? explicitIds : deriveCapabilityIds(event);
}

function isSyntheticAlert(event = {}) {
  if (event.isSynthetic === true || event.dataOrigin === 'synthetic') return true;
  return /^RULE_\d{3}$/i.test(String(event.ruleId || ''))
    && /^Agent-\d+$/i.test(String(event.agentName || ''))
    && ['firewall', 'ids', 'edr', 'syslog'].includes(String(event.source || '').toLowerCase());
}

function applyCapabilityTelemetry(event = {}) {
  const ids = deriveCapabilityIds(event);
  event.capabilityIds = ids;
  if (ids.length && !ids.includes(Number(event.capabilityId))) {
    event.capabilityId = ids[0];
  }
  if (isSyntheticAlert(event)) {
    event.isSynthetic = true;
    event.dataOrigin = 'synthetic';
  }
  return event;
}

module.exports = {
  CAPABILITY_IDS,
  applyCapabilityTelemetry,
  canonicalCapabilityIds,
  deriveCapabilityIds,
  focusedTelemetryText,
  isRegistryTelemetry,
  isSyntheticAlert,
  telemetryText,
};
