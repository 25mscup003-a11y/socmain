/**
 * soc-agent-edr.service.js
 *
 * SOC AI Agent — Tier 2/3 Correlation & Detection Engine
 *
 * Responsibilities:
 *  - Correlate multiple low-level alerts into high-confidence incidents
 *  - Map detections to MITRE ATT&CK TTPs
 *  - Assign confidence scores to avoid false positive noise
 *  - Generate structured incident reports with IOCs
 *  - Recommend or auto-execute EDR response actions
 *  - Run continuous threat hunting across telemetry
 */

const Alert       = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const System      = require('../models/System.model');
const { autoScanCorrelationFinding } = require('./velociraptor.service');
const { networkEvidenceAlertIds } = require('../utils/networkEvidence');
const { claimAlertsForIncident } = require('./socCaseExclusivity.service');

// ─────────────────────────────────────────────────────────────────────────────
// MITRE ATT&CK Technique Mapping
// ─────────────────────────────────────────────────────────────────────────────
const MITRE_MAP = {
  /* Execution */
  powershell:           { id: 'T1059.001', name: 'PowerShell', tactics: ['Execution'] },
  cmd:                  { id: 'T1059.003', name: 'Windows Command Shell', tactics: ['Execution'] },
  bash:                 { id: 'T1059.004', name: 'Unix Shell', tactics: ['Execution'] },
  script_execution:     { id: 'T1059',     name: 'Command and Scripting Interpreter', tactics: ['Execution'] },
  wmic:                 { id: 'T1047',     name: 'Windows Management Instrumentation', tactics: ['Execution'] },
  mshta:                { id: 'T1218.005', name: 'Mshta', tactics: ['Execution', 'Defense Evasion'] },
  regsvr32:             { id: 'T1218.010', name: 'Regsvr32', tactics: ['Execution', 'Defense Evasion'] },
  lolbin:               { id: 'T1218',     name: 'System Binary Proxy Execution (LOLBin)', tactics: ['Defense Evasion'] },

  /* Persistence */
  scheduled_task:       { id: 'T1053.005', name: 'Scheduled Task', tactics: ['Execution', 'Persistence', 'Privilege Escalation'] },
  startup_entry:        { id: 'T1547.001', name: 'Registry Run Keys / Startup Folder', tactics: ['Persistence', 'Privilege Escalation'] },
  service_creation:     { id: 'T1543.003', name: 'Windows Service', tactics: ['Persistence', 'Privilege Escalation'] },
  autorun:              { id: 'T1547',     name: 'Boot/Logon Autostart Execution', tactics: ['Persistence'] },

  /* Privilege Escalation */
  privilege_escalation: { id: 'T1068',     name: 'Exploitation for Privilege Escalation', tactics: ['Privilege Escalation'] },
  sudo_abuse:           { id: 'T1548.003', name: 'Sudo and Sudo Caching', tactics: ['Privilege Escalation', 'Defense Evasion'] },
  priv_esc:             { id: 'T1134',     name: 'Access Token Manipulation', tactics: ['Privilege Escalation', 'Defense Evasion'] },
  new_user:             { id: 'T1136',     name: 'Create Account', tactics: ['Persistence'] },

  /* Defense Evasion */
  process_injection:    { id: 'T1055',     name: 'Process Injection', tactics: ['Defense Evasion', 'Privilege Escalation'] },
  process_hollowing:    { id: 'T1055.012', name: 'Process Hollowing', tactics: ['Defense Evasion', 'Privilege Escalation'] },
  reflective_dll:       { id: 'T1055.001', name: 'DLL Injection', tactics: ['Defense Evasion', 'Privilege Escalation'] },
  obfuscation:          { id: 'T1027',     name: 'Obfuscated Files or Information', tactics: ['Defense Evasion'] },
  masquerading:         { id: 'T1036',     name: 'Masquerading', tactics: ['Defense Evasion'] },
  defense_evasion:      { id: 'T1562',     name: 'Impair Defenses', tactics: ['Defense Evasion'] },

  /* Credential Access */
  credential_dumping:   { id: 'T1003',     name: 'OS Credential Dumping', tactics: ['Credential Access'] },
  mimikatz:             { id: 'T1003.001', name: 'LSASS Memory', tactics: ['Credential Access'] },
  brute_force:          { id: 'T1110',     name: 'Brute Force', tactics: ['Credential Access'] },
  pass_the_hash:        { id: 'T1550.002', name: 'Pass the Hash', tactics: ['Defense Evasion', 'Lateral Movement'] },
  token_hijacking:      { id: 'T1134',     name: 'Access Token Manipulation', tactics: ['Defense Evasion', 'Privilege Escalation'] },

  /* Discovery */
  port_scan:            { id: 'T1046',     name: 'Network Service Discovery', tactics: ['Discovery'] },
  host_discovery:       { id: 'T1018',     name: 'Remote System Discovery', tactics: ['Discovery'] },
  recon:                { id: 'T1592',     name: 'Gather Victim Host Information', tactics: ['Reconnaissance'] },

  /* Lateral Movement */
  lateral_movement:     { id: 'T1021',     name: 'Remote Services', tactics: ['Lateral Movement'] },
  psexec:               { id: 'T1021.002', name: 'SMB/Windows Admin Shares (PsExec)', tactics: ['Lateral Movement'] },
  rdp:                  { id: 'T1021.001', name: 'Remote Desktop Protocol', tactics: ['Lateral Movement'] },
  smb:                  { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactics: ['Lateral Movement'] },

  /* Collection & Exfiltration */
  data_exfiltration:    { id: 'T1048',     name: 'Exfiltration Over Alternative Protocol', tactics: ['Exfiltration'] },
  data_staged:          { id: 'T1074',     name: 'Data Staged', tactics: ['Collection'] },
  clipboard:            { id: 'T1115',     name: 'Clipboard Data', tactics: ['Collection'] },

  /* C2 */
  c2:                   { id: 'T1071',     name: 'Application Layer Protocol (C2)', tactics: ['Command and Control'] },
  beaconing:            { id: 'T1071.001', name: 'Web Protocols (Beaconing)', tactics: ['Command and Control'] },
  dns_tunneling:        { id: 'T1071.004', name: 'DNS (C2 Tunneling)', tactics: ['Command and Control'] },
  reverse_shell:        { id: 'T1059',     name: 'Reverse Shell via Scripting', tactics: ['Execution', 'Command and Control'] },

  /* Impact */
  ransomware:           { id: 'T1486',     name: 'Data Encrypted for Impact (Ransomware)', tactics: ['Impact'] },
  wiper:                { id: 'T1485',     name: 'Data Destruction', tactics: ['Impact'] },
  ddos:                 { id: 'T1498',     name: 'Network Denial of Service', tactics: ['Impact'] },

  /* Initial Access */
  phishing:             { id: 'T1566',     name: 'Phishing', tactics: ['Initial Access'] },
  exploit:              { id: 'T1190',     name: 'Exploit Public-Facing Application', tactics: ['Initial Access'] },
  usb_autorun:          { id: 'T1091',     name: 'Replication Through Removable Media', tactics: ['Initial Access', 'Lateral Movement'] },

  /* Malware */
  malware:              { id: 'T1204',     name: 'User Execution (Malware)', tactics: ['Execution'] },
  trojan:               { id: 'T1204.002', name: 'Malicious File', tactics: ['Execution'] },
  rootkit:              { id: 'T1014',     name: 'Rootkit', tactics: ['Defense Evasion', 'Persistence'] },
  miner:                { id: 'T1496',     name: 'Resource Hijacking (Cryptominer)', tactics: ['Impact'] },
  backdoor:             { id: 'T1546',     name: 'Event Triggered Execution (Backdoor)', tactics: ['Persistence', 'Privilege Escalation'] },

  /* File / Registry */
  file_modification:    { id: 'T1565.001', name: 'Stored Data Manipulation', tactics: ['Impact', 'Defense Evasion'] },
  registry_modification:{ id: 'T1112',     name: 'Modify Registry', tactics: ['Defense Evasion'] },
};

// ─────────────────────────────────────────────────────────────────────────────
// Correlation Rules — each rule correlates event patterns into an incident
// ─────────────────────────────────────────────────────────────────────────────
const CORRELATION_RULES = [
  {
    id: 'CR-001',
    name: 'Ransomware Attack Chain',
    category: 'ransomware',
    severity: 'critical',
    mitre: 'ransomware',
    confidenceBase: 95,
    description: 'Mass file encryption combined with shadow copy deletion detected — high confidence ransomware',
    match: (alerts) => {
      const hasEncryption = alerts.some(a =>
        (a.ruleId || '').toLowerCase().match(/ransomware|encrypt|shadow|vssadmin|bcdedit/)
        || (a.malwareType || '') === 'Ransomware'
        || (a.description || '').toLowerCase().includes('ransom')
      );
      const hasMassFile = alerts.filter(a =>
        a.eventCategory === 'file' || (a.ruleId || '').includes('file')
      ).length >= 3;
      return hasEncryption || (hasMassFile && alerts.length >= 5);
    },
  },
  {
    id: 'CR-002',
    name: 'Credential Dumping Attempt',
    category: 'credential_dumping',
    severity: 'critical',
    mitre: 'credential_dumping',
    confidenceBase: 90,
    description: 'LSASS access or credential dumping tool detected (Mimikatz/procdump pattern)',
    match: (alerts) => alerts.some(a =>
      (a.ruleId || '').toLowerCase().match(/mimikatz|lsass|procdump|sekurlsa|credentials|samdum/) ||
      (a.description || '').toLowerCase().match(/credential.*dump|lsass.*access|mimikatz/)
    ),
  },
  {
    id: 'CR-003',
    name: 'Brute Force + Privilege Escalation Chain',
    category: 'privilege_escalation',
    severity: 'high',
    mitre: 'privilege_escalation',
    confidenceBase: 85,
    description: 'Multiple authentication failures followed by successful login with privilege escalation',
    match: (alerts) => {
      const hasBrute = alerts.some(a =>
        (a.userAction || '') === 'brute_force' ||
        (a.ruleId || '').toLowerCase().match(/brute|failed.*login|auth.*fail/)
      );
      const hasPrivEsc = alerts.some(a =>
        (a.userAction || '') === 'privilege_escalation' ||
        (a.ruleId || '').toLowerCase().match(/priv.*esc|sudo|suid|capability/)
      );
      return hasBrute && hasPrivEsc;
    },
  },
  {
    id: 'CR-004',
    name: 'C2 Beaconing + Data Exfiltration',
    category: 'c2_communication',
    severity: 'critical',
    mitre: 'c2',
    confidenceBase: 88,
    description: 'Repeated outbound connections to suspicious IPs with data transfer patterns indicating C2',
    match: (alerts) => {
      const networkAlerts = alerts.filter(a => a.eventCategory === 'network');
      const uniqueIps = new Set(networkAlerts.map(a => a.destip || a.srcip).filter(Boolean));
      const hasSuspiciousC2 = networkAlerts.some(a =>
        (a.ruleId || '').toLowerCase().match(/c2|beacon|reverse.*shell|malicious.*ip|suspicious.*conn/)
      );
      return hasSuspiciousC2 || (networkAlerts.length >= 5 && uniqueIps.size <= 2 && networkAlerts.length > 3);
    },
  },
  {
    id: 'CR-005',
    name: 'Lateral Movement via SMB/RDP',
    category: 'lateral_movement',
    severity: 'high',
    mitre: 'lateral_movement',
    confidenceBase: 82,
    description: 'RDP abuse, PsExec, or SMB exploitation indicating lateral movement within the network',
    match: (alerts) => alerts.some(a =>
      (a.ruleId || '').toLowerCase().match(/psexec|rdp.*abuse|smb.*exploit|wmi.*remote|lateral|pass.*hash/)
    ),
  },
  {
    id: 'CR-006',
    name: 'Process Injection / Hollow',
    category: 'malware',
    severity: 'high',
    mitre: 'process_injection',
    confidenceBase: 87,
    description: 'Memory-based process injection or hollowing technique detected — possible fileless malware',
    match: (alerts) => alerts.some(a =>
      (a.ruleId || '').toLowerCase().match(/inject|hollow|reflective|dll.*inject|mavinject|memory.*exec/) ||
      (a.description || '').toLowerCase().match(/process.*inject|code.*inject|dll.*inject|reflective/)
    ),
  },
  {
    id: 'CR-007',
    name: 'Persistence Mechanism Installed',
    category: 'persistence',
    severity: 'medium',
    mitre: 'scheduled_task',
    confidenceBase: 78,
    description: 'Unauthorized scheduled task, service, startup entry, or registry autorun created',
    match: (alerts) => alerts.some(a =>
      (a.ruleId || '').toLowerCase().match(/scheduled.*task|autostart|startup|autorun|new.*service|registry.*run/) ||
      (a.userAction || '').match(/persistence|startup/)
    ),
  },
  {
    id: 'CR-008',
    name: 'Living-off-the-Land (LOLBin) Attack',
    category: 'defense_evasion',
    severity: 'high',
    mitre: 'lolbin',
    confidenceBase: 80,
    description: 'Abuse of legitimate system tools (PowerShell, WMIC, Regsvr32, Mshta) for malicious purposes',
    match: (alerts) => alerts.some(a =>
      (a.ruleId || '').toLowerCase().match(/lolbin|wmic.*exec|powershell.*obf|mshta|regsvr32|certutil.*download|bitsadmin/)
    ),
  },
  {
    id: 'CR-009',
    name: 'Malware Confirmed by VT',
    category: 'malware',
    severity: 'high',
    mitre: 'malware',
    confidenceBase: 92,
    description: 'File confirmed malicious by multiple VirusTotal engines with YARA rule match',
    match: (alerts) => alerts.some(a =>
      (a.vtVerdict === 'malicious' && (a.vtDetections || 0) > 5) ||
      (a.eventCategory === 'malware' && a.yaraRules && a.yaraRules.length > 0)
    ),
  },
  {
    id: 'CR-010',
    name: 'USB Threat — Malware Auto-Execution',
    category: 'usb_threat',
    severity: 'high',
    mitre: 'usb_autorun',
    confidenceBase: 83,
    description: 'Malicious content detected on removable media — possible initial access vector',
    match: (alerts) => alerts.some(a =>
      a.eventCategory === 'usb' && (
        (a.ruleId || '').toLowerCase().match(/malware|yara|virus/) ||
        a.vtVerdict === 'malicious'
      )
    ),
  },
  {
    id: 'CR-011',
    name: 'Data Exfiltration Attempt',
    category: 'data_exfiltration',
    severity: 'critical',
    mitre: 'data_exfiltration',
    confidenceBase: 85,
    description: 'Large data transfer to external IPs or suspicious DNS exfiltration detected',
    match: (alerts) => alerts.some(a =>
      (a.ruleId || '').toLowerCase().match(/exfil|data.*leak|dns.*tunnel|large.*transfer|sensitive.*data/) ||
      (a.description || '').toLowerCase().match(/exfiltrat|data.*leak/)
    ),
  },
  {
    id: 'CR-012',
    name: 'Zero-Day / Exploit Attempt',
    category: 'zero_day',
    severity: 'critical',
    mitre: 'exploit',
    confidenceBase: 78,
    description: 'Buffer overflow, heap spray, or unknown exploit pattern detected — possible zero-day',
    match: (alerts) => alerts.some(a =>
      (a.ruleId || '').toLowerCase().match(/overflow|heap.*spray|exploit|shellcode|rop.*chain|zero.*day/)
    ),
  },
  {
    id: 'CR-013',
    name: 'Anomalous Login Pattern',
    category: 'insider_threat',
    severity: 'medium',
    mitre: 'brute_force',
    confidenceBase: 70,
    description: 'Unusual authentication timing, impossible travel, or simultaneous multi-location login',
    match: (alerts) => {
      const loginAlerts = alerts.filter(a =>
        (a.userAction || '').match(/login|logon|auth/) ||
        (a.ruleId || '').toLowerCase().match(/login|auth/)
      );
      return loginAlerts.length >= 3;
    },
  },
  {
    id: 'CR-014',
    name: 'Rootkit / Kernel Manipulation',
    category: 'malware',
    severity: 'critical',
    mitre: 'rootkit',
    confidenceBase: 91,
    description: 'Kernel-level or low-level system manipulation detected — potential rootkit installation',
    match: (alerts) => alerts.some(a =>
      (a.ruleId || '').toLowerCase().match(/rootkit|kernel|ring0|kmod|driver.*load|dkom|syscall.*hook/)
    ),
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// ADAPTIVE CONFIDENCE ENGINE
// Dynamically adjusts confidence score based on historical evidence.
// Replaces static confidenceBase with evidence-weighted dynamic scoring.
//
// Factors:
//   1. confidenceBase        — rule's baseline (0–100)
//   2. alertVolumeBonus      — more correlated alerts = higher confidence
//   3. tiEnrichmentBonus     — AbuseIPDB score + OTX pulses boost confidence
//   4. recurrenceBonus       — same pattern fired before = higher confidence
//   5. falsePositiveDecay    — rule fires often without escalation = lower confidence
//   6. vtConfirmedBonus      — VT malicious verdict adds confidence
// ─────────────────────────────────────────────────────────────────────────────
async function computeAdaptiveConfidence(rule, alerts, companyId) {
  let score = rule.confidenceBase;

  // ── Factor 1: Alert volume bonus (more correlated events = higher confidence)
  const alertCount = alerts.length;
  if (alertCount >= 10) score += 5;
  else if (alertCount >= 5) score += 3;
  else if (alertCount >= 3) score += 1;

  // ── Factor 2: TI enrichment bonus (AbuseIPDB + OTX from alert fields)
  const tiScores = alerts
    .filter(a => a.tiEnriched && a.tiConfidence > 0)
    .map(a => a.tiConfidence || 0);
  if (tiScores.length > 0) {
    const avgTi = tiScores.reduce((s, v) => s + v, 0) / tiScores.length;
    if (avgTi >= 90) score += 8;
    else if (avgTi >= 75) score += 5;
    else if (avgTi >= 50) score += 2;
  }

  // ── Factor 3: VirusTotal confirmed malicious bonus
  const vtMalicious = alerts.filter(a => a.vtVerdict === 'malicious' && (a.vtDetections || 0) > 5);
  if (vtMalicious.length > 0) {
    const maxDetections = Math.max(...vtMalicious.map(a => a.vtDetections || 0));
    if (maxDetections >= 30) score += 7;
    else if (maxDetections >= 10) score += 4;
    else score += 2;
  }

  // ── Factor 4: Recurrence bonus — same rule fired in past 7 days
  try {
    const past7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const priorIncidents = await EdrIncident.countDocuments({
      companyId,
      category: rule.category,
      createdAt: { $gte: past7d },
      status: { $in: ['open', 'investigating', 'resolved', 'contained'] },
    });
    if (priorIncidents >= 5) score += 6;      // repeat attack campaign
    else if (priorIncidents >= 3) score += 3;
    else if (priorIncidents >= 1) score += 1;
  } catch (_) {}

  // ── Factor 5: False-positive decay — rule fires often but never escalated
  // (Fires >= 10 times in 7d but 0 resolved incidents → likely noisy rule)
  try {
    const past7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const [totalFired, resolvedCount] = await Promise.all([
      EdrIncident.countDocuments({ companyId, category: rule.category, createdAt: { $gte: past7d } }),
      EdrIncident.countDocuments({ companyId, category: rule.category, status: 'resolved', createdAt: { $gte: past7d } }),
    ]);
    if (totalFired >= 10 && resolvedCount === 0) {
      score -= 8;  // noisy rule — reduce confidence
    } else if (totalFired >= 5 && resolvedCount === 0) {
      score -= 4;
    }
  } catch (_) {}

  // ── Factor 6: Severity multiplier — critical severity alerts in window
  const criticalCount = alerts.filter(a => a.severity === 'critical').length;
  if (criticalCount >= 3) score += 4;
  else if (criticalCount >= 1) score += 2;

  // Clamp to [10, 100]
  score = Math.min(100, Math.max(10, Math.round(score)));

  return score;
}


// ─────────────────────────────────────────────────────────────────────────────
// Utility: Extract MITRE data from ruleId / category / description
// ─────────────────────────────────────────────────────────────────────────────
function extractMitre(ruleId, category, description, overrideKey) {
  const searchStr = [ruleId, category, description, overrideKey].join(' ').toLowerCase();

  // Check override key first (from correlation rule)
  if (overrideKey && MITRE_MAP[overrideKey]) return MITRE_MAP[overrideKey];

  // Try direct key match
  for (const [key, val] of Object.entries(MITRE_MAP)) {
    if (searchStr.includes(key)) return val;
  }

  // Category-based fallback
  const catMap = {
    malware:   MITRE_MAP.malware,
    network:   MITRE_MAP.c2,
    edr:       MITRE_MAP.privilege_escalation,
    usb:       MITRE_MAP.usb_autorun,
    file:      MITRE_MAP.file_modification,
    system:    MITRE_MAP.service_creation,
  };
  return catMap[category] || { id: 'T1204', name: 'User Execution', tactics: ['Execution'] };
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: Extract IOCs from an alert
// ─────────────────────────────────────────────────────────────────────────────
function extractIocs(alert) {
  const iocs = [];
  if (alert.srcip)   iocs.push({ type: 'ip',      value: alert.srcip,    context: 'Source IP' });
  if (alert.destip)  iocs.push({ type: 'ip',      value: alert.destip,   context: 'Destination IP' });
  if (alert.fileHash) iocs.push({ type: 'hash',   value: alert.fileHash,  context: `SHA256 — ${alert.fileName || alert.filePath || 'unknown'}` });
  if (alert.fileHashMd5) iocs.push({ type: 'hash', value: alert.fileHashMd5, context: `MD5 — ${alert.fileName || ''}` });
  if (alert.fileName) iocs.push({ type: 'file',   value: alert.fileName,  context: alert.filePath || 'unknown path' });
  if (alert.processName) iocs.push({ type: 'process', value: alert.processName, context: `PID: ${alert.pid || 'unknown'}` });
  if (alert.device)  iocs.push({ type: 'device',  value: alert.device,   context: 'USB device' });
  if (alert.yaraRules && alert.yaraRules.length) {
    alert.yaraRules.forEach(r => iocs.push({ type: 'yara', value: r, context: 'YARA rule match' }));
  }
  return iocs;
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: Deduplicate IOCs
// ─────────────────────────────────────────────────────────────────────────────
function dedupIocs(iocList) {
  const seen = new Set();
  return iocList.filter(ioc => {
    const key = `${ioc.type}:${ioc.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: Build AI-style analysis text
// ─────────────────────────────────────────────────────────────────────────────
function buildAnalysisText(rule, alerts, mitre, iocs, adaptiveScore) {
  const score     = adaptiveScore ?? rule.confidenceBase;
  const baseScore = rule.confidenceBase;
  const scoreDiff = score - baseScore;
  const scoreNote = scoreDiff > 0
    ? `(+${scoreDiff} from TI/VT/recurrence evidence)`
    : scoreDiff < 0
    ? `(${scoreDiff} false-positive decay applied)`
    : '(no historical adjustment)';

  const endpoint = alerts[0]?.agentName || alerts[0]?.username || 'Unknown endpoint';
  const timeRange = alerts.length > 1
    ? `${new Date(alerts[alerts.length - 1].createdAt).toISOString()} → ${new Date(alerts[0].createdAt).toISOString()}`
    : new Date(alerts[0].createdAt).toISOString();

  const ipList = [...new Set(iocs.filter(i => i.type === 'ip').map(i => i.value))];
  const hashList = [...new Set(iocs.filter(i => i.type === 'hash').map(i => i.value))];

  return `
[SOC AI Analysis — ${new Date().toISOString()}]

Correlation Rule : ${rule.id} — ${rule.name}
Affected Endpoint: ${endpoint}
Event Window     : ${timeRange}
Alert Count      : ${alerts.length} correlated event(s)
Confidence Score : ${score}% ${scoreNote}

MITRE ATT&CK     : ${mitre.id} — ${mitre.name}
Tactics          : ${(mitre.tactics || []).join(', ')}

Attack Summary:
${rule.description}

Observed Indicators:
${iocs.slice(0, 8).map(i => `  • [${i.type.toUpperCase()}] ${i.value} (${i.context})`).join('\n') || '  • No specific IOCs extracted'}
${ipList.length ? `\nSuspicious IPs: ${ipList.join(', ')}` : ''}
${hashList.length ? `Malicious Hashes: ${hashList.join(', ')}` : ''}

Event Details:
${alerts.slice(0, 5).map(a => `  • ${a.ruleId || a.eventCategory}: ${a.description || 'No description'} (${a.severity})`).join('\n')}
${alerts.length > 5 ? `  ... and ${alerts.length - 5} more events` : ''}

Classification: ${rule.category.replace(/_/g, ' ').toUpperCase()}
Severity Assessment: ${rule.severity.toUpperCase()} — ${
    rule.severity === 'critical' ? 'Immediate containment required' :
    rule.severity === 'high'     ? 'Urgent investigation needed'   :
    rule.severity === 'medium'   ? 'Monitor and investigate'       :
                                   'Low risk — document and review'
  }
`.trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// Recommended Actions based on category & severity
// ─────────────────────────────────────────────────────────────────────────────
function buildRecommendedActions(category, severity, iocs) {
  const actions = [];
  const hasIp   = iocs.some(i => i.type === 'ip');
  const hasHash = iocs.some(i => i.type === 'hash');

  // Universal
  if (severity === 'critical' || severity === 'high') {
    actions.push('Isolate endpoint immediately to prevent lateral spread');
  }

  // Category-specific
  switch (category) {
    case 'ransomware':
      actions.push('Immediately isolate endpoint — kill all suspicious processes');
      actions.push('Take VSS snapshot if accessible before it is deleted');
      actions.push('Block all outbound traffic from this endpoint');
      actions.push('Notify management and initiate incident response plan');
      actions.push('Identify patient zero and infection vector');
      actions.push('Begin backup restoration process from last clean backup');
      break;
    case 'credential_dumping':
      actions.push('Force password reset for ALL accounts on this endpoint');
      actions.push('Rotate all service account credentials immediately');
      actions.push('Check for lateral movement using dumped credentials');
      actions.push('Enable enhanced auditing on LSASS process');
      if (hasIp) actions.push('Block attacker C2 IPs at perimeter firewall');
      break;
    case 'c2_communication':
      if (hasIp) actions.push('Block destination IPs at firewall and DNS level');
      actions.push('Kill process responsible for C2 communication');
      actions.push('Review all outbound connections from this endpoint in last 24h');
      actions.push('Capture network traffic for forensic analysis');
      break;
    case 'lateral_movement':
      actions.push('Review all systems accessed from this endpoint');
      actions.push('Disable compromised credentials — reset affected passwords');
      actions.push('Block RDP/SMB from this endpoint to internal network');
      actions.push('Check for persistence mechanisms on all touched systems');
      break;
    case 'malware':
      if (hasHash) actions.push('Quarantine malicious file(s) immediately');
      actions.push('Run full YARA + AV scan on affected endpoint');
      actions.push('Check for additional malware droppers or persistence');
      if (hasHash) actions.push('Submit file hash to threat intelligence — block enterprise-wide');
      actions.push('Analyze parent process for additional infection vectors');
      break;
    case 'privilege_escalation':
      actions.push('Revoke elevated privileges on affected account');
      actions.push('Audit SUID/SGID binaries (Linux) or token privileges (Windows)');
      actions.push('Review sudo configuration and recent command history');
      actions.push('Check for newly created privileged accounts');
      break;
    case 'data_exfiltration':
      if (hasIp) actions.push('Block external destination IPs immediately');
      actions.push('Identify what data was accessed and exfiltrated');
      actions.push('Invoke data breach notification procedures if PII involved');
      actions.push('Enable DLP monitoring on all endpoints');
      break;
    case 'persistence':
      actions.push('Remove unauthorized scheduled tasks, services, and startup entries');
      actions.push('Audit registry autorun keys');
      actions.push('Check cron jobs and systemd units (Linux)');
      actions.push('Review recently installed software');
      break;
    case 'usb_threat':
      actions.push('Block USB device and quarantine any transferred files');
      actions.push('Scan endpoint with YARA rules for USB-dropped malware');
      actions.push('Enforce USB device control policies');
      break;
    case 'zero_day':
      actions.push('Isolate endpoint immediately — escalate to Tier-3 / IR team');
      actions.push('Capture memory dump for offline analysis');
      actions.push('Apply emergency patches if available');
      actions.push('Enable enhanced kernel-level monitoring');
      break;
    default:
      actions.push('Investigate alert source and collect additional evidence');
      actions.push('Review process tree and network connections at time of detection');
  }

  // General recommendations
  actions.push('Document all findings in the incident ticket');
  actions.push('Update MITRE ATT&CK coverage map after investigation');

  return actions;
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN CORRELATION ENGINE
// Called after each alert is ingested. Looks back over a 15-min window
// to find correlated events and generate incidents.
// ─────────────────────────────────────────────────────────────────────────────
async function correlateAlerts(alert, io) {
  try {
    const windowMs    = 15 * 60 * 1000; // 15 minutes
    const windowStart = new Date(Date.now() - windowMs);

    // Fetch recent alerts for same system or same company (broader scope)
    const query = {
      companyId: alert.companyId,
      createdAt: { $gte: windowStart },
      ticketOpenedAt: null,
      ticketSource: { $ne: 'soar' },
      socCaseType: { $ne: 'ticket' },
      // Exclude alerts already incorporated into a resolved/contained incident
      _id: { $ne: alert._id },
    };
    if (alert.systemId) query.systemId = alert.systemId;

    const recentAlerts = await Alert.find(query)
      .sort({ createdAt: -1 })
      .limit(50)
      .lean();

    // Include the triggering alert
    const allAlerts = [alert, ...recentAlerts];

    for (const rule of CORRELATION_RULES) {
      if (!rule.match(allAlerts)) continue;
      const claim = await claimAlertsForIncident(allAlerts.map(item => item._id), alert.companyId);
      const claimedSet = new Set(claim.claimedIds.map(String));
      if (!claimedSet.has(String(alert._id))) return null;
      const incidentAlerts = allAlerts.filter(item => claimedSet.has(String(item._id)));
      const networkAlertIds = networkEvidenceAlertIds(incidentAlerts);

      // Check if an open incident for this rule+system already exists (24h window)
      const existingIncident = await EdrIncident.findOne({
        companyId: alert.companyId,
        // Match by category to avoid duplicate incidents
        category:  rule.category,
        status:    { $in: ['open', 'investigating'] },
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
        ...(alert.systemId && { systemId: alert.systemId }),
      });

      if (existingIncident) {
        // Recompute adaptive confidence — new evidence may raise the score
        const newConfidence = await computeAdaptiveConfidence(rule, incidentAlerts, alert.companyId);
        await EdrIncident.findByIdAndUpdate(existingIncident._id, {
          $addToSet: {
            alertIds: alert._id,
            ...(networkAlertIds.length ? { networkEvidenceAlertIds: { $each: networkAlertIds } } : {}),
          },
          $inc:      { sourceAlertCount: 1 },
          lastEventAt: new Date(),
          ...(networkAlertIds.length ? { networkInvolved: true } : {}),
          // Escalate severity if needed
          ...(severityOrder(rule.severity) > severityOrder(existingIncident.severity) && {
            severity: rule.severity
          }),
          // Update confidence if new evidence is stronger
          ...(newConfidence > (existingIncident.confidenceScore || 0) && {
            confidenceScore: newConfidence
          }),
        });
        continue;
      }

      // Build new incident
      const iocs              = dedupIocs(incidentAlerts.flatMap(a => extractIocs(a)));
      const mitre             = extractMitre(alert.ruleId, alert.eventCategory, alert.description, rule.mitre);
      // → ADAPTIVE CONFIDENCE: dynamically computed from historical + TI + VT evidence
      const adaptiveScore     = await computeAdaptiveConfidence(rule, incidentAlerts, alert.companyId);
      const analysis          = buildAnalysisText(rule, incidentAlerts, mitre, iocs, adaptiveScore);
      const actions           = buildRecommendedActions(rule.category, rule.severity, iocs);

      const incident = await EdrIncident.create({
        companyId:    alert.companyId,
        systemId:     alert.systemId,
        departmentId: alert.departmentId,
        title:        `[${rule.severity.toUpperCase()}] ${rule.name}`,
        description:  rule.description,
        severity:     rule.severity,
        status:       'open',
        assignedTo:   incidentAlerts.find(item => item.assignedTo)?.assignedTo || null,
        category:     rule.category,
        mitreTechnique:     mitre.id,
        mitreTechniqueName: mitre.name,
        mitreTactics:       mitre.tactics,
        alertIds:           incidentAlerts.map(a => a._id),
        networkInvolved:    networkAlertIds.length > 0,
        networkEvidenceAlertIds: networkAlertIds,
        affectedEndpoint:   alert.agentName || alert.hostname,
        affectedUser:       alert.username,
        agentId:            alert.agentId,
        agentName:          alert.agentName,
        iocs,
        confidenceScore:    adaptiveScore,   // ← dynamic, not static
        aiAnalysis:         analysis,
        recommendedActions: actions,
        sourceAlertCount:   incidentAlerts.length,
        firstEventAt:       incidentAlerts[incidentAlerts.length - 1]?.createdAt || new Date(),
        lastEventAt:        new Date(),
        rawCorrelationData: { ruleId: rule.id, alertCount: incidentAlerts.length, baseScore: rule.confidenceBase, adaptiveScore },
      });

      console.log(`[SOC-AI] Incident: ${incident.title} | Rule: ${rule.id} | Confidence: ${rule.confidenceBase}% → ${adaptiveScore}% (adaptive)`);

      autoScanCorrelationFinding(incident, { io, source: 'edr_incident_correlation' }).catch((err) => {
        console.error('[SOC-AI] Velociraptor auto-scan error:', err.message);
      });

      // Emit via Socket.IO to company room and superadmin
      if (io) {
        io.to(`company:${alert.companyId}`).emit('edr:incident:new', incident);
        io.to('superadmin').emit('edr:incident:new', incident);
      }

      // Only trigger one incident per alert (the highest priority matching rule)
      break;
    }
  } catch (err) {
    console.error('[SOC-AI] Correlation error:', err.message);
  }
}

function severityOrder(s) {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s] || 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// EDR Response Actions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Log a response action taken on an incident.
 * Actual enforcement (kill process, quarantine, isolate, block IP) is performed
 * by the SOC Agent via the existing firewall/isolation routes — this service
 * records it and emits the socket event.
 */
async function logResponseAction(incidentId, action, target, result, takenBy) {
  const log = { action, target, result, takenBy, takenAt: new Date() };
  await EdrIncident.findByIdAndUpdate(incidentId, {
    $push: { actionsLog: log },
  });
  return log;
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat Hunting — proactive scan over last 24h of alerts
// ─────────────────────────────────────────────────────────────────────────────
async function runThreatHunt(companyId) {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const alerts = await Alert.find({
    companyId,
    createdAt: { $gte: since },
  }).lean();

  const hunts = [];

  // Hunt 1: Beaconing — same external IP contacted many times
  const ipCounts = {};
  alerts.filter(a => a.destip && a.eventCategory === 'network').forEach(a => {
    ipCounts[a.destip] = (ipCounts[a.destip] || 0) + 1;
  });
  for (const [ip, count] of Object.entries(ipCounts)) {
    if (count >= 10) {
      hunts.push({
        type: 'beaconing',
        title: `Beaconing: ${count} connections to ${ip}`,
        severity: count >= 20 ? 'critical' : 'high',
        mitre: 'T1071.001',
        details: `${count} outbound connections to ${ip} suggest C2 beaconing`,
        affectedAlerts: alerts.filter(a => a.destip === ip).length,
      });
    }
  }

  // Hunt 2: Multiple unique malware detections on same endpoint
  const agentMalware = {};
  alerts.filter(a => a.eventCategory === 'malware').forEach(a => {
    const key = a.agentName || a.systemId?.toString() || 'unknown';
    agentMalware[key] = (agentMalware[key] || 0) + 1;
  });
  for (const [agent, count] of Object.entries(agentMalware)) {
    if (count >= 3) {
      hunts.push({
        type: 'malware_cluster',
        title: `Malware cluster: ${count} detections on ${agent}`,
        severity: 'high',
        mitre: 'T1204',
        details: `${count} malware events on ${agent} within 24h — endpoint likely compromised`,
        affectedAlerts: count,
      });
    }
  }

  // Hunt 3: Impossible travel (multiple geoCountry in short window)
  const userGeos = {};
  alerts.filter(a => a.username && a.geoCountry).forEach(a => {
    if (!userGeos[a.username]) userGeos[a.username] = new Set();
    userGeos[a.username].add(a.geoCountry);
  });
  for (const [user, countries] of Object.entries(userGeos)) {
    if (countries.size >= 2) {
      hunts.push({
        type: 'impossible_travel',
        title: `Impossible travel: ${user} logged from ${countries.size} countries`,
        severity: 'high',
        mitre: 'T1078',
        details: `User ${user} activity from: ${[...countries].join(', ')} — possible account takeover`,
        affectedAlerts: alerts.filter(a => a.username === user).length,
      });
    }
  }

  // Hunt 4: High-severity under-observation alerts (VT missing)
  const underObs = alerts.filter(a => a.underObservation && a.eventCategory === 'malware');
  if (underObs.length >= 3) {
    hunts.push({
      type: 'vt_gap',
      title: `${underObs.length} unresolved malware events awaiting VT intel`,
      severity: 'medium',
      mitre: 'T1204',
      details: `${underObs.length} malware detections with missing VT verdict — prioritize manual analysis`,
      affectedAlerts: underObs.length,
    });
  }

  // Hunt 5: Brute force surge
  const bruteAlerts = alerts.filter(a =>
    (a.userAction || '') === 'brute_force' ||
    (a.ruleId || '').toLowerCase().match(/brute|failed.*login/)
  );
  if (bruteAlerts.length >= 10) {
    hunts.push({
      type: 'brute_surge',
      title: `Brute force surge: ${bruteAlerts.length} auth failures detected`,
      severity: bruteAlerts.length >= 30 ? 'critical' : 'high',
      mitre: 'T1110',
      details: `${bruteAlerts.length} authentication failures in 24h — active brute force campaign`,
      affectedAlerts: bruteAlerts.length,
    });
  }

  return { hunts, totalAlerts: alerts.length, scannedAt: new Date() };
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard Statistics
// ─────────────────────────────────────────────────────────────────────────────
async function getEdrDashboardStats(companyId) {
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const incidentObjectId = require('mongoose').Types.ObjectId.createFromHexString(companyId.toString());

  const [
    incidents7d,
    incidentsCritical,
    incidentsOpen,
    alerts24h,
    alertsCritical24h,
    malware24h,
    c2Detected,
    lateralMovement,
    endpointsMonitored,
    recentIncidents,
    categoryBreakdown,
    severityBreakdown,
  ] = await Promise.all([
    EdrIncident.countDocuments({ companyId, createdAt: { $gte: since24h } }),
    EdrIncident.countDocuments({ companyId, severity: 'critical', status: { $in: ['open', 'investigating'] }, createdAt: { $gte: since24h } }),
    EdrIncident.countDocuments({ companyId, status: { $in: ['open', 'investigating'] }, createdAt: { $gte: since24h } }),
    Alert.countDocuments({ companyId, createdAt: { $gte: since24h } }),
    Alert.countDocuments({ companyId, severity: 'critical', createdAt: { $gte: since24h } }),
    Alert.countDocuments({ companyId, eventCategory: 'malware', createdAt: { $gte: since24h } }),
    EdrIncident.countDocuments({ companyId, category: 'c2_communication', createdAt: { $gte: since24h } }),
    EdrIncident.countDocuments({ companyId, category: 'lateral_movement', createdAt: { $gte: since24h } }),
    System.countDocuments({ companyId, isActive: true }),
    EdrIncident.find({ companyId, createdAt: { $gte: since24h } })
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('systemId', 'name hostname')
      .lean(),
    EdrIncident.aggregate([
      { $match: { companyId: incidentObjectId, createdAt: { $gte: since24h } } },
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]),
    EdrIncident.aggregate([
      { $match: { companyId: incidentObjectId, createdAt: { $gte: since24h } } },
      { $group: { _id: '$severity', count: { $sum: 1 } } },
    ]),
  ]);

  // MTTR — mean time to resolve (resolved incidents)
  const resolvedSample = await EdrIncident.find({
    companyId,
    status: 'resolved',
    resolvedAt: { $exists: true },
    createdAt: { $gte: since24h },
  }).select('createdAt resolvedAt').lean();

  let mttrHours = null;
  if (resolvedSample.length > 0) {
    const totalMs = resolvedSample.reduce((sum, i) =>
      sum + (new Date(i.resolvedAt) - new Date(i.createdAt)), 0);
    mttrHours = +(totalMs / resolvedSample.length / 3_600_000).toFixed(1);
  }

  return {
    kpis: {
      incidents7d,
      incidentsCritical,
      incidentsOpen,
      alerts24h,
      alertsCritical24h,
      malware24h,
      c2Detected,
      lateralMovement,
      endpointsMonitored,
      mttrHours,
    },
    recentIncidents,
    categoryBreakdown: categoryBreakdown.map(c => ({ category: c._id, count: c.count })),
    severityBreakdown: severityBreakdown.map(s => ({ severity: s._id, count: s.count })),
  };
}

module.exports = {
  correlateAlerts,
  runThreatHunt,
  getEdrDashboardStats,
  logResponseAction,
  extractIocs,
  MITRE_MAP,
  CORRELATION_RULES,
};
