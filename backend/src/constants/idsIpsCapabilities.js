const CAPABILITY_GROUPS = [
  {
    id: 'traffic',
    title: 'Traffic Monitoring',
    sensor: 'SOC Agent network collector / IDS sensor',
    capabilities: [
      'Incoming Traffic', 'Outgoing Traffic', 'Internal Traffic', 'Network Packets',
      'TCP Traffic', 'UDP Traffic', 'ICMP Traffic', 'IPv4/IPv6 Traffic',
      'Session Monitoring', 'Connection Monitoring',
    ],
  },
  {
    id: 'recon',
    title: 'Network Reconnaissance Detection',
    sensor: 'IDS agent + Suricata/Zeek ingestion',
    capabilities: [
      'Port Scan', 'SYN Scan', 'FIN Scan', 'NULL Scan', 'XMAS Scan', 'ACK Scan',
      'UDP Scan', 'Ping Sweep', 'Host Discovery', 'Service Enumeration',
      'Banner Grabbing',
    ],
  },
  {
    id: 'web',
    title: 'Web Application Attack Detection',
    sensor: 'WAF proxy + IDS alert ingestion',
    capabilities: [
      'SQL Injection', 'Blind SQL Injection', 'XSS', 'Stored XSS', 'Reflected XSS',
      'CSRF', 'Command Injection', 'Remote Code Execution (RCE)', 'File Upload Attack',
      'Path Traversal', 'Directory Traversal', 'Local File Inclusion (LFI)',
      'Remote File Inclusion (RFI)', 'XXE Attack', 'SSRF', 'SSTI',
    ],
  },
  {
    id: 'auth',
    title: 'Authentication Attack Detection',
    sensor: 'OS auth logs + IDS policy',
    capabilities: [
      'Brute Force', 'Password Spraying', 'Credential Stuffing', 'Login Flood',
      'Multiple Failed Login Attempts', 'Privilege Escalation Attempts',
    ],
  },
  {
    id: 'malware',
    title: 'Malware Detection',
    sensor: 'EDR/YARA/VT agent, escalated to IDS/IPS only when network/block action is required',
    capabilities: [
      'Virus', 'Worm', 'Trojan', 'Spyware', 'Rootkit', 'Ransomware', 'Botnet Traffic',
      'Crypto Miner', 'Backdoor', 'Malicious Payload',
    ],
  },
  {
    id: 'c2',
    title: 'Command & Control (C2)',
    sensor: 'IDS network collector + threat intelligence',
    capabilities: [
      'HTTP Beaconing', 'HTTPS Beaconing', 'DNS Tunneling', 'Reverse Shell',
      'C2 Communication', 'IRC C2', 'TOR Traffic',
    ],
  },
  {
    id: 'dos',
    title: 'Denial of Service Detection',
    sensor: 'IDS rate/anomaly rules + network IDS sensors',
    capabilities: [
      'DoS Attack', 'DDoS Attack', 'SYN Flood', 'UDP Flood', 'ICMP Flood',
      'HTTP Flood', 'HTTPS Flood', 'Slowloris Attack',
    ],
  },
  {
    id: 'spoofing',
    title: 'Network Spoofing Detection',
    sensor: 'ARP/DNS cache poison detector + IDS ingestion',
    capabilities: [
      'ARP Spoofing', 'ARP Poisoning', 'DNS Spoofing', 'DNS Cache Poisoning',
      'IP Spoofing', 'MAC Spoofing',
    ],
  },
  {
    id: 'protocols',
    title: 'Protocol Monitoring',
    sensor: 'SOC Agent network collector / Zeek / Suricata',
    capabilities: [
      'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH', 'SMTP', 'POP3', 'IMAP',
      'SMB', 'LDAP', 'SNMP', 'RDP', 'Telnet',
    ],
  },
  {
    id: 'threat_intel',
    title: 'Threat Intelligence Matching',
    sensor: 'AbuseIPDB + OTX + VirusTotal + IDS signatures',
    capabilities: [
      'Malicious IP Detection', 'Malicious Domain Detection', 'Malicious URL Detection',
      'IOC Matching', 'CVE Exploit Detection', 'Known Exploit Detection',
      'Signature Match', 'Zero-Day Behavior Detection',
    ],
  },
  {
    id: 'anomaly',
    title: 'Anomaly Detection',
    sensor: 'SOC Agent network baseline + IDS thresholds',
    capabilities: [
      'Unusual Traffic Volume', 'Unusual Packet Size', 'Suspicious Connection Rate',
      'Unknown Protocol Usage', 'Abnormal Network Behavior', 'Suspicious Payload',
      'Traffic Spike Detection',
    ],
  },
  {
    id: 'prevention',
    title: 'IPS Prevention Actions',
    sensor: 'IPS server + nftables/Windows Defender/log-only fallback',
    capabilities: [
      'Block Source IP (all supported OS)', 'Block Destination IP (all supported OS)',
      'Inline Packet Drop (Linux NFQUEUE)',
      'Reset TCP Session', 'Block Port', 'Block Protocol', 'Block URL',
      'Block Domain', 'Quarantine Connection', 'Temporary IP Block',
      'Permanent IP Block', 'Auto Blacklist',
    ],
  },
  {
    id: 'alert_fields',
    title: 'IDS/IPS Alerts & Logs',
    sensor: 'Alert schema',
    capabilities: [
      'Alert ID', 'Attack Type', 'Threat Severity', 'Signature Name', 'Source IP',
      'Destination IP', 'Source Port', 'Destination Port', 'Protocol', 'Timestamp',
      'Packet Count', 'Action (Detected / Blocked)', 'Sensor Name', 'Rule ID',
      'CVE ID (if available)', 'MITRE ATT&CK Mapping (if available)',
    ],
  },
];

const ATTACK_TYPE_PATTERNS = [
  ['SQL Injection', /\b(sql injection|sqli|union select|sqlmap|blind sql)\b/i],
  ['Blind SQL Injection', /\bblind sql/i],
  ['XSS', /\b(cross[- ]site scripting|xss|stored xss|reflected xss)\b|<script\b/i],
  ['CSRF', /\b(csrf|cross[- ]site request forgery)\b/i],
  ['Command Injection', /\b(command injection|shell injection|cmdi)\b/i],
  ['Remote Code Execution (RCE)', /\b(remote code execution|rce|code execution)\b/i],
  ['File Upload Attack', /\b(file upload|upload attack|webshell upload)\b/i],
  ['Path Traversal', /\b(path traversal|directory traversal|lfi|rfi|local file inclusion|remote file inclusion)\b|\.\.[/\\]/i],
  ['XXE Attack', /\b(xxe|xml external entity)\b/i],
  ['SSRF', /\b(ssrf|server-side request forgery|server side request forgery)\b/i],
  ['SSTI', /\b(ssti|server-side template injection|template injection)\b/i],
  ['Port Scan', /\b(port scan|network scan|nmap|masscan|service enumeration|banner grabbing)\b/i],
  ['SYN Scan', /\bsyn scan\b/i],
  ['FIN Scan', /\bfin scan\b/i],
  ['NULL Scan', /\bnull scan\b/i],
  ['XMAS Scan', /\bxmas scan\b/i],
  ['ACK Scan', /\back scan\b/i],
  ['UDP Scan', /\budp scan\b/i],
  ['Ping Sweep', /\bping sweep|host discovery\b/i],
  ['Brute Force', /\b(brute force|multiple failed login|login flood)\b/i],
  ['Password Spraying', /\bpassword spraying\b/i],
  ['Credential Stuffing', /\bcredential stuffing\b/i],
  ['Privilege Escalation Attempts', /\bprivilege escalation\b/i],
  ['Malware / C2', /\b(malware|trojan|virus|worm|spyware|rootkit|botnet|backdoor|malicious payload|command and control|c2 communication|beaconing|reverse shell|irc c2|tor traffic)\b/i],
  ['Ransomware', /\bransomware|file encryption attack\b/i],
  ['Crypto Miner', /\bcrypto miner|cryptominer|coinminer\b/i],
  ['DNS Tunneling', /\bdns tunneling\b/i],
  ['DoS Attack', /\b(denial of service|dos attack|slowloris)\b/i],
  ['DDoS Attack', /\b(ddos|distributed denial of service)\b/i],
  ['SYN Flood', /\bsyn flood\b/i],
  ['UDP Flood', /\budp flood\b/i],
  ['ICMP Flood', /\bicmp flood\b/i],
  ['HTTP Flood', /\bhttp flood|https flood\b/i],
  ['ARP Spoofing', /\barp spoof|arp poison/i],
  ['DNS Spoofing', /\bdns spoof|dns cache poison/i],
  ['IP Spoofing', /\bip spoof/i],
  ['MAC Spoofing', /\bmac spoof/i],
  ['Malicious IP Detection', /\bmalicious ip|threat intelligence network|ioc match/i],
  ['Malicious Domain Detection', /\bmalicious domain/i],
  ['Malicious URL Detection', /\bmalicious url/i],
  ['CVE Exploit Detection', /\bcve-\d{4}-\d+|known exploit|exploit attempt|zero[- ]day|0day/i],
  ['Suspicious Payload', /\bsuspicious payload|unknown protocol|abnormal network|traffic spike|unusual packet|unusual traffic|suspicious connection rate/i],
  ['Phishing', /\bphishing|credential harvest/i],
  ['Unauthorized Access', /\bunauthorized access|access attempt|permission denied\b/i],
  ['Suspicious DNS Activity', /\bdns query|dns lookup|suspicious dns\b/i],
  ['Data Exfiltration', /\bdata exfiltration|exfiltration|data leak\b/i],
  ['Buffer Overflow Exploit', /\bbuffer overflow|overflow exploit|stack overflow\b/i],
  ['Protocol Anomaly', /\bssl certificate|certificate anomaly|protocol command|stream packet|invalid timestamp|stream event\b/i],
  ['Suspicious Process Execution', /\bprocess execution|suspicious process\b/i],
  ['Policy Violation', /\bexternal ip lookup|ip lookup|policy violation\b/i],
];

function listAttackTypes() {
  return [...new Set(ATTACK_TYPE_PATTERNS.map(([name]) => name))];
}

function resolveAttackType(...values) {
  const text = values.filter(Boolean).map(String).join(' ').trim();
  if (!text) return 'Unknown Attack';
  const normalized = text.toLowerCase();
  const exact = listAttackTypes().find(name => normalized === name.toLowerCase());
  if (exact) return exact;
  const matched = ATTACK_TYPE_PATTERNS.find(([, pattern]) => pattern.test(text));
  return matched?.[0] || 'Unknown Attack';
}

module.exports = {
  CAPABILITY_GROUPS,
  ATTACK_TYPE_PATTERNS,
  listAttackTypes,
  resolveAttackType,
};
