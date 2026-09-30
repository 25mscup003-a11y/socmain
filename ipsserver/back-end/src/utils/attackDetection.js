/**
 * Attack Detection System — SOC4 IPS Server v3.0
 * =================================================
 * Automatically detects, classifies, and scores attacks.
 *
 * Supported Attack Types:
 *   - SQL Injection (SQLi)
 *   - Cross-Site Scripting (XSS)
 *   - Brute Force
 *   - DDoS / Flood
 *   - Port Scan
 *   - Malware / Virus Signature
 *   - Botnet Activity
 *   - Data Exfiltration
 *   - Privilege Escalation
 *   - Credential Theft
 *   - Web Shell Injection
 *   - Command Injection
 *   - Path Traversal / LFI
 *   - SSRF
 *   - Log4Shell (CVE-2021-44228)
 *   - DNS Tunneling
 */

const logger = require('./logger');

// ── Attack Type Registry ──────────────────────────────────────────────────────
const ATTACK_TYPES = {
  SQL_INJECTION:       'SQL Injection',
  XSS:                 'Cross-Site Scripting (XSS)',
  BRUTE_FORCE:         'Brute Force',
  DDOS:                'Distributed Denial of Service (DDoS)',
  PORT_SCAN:           'Port Scan',
  MALWARE:             'Malware/Virus',
  BOTNET:              'Botnet Activity',
  DATA_EXFILTRATION:   'Data Exfiltration',
  PRIVILEGE_ESCALATION:'Privilege Escalation',
  CREDENTIAL_THEFT:    'Credential Theft',
  WEB_SHELL:           'Web Shell Injection',
  COMMAND_INJECTION:   'Command Injection',
  PATH_TRAVERSAL:      'Path Traversal / LFI',
  SSRF:                'Server-Side Request Forgery (SSRF)',
  LOG4SHELL:           'Log4Shell (CVE-2021-44228)',
  DNS_TUNNEL:          'DNS Tunneling',
  SUSPICIOUS:          'Suspicious Activity',
};

// ── Pattern Libraries ─────────────────────────────────────────────────────────
const PATTERNS = {
  SQL_INJECTION: [
    /('|")\s*(OR|AND)\s*('|")?true/i,
    /union\s+(all\s+)?select/i,
    /drop\s+table/i,
    /insert\s+into/i,
    /delete\s+from/i,
    /update\s+\w+\s+set/i,
    /exec\s*\(/i,
    /execute\s*\(/i,
    /xp_cmdshell/i,
    /;\s*--/,
    /\/\*.*?\*\//s,
    /'\s*;\s*drop/i,
    /char\s*\(\s*\d/i,
    /0x[0-9a-f]{4,}/i,
    /waitfor\s+delay/i,
    /select.*from.*information_schema/i,
    /load_file\s*\(/i,
    /into\s+outfile/i,
  ],

  XSS: [
    /<script[^>]*>/i,
    /javascript:/i,
    /onerror\s*=/i,
    /onload\s*=/i,
    /onclick\s*=/i,
    /on\w+\s*=\s*["']?\s*\w/i,
    /<iframe/i,
    /eval\s*\(/i,
    /document\.cookie/i,
    /document\.write\s*\(/i,
    /window\.location/i,
    /<img[^>]+src[^>]+onerror/i,
    /expression\s*\(/i,
    /vbscript:/i,
    /&#x?[0-9a-f]+;/i,
  ],

  COMMAND_INJECTION: [
    /[;&|`$(){}[\]\\]/,
    /\b(exec|system|shell_exec|passthru|popen|proc_open)\s*\(/i,
    /\|\s*(cat|ls|id|whoami|uname|pwd|wget|curl)\b/i,
    /;\s*(cat|ls|id|whoami|uname|pwd|wget|curl)\b/i,
    /`[^`]+`/,
    /\$\([^)]+\)/,
  ],

  PATH_TRAVERSAL: [
    /\.\.[\/\\]/,
    /%2e%2e[%2f%5c]/i,
    /\.\.%2f/i,
    /%252e%252e/i,
    /\/etc\/passwd/i,
    /\/etc\/shadow/i,
    /\/proc\/self/i,
    /\/windows\/system32/i,
    /c:\\windows/i,
  ],

  WEB_SHELL: [
    /\b(c99|r57|b374k|wso|FilesMan)\b/i,
    /eval\s*\(\s*base64_decode/i,
    /eval\s*\(\s*gzinflate/i,
    /preg_replace\s*\(['"]\//i,
    /assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i,
    /\$_(GET|POST|REQUEST|COOKIE)\s*\[['"]\w+['"]\]\s*\(/i,
    /phpinfo\s*\(\s*\)/i,
    /system\s*\(\s*\$_(GET|POST)/i,
  ],

  SSRF: [
    /http:\/\/127\.\d+\.\d+\.\d+/i,
    /http:\/\/localhost/i,
    /http:\/\/169\.254\.169\.254/i,  // AWS metadata
    /http:\/\/192\.168\.\d+\.\d+/i,
    /file:\/\//i,
    /dict:\/\//i,
    /gopher:\/\//i,
    /ftp:\/\/\d+\.\d+\.\d+\.\d+/i,
    /http:\/\/0\.0\.0\.0/i,
  ],

  LOG4SHELL: [
    /\$\{jndi:/i,
    /\$\{.*jndi:.*ldap/i,
    /\$\{.*:.*:.*\}/i,  // obfuscated variants
    /%24%7bjndi/i,       // URL encoded
    /\$\{lower:/i,
    /\$\{upper:/i,
  ],

  DNS_TUNNEL: [
    // Long subdomain labels (>63 chars) or many subdomains (>5 levels)
    /([a-z0-9]{32,})\.\w+\.\w+/i,
    /[a-z0-9]{20,}\.[a-z0-9]{20,}\./i,
  ],

  CREDENTIAL_THEFT: [
    /password\s*=|passwd\s*=|pwd\s*=/i,
    /api[_-]?key\s*=/i,
    /authorization:\s*bearer\s+[a-z0-9._-]{20,}/i,
    /token\s*=\s*[a-z0-9._-]{20,}/i,
    /private[_-]?key\s*=/i,
    /secret[_-]?key\s*=/i,
    /\b[A-Za-z0-9+/]{64,}={0,2}\b/,  // long base64 (possible credential)
  ],

  DATA_EXFILTRATION: [
    /exfil/i,
    /\bdata:\s*image\/[a-z]+;base64/i,
    /\bdownload.*confidential/i,
    /Content-Disposition.*attachment/i,
  ],
};

// ── Known Malware Signatures (simplified hash list) ───────────────────────────
const MALWARE_SIGNATURES = [
  'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR',  // EICAR test string
  'TVqQAAMAAAAEAAAA',                        // PE header base64
  '4d5a9000',                                // PE header hex
];

// ── Rate Tracking (in-memory — per-IP request counts) ────────────────────────
const ipRequestMap  = new Map();  // ip → { count, firstSeen, ports: Set }
const ipFailedLogin = new Map();  // ip → { count, firstSeen }

const RATE_WINDOW_MS = 60 * 1000;  // 1-minute rolling window

// ── Core: Detect Attack Type ──────────────────────────────────────────────────
/**
 * Detect attack type from a payload string.
 * @param {string|object} data
 * @returns {{ type: string, patterns: string[] } | null}
 */
function detectAttackType(data) {
  if (!data) return null;

  const str = typeof data === 'string' ? data : JSON.stringify(data);

  // Check all pattern groups in priority order
  const checks = [
    ['LOG4SHELL',        PATTERNS.LOG4SHELL],
    ['COMMAND_INJECTION',PATTERNS.COMMAND_INJECTION],
    ['SQL_INJECTION',    PATTERNS.SQL_INJECTION],
    ['PATH_TRAVERSAL',   PATTERNS.PATH_TRAVERSAL],
    ['SSRF',             PATTERNS.SSRF],
    ['WEB_SHELL',        PATTERNS.WEB_SHELL],
    ['XSS',              PATTERNS.XSS],
    ['CREDENTIAL_THEFT', PATTERNS.CREDENTIAL_THEFT],
    ['DATA_EXFILTRATION',PATTERNS.DATA_EXFILTRATION],
    ['DNS_TUNNEL',       PATTERNS.DNS_TUNNEL],
  ];

  for (const [key, patterns] of checks) {
    const matched = patterns.filter(p => p.test(str));
    if (matched.length > 0) {
      return {
        type:     ATTACK_TYPES[key],
        key,
        patterns: matched.map(p => p.toString()),
      };
    }
  }

  // Check malware signatures
  if (MALWARE_SIGNATURES.some(sig => str.includes(sig))) {
    return { type: ATTACK_TYPES.MALWARE, key: 'MALWARE', patterns: ['signature_match'] };
  }

  return null;
}

// ── Core: Classify Threat ─────────────────────────────────────────────────────
/**
 * Full threat classification with scoring.
 * @param {object} factors
 * @param {string}  [factors.ip]                - Source IP
 * @param {number}  [factors.failedAttempts]     - Failed auth attempts
 * @param {number}  [factors.requestsPerSecond]  - RPS for this IP
 * @param {string}  [factors.payload]            - Request payload
 * @param {string}  [factors.ipReputation]       - 'malicious'|'botnet'|'clean'
 * @param {string}  [factors.attackType]         - Manually provided type string
 * @param {number}  [factors.portCount]          - Distinct ports scanned
 * @returns {object} { threatLevel, attackType, confidence, score, recommendedAction }
 */
function classifyThreat(factors = {}) {
  const {
    ip = '',
    failedAttempts = 0,
    requestsPerSecond = 0,
    payload = '',
    ipReputation = null,
    attackType: manualType = null,
    portCount = 0,
  } = factors;

  let score = 0;
  let attackType = null;
  const confidence = {
    sql_injection: 0,
    xss: 0,
    brute_force: 0,
    ddos: 0,
    port_scan: 0,
    malware: 0,
    web_shell: 0,
    command_injection: 0,
  };

  // ── Manual override ──
  if (manualType) {
    attackType = manualType;
    score += 60;
  }

  // ── Brute Force ──
  if (failedAttempts > 0) {
    score += Math.min(80, failedAttempts * 8);
    confidence.brute_force = Math.min(100, failedAttempts * 10);
    if (failedAttempts > 5) attackType = attackType || ATTACK_TYPES.BRUTE_FORCE;
  }

  // ── DDoS / Volume ──
  if (requestsPerSecond > 50) {
    score += Math.min(90, requestsPerSecond / 5);
    confidence.ddos = Math.min(100, requestsPerSecond);
    attackType = attackType || ATTACK_TYPES.DDOS;
  }

  // ── IP Reputation ──
  if (ipReputation === 'malicious') { score += 70; attackType = attackType || ATTACK_TYPES.BOTNET; confidence.ddos = 90; }
  if (ipReputation === 'botnet')    { score += 80; attackType = ATTACK_TYPES.BOTNET; confidence.ddos = 95; }
  if (ipReputation === 'tor_exit')  { score += 40; }
  if (ipReputation === 'proxy')     { score += 20; }

  // ── Port Scan ──
  if (portCount > 10) {
    score += Math.min(70, portCount * 3);
    confidence.port_scan = Math.min(100, portCount * 5);
    attackType = attackType || ATTACK_TYPES.PORT_SCAN;
  }

  // ── Payload Analysis ──
  if (payload) {
    const detected = detectAttackType(payload);
    if (detected) {
      score += 75;
      attackType = attackType || detected.type;
      const key = detected.key.toLowerCase();
      if (confidence[key] !== undefined) confidence[key] = 95;
      else if (detected.key === 'SQL_INJECTION') confidence.sql_injection = 95;
      else if (detected.key === 'XSS')           confidence.xss = 95;
      else if (detected.key === 'WEB_SHELL')     confidence.web_shell = 95;
      else if (detected.key === 'COMMAND_INJECTION') confidence.command_injection = 95;
      else if (detected.key === 'MALWARE')       confidence.malware = 95;
    }
  }

  // ── Calculate threat level from score ──
  let threatLevel;
  if      (score >= 80) threatLevel = 'critical';
  else if (score >= 55) threatLevel = 'high';
  else if (score >= 30) threatLevel = 'medium';
  else                  threatLevel = 'low';

  // Normalize confidence values
  Object.keys(confidence).forEach(k => { confidence[k] = Math.min(100, confidence[k]); });

  return {
    threatLevel,
    attackType: attackType || ATTACK_TYPES.SUSPICIOUS,
    confidence,
    score: Math.min(100, Math.round(score)),
    recommendedAction: getRecommendedAction(threatLevel, attackType),
  };
}

// ── Core: Recommended Actions ─────────────────────────────────────────────────
/**
 * Get recommended response actions based on threat level + type.
 */
function getRecommendedAction(threatLevel, attackType) {
  const actions = [];

  if (threatLevel === 'critical') {
    actions.push('block_ip', 'alert_soc', 'log_forensics', 'isolate_system');
    if (attackType === ATTACK_TYPES.BOTNET || attackType === ATTACK_TYPES.DDOS) {
      actions.push('rate_limit', 'geo_block');
    }
    return actions;
  }

  if (threatLevel === 'high') {
    actions.push('block_ip', 'rate_limit', 'log_event', 'alert_analyst');
    if (attackType === ATTACK_TYPES.WEB_SHELL || attackType === ATTACK_TYPES.COMMAND_INJECTION) {
      actions.push('isolate_system', 'log_forensics');
    }
    return actions;
  }

  if (threatLevel === 'medium') {
    actions.push('rate_limit', 'log_event', 'whitelist_review');
    return actions;
  }

  actions.push('monitor', 'log_event');
  return actions;
}

// ── Request Analysis ──────────────────────────────────────────────────────────
/**
 * Analyze an incoming HTTP request for suspicious patterns.
 * @param {object} req  - HTTP request object
 * @param {object} body - Parsed request body
 * @returns {{ suspicious: boolean, patterns: string[], score: number, threatLevel: string }}
 */
function analyzeRequest(req, body = {}) {
  const analysis = {
    suspicious: false,
    patterns: [],
    score: 0,
    threatLevel: 'low',
    attackType: null,
  };

  const userAgent = (req.headers && req.headers['user-agent']) || '';
  const ip = (req.socket && req.socket.remoteAddress) || req.ip || '';

  // Missing / suspicious User-Agent
  if (!userAgent || userAgent.length < 5) {
    analysis.patterns.push('missing_user_agent');
    analysis.score += 10;
  }

  // Known scanner user agents
  const scanners = ['nmap', 'masscan', 'nikto', 'sqlmap', 'burpsuite', 'metasploit', 'hydra', 'acunetix'];
  if (scanners.some(s => userAgent.toLowerCase().includes(s))) {
    analysis.patterns.push('scanner_user_agent');
    analysis.score += 50;
  }

  // Large payload (possible data exfiltration attempt)
  const contentLength = parseInt((req.headers && req.headers['content-length']) || '0', 10);
  if (contentLength > 1000000) {
    analysis.patterns.push('large_payload');
    analysis.score += 20;
  }

  // Body attack detection
  if (body && Object.keys(body).length > 0) {
    const detected = detectAttackType(JSON.stringify(body));
    if (detected) {
      analysis.patterns.push(detected.key.toLowerCase());
      analysis.score += 60;
      analysis.attackType = detected.type;
    }
  }

  // Rate tracking
  if (ip) {
    const now = Date.now();
    const entry = ipRequestMap.get(ip) || { count: 0, firstSeen: now, ports: new Set() };
    if (now - entry.firstSeen > RATE_WINDOW_MS) {
      // Reset window
      entry.count = 1;
      entry.firstSeen = now;
      entry.ports = new Set();
    } else {
      entry.count++;
    }
    ipRequestMap.set(ip, entry);

    const rps = entry.count / ((now - entry.firstSeen) / 1000 || 1);
    if (rps > 20) {
      analysis.patterns.push(`high_rate:${Math.round(rps)}rps`);
      analysis.score += Math.min(40, rps);
    }
  }

  // Set suspicious flag + threat level
  analysis.suspicious = analysis.score > 20;
  if      (analysis.score >= 80) analysis.threatLevel = 'critical';
  else if (analysis.score >= 55) analysis.threatLevel = 'high';
  else if (analysis.score >= 20) analysis.threatLevel = 'medium';
  else                           analysis.threatLevel = 'low';

  return analysis;
}

// ── Rate Limit Tracking ───────────────────────────────────────────────────────
/**
 * Record a failed login attempt for an IP.
 * Returns the total count in the current window.
 */
function recordFailedAttempt(ip) {
  const now = Date.now();
  const entry = ipFailedLogin.get(ip) || { count: 0, firstSeen: now };
  if (now - entry.firstSeen > RATE_WINDOW_MS) {
    entry.count = 1;
    entry.firstSeen = now;
  } else {
    entry.count++;
  }
  ipFailedLogin.set(ip, entry);
  return entry.count;
}

/**
 * Get current request rate (requests/second) for an IP.
 */
function getRequestRate(ip) {
  const now = Date.now();
  const entry = ipRequestMap.get(ip);
  if (!entry) return 0;
  if (now - entry.firstSeen > RATE_WINDOW_MS) return 0;
  const seconds = Math.max(1, (now - entry.firstSeen) / 1000);
  return entry.count / seconds;
}

/**
 * Check if IP is rate-limited (too many requests).
 * @param {string} ip
 * @param {number} [maxRps=100] - Max allowed requests/second
 */
function isRateLimited(ip, maxRps = 100) {
  return getRequestRate(ip) > maxRps;
}

/**
 * Cleanup old tracking entries (call periodically).
 */
function cleanupTracking() {
  const now = Date.now();
  for (const [ip, entry] of ipRequestMap) {
    if (now - entry.firstSeen > RATE_WINDOW_MS * 5) ipRequestMap.delete(ip);
  }
  for (const [ip, entry] of ipFailedLogin) {
    if (now - entry.firstSeen > RATE_WINDOW_MS * 5) ipFailedLogin.delete(ip);
  }
}

// Run cleanup every 5 minutes
const cleanupTimer = setInterval(cleanupTracking, 5 * 60 * 1000);
cleanupTimer.unref();

// ── Exports ───────────────────────────────────────────────────────────────────
module.exports = {
  ATTACK_TYPES,
  PATTERNS,
  detectAttackType,
  classifyThreat,
  analyzeRequest,
  getRecommendedAction,
  recordFailedAttempt,
  getRequestRate,
  isRateLimited,
  cleanupTracking,
};
