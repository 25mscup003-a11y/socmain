# IPS Webhook Server - v2.0 Upgrades

## Summary of Enhancements

This document outlines all the new features and upgrades added to the IPS Webhook Server.

---

## 🔥 New Blocking Capabilities

### 1. Advanced Blocking by Multiple Criteria

The firewall service now supports blocking targets by:

- **IP Address** - IPv4/IPv6
- **Port Number** - Specific port blocking (1-65535)
- **Domain** - Malicious domains and DNS blocking
- **Application** - Application/executable path blocking
- **Protocol** - TCP, UDP, ICMP selective blocking

#### Example: Block SSH Brute Force

```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "203.0.113.45",
    "port": 22,
    "protocol": "tcp",
    "reason": "SSH brute force attack"
  }'
```

---

## 🧠 Attack Detection System

### New File: `src/utils/attackDetection.js`

Automatically detects and classifies attacks:

**Supported Attack Types:**
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Brute Force
- Distributed Denial of Service (DDoS)
- Port Scan
- Malware/Virus
- Botnet Activity
- Data Exfiltration
- Privilege Escalation
- Credential Theft
- Web Shell Injection

**Threat Classification:**
```javascript
const attackDetection = require('./src/utils/attackDetection');

const threat = attackDetection.classifyThreat({
  failedAttempts: 10,
  requestsPerSecond: 500,
  payload: 'SELECT * FROM users WHERE id=1 OR 1=1',
  ipReputation: 'malicious'
});

// Returns:
// {
//   threatLevel: 'critical',     // low, medium, high, critical
//   attackType: 'SQL Injection',
//   confidence: { sql_injection: 95 },
//   recommendedAction: ['block_ip', 'alert_soc', 'log_forensics']
// }
```

**Key Functions:**
- `detectAttackType(data)` - Identify attack pattern in payload
- `classifyThreat(factors)` - Full threat assessment
- `analyzeRequest(req, body)` - Request security analysis
- `getRecommendedAction(threatLevel, attackType)` - Action recommendations

---

## 📊 MongoDB Integration

### New File: `src/services/mongoService.js`

Complete database integration for persistence and analytics.

**Collections Created:**

#### 1. **blocks** - Block History
```json
{
  "blockKey": "ip:203.0.113.45|port:22|proto:tcp",
  "type": "ip",
  "ip": "203.0.113.45",
  "port": 22,
  "protocol": "tcp",
  "reason": "SSH brute force",
  "timestamp": "2024-04-03T10:25:00.000Z",
  "method": "iptables",
  "status": "blocked"
}
```

#### 2. **logs** - Server Logs
```json
{
  "level": "BLOCK",
  "message": "✅ iptables: Blocked 203.0.113.45 — SSH brute force",
  "timestamp": "2024-04-03T10:25:00.000Z"
}
```

#### 3. **threats** - Threat Intelligence
```json
{
  "ip": "203.0.113.45",
  "attackType": "SQL Injection",
  "threatLevel": "high",
  "confidence": 95,
  "payload": "SELECT * FROM users",
  "timestamp": "2024-04-03T10:25:00.000Z"
}
```

**API Methods:**
- `connect(mongoClient, dbName)` - Initialize database
- `storeBlock(blockData)` - Save blocking event
- `storeLog(logData)` - Save log event
- `storeThreat(threatData)` - Save threat intelligence
- `getAllBlocks(filter)` - Query blocks
- `getBlocksByIP(ip)` - Get IP history
- `getBlocksByDomain(domain)` - Get domain history
- `getThreatStats(timeWindowMs)` - Threat statistics
- `cleanup(ageMs)` - Remove old records

---

## 🔄 Firewall Service Enhancements

### Enhanced File: `src/services/firewallService.js`

**New Functions:**

1. **blockTarget(options)** - Advanced blocking
   ```javascript
   await firewallService.blockTarget({
     ip: '203.0.113.45',
     port: 22,
     protocol: 'tcp',
     reason: 'SSH brute force'
   });
   ```

2. **unblockTarget(options)** - Advanced unblocking
   ```javascript
   await firewallService.unblockTarget({
     ip: '203.0.113.45',
     port: 22
   });
   ```

3. **Helper Functions:**
   - `generateBlockKey(criteria)` - Create unique block identifier
   - `formatBlockDescription(criteria)` - Human-readable description
   - `applyLinuxBlock(criteria)` - Linux iptables rules
   - `removeLinuxBlock(entry)` - Remove iptables rules
   - `applyWindowsBlock(criteria)` - Windows netsh rules
   - `clearBlockEntry(blockKey)` - Remove single entry
   - `clearAllBlocks()` - Flush blocklist

**Backward Compatibility:**
- `blockIP(ip, reason)` - Legacy function still works
- `unblockIP(ip)` - Legacy function still works

---

## 🎮 Controller & Request Handling

### Enhanced File: `src/controllers/webhookController.js`

**handleWebhook() Improvements:**
- Now accepts `port`, `domain`, `application`, `protocol` parameters
- Auto-detects attack types from `attackType` parameter
- Validates all blocking criteria combinations
- Improved error messages

**Request Example:**
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "192.0.2.100",
    "port": 3306,
    "protocol": "tcp",
    "attackType": "SQL Injection",
    "reason": "SQL injection attempt on database"
  }'
```

---

## 📚 Documentation Updates

### Updated Files:
1. **README.md** - Complete rewrite with:
   - Advanced features section
   - MongoDB setup guide
   - Attack detection examples
   - Full API parameter documentation
   - Roadmap for future features

2. **API_EXAMPLES.md** - Comprehensive examples:
   - Block IP combinations
   - Domain blocking examples
   - Application blocking
   - Attack type detection
   - Error response examples
   - Integration templates (pfSense, Suricata, FortiGate)

3. **package.json** - Added MongoDB dependency:
   ```json
   "mongodb": "^5.5.0"
   ```

---

## 🛡️ Platform-Specific Improvements

### Linux (iptables)
- Now supports port-specific blocking
- Protocol-specific rules (tcp/udp/icmp)
- Better rule validation and error handling

### Windows (netsh)
- Enhanced rule naming with port information
- Support for local/remote port filtering
- Protocol-specific firewall rules

---

## 🚀 Roadmap

### Completed ✅
- ✅ Multi-criteria blocking (IP, port, protocol)
- ✅ Domain and application blocking
- ✅ Attack type detection
- ✅ MongoDB integration
- ✅ Advanced threat classification

### Coming Soon ⏳
- React Admin Dashboard
- Real-time Alerts (Telegram, Email, Slack)
- pfSense/OPNsense Direct API
- GeoIP-based Blocking
- Machine Learning Classification
- REST API Rate Limiting
- Whitelist Management

---

## 📥 Installation & Setup

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure Environment
```bash
cp .env .env.local
# Edit .env.local with your settings
```

### 3. Setup MongoDB (Optional)
```bash
# Or use MongoDB Atlas cloud
docker run -d -p 27017:27017 mongo:latest
```

### 4. Start Server
```bash
npm start
```

---

## 🧪 Testing

### Test Block by IP + Port
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "192.168.1.100",
    "port": 22,
    "protocol": "tcp",
    "reason": "SSH attack"
  }'
```

### Test Attack Detection
```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "10.0.0.1",
    "attackType": "SQL Injection",
    "reason": "SQL injection payload detected"
  }'
```

### Query Blocklist
```bash
curl http://localhost:5050/
```

---

## 🔐 Security Notes

1. **Always enable** `IPS_WEBHOOK_SECRET` in production
2. **Use HTTPS** when exposing to the internet
3. **Validate all inputs** - Server validates IP/port/protocol formats
4. **Monitor logs** - Check for blocked attacks and false positives
5. **Regular cleanup** - Remove old blocks from database

---

## 📞 Support

For issues or feature requests, consult:
- [API Examples](tests/API_EXAMPLES.md)
- [README Documentation](README.md)
- Attack Detection Patterns in `src/utils/attackDetection.js`

---

**Version:** 2.0  
**Last Updated:** April 3, 2024  
**Status:** Production Ready
