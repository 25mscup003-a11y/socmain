# IPS Webhook Server

A modular Node.js webhook server that receives and executes firewall blocking/unblocking commands from security threat intelligence systems (SOC, IDS, Firewall).

🎉 **Now with React Dashboard!** - Monitor and manage blocks in real-time with a modern web interface.

## 🎯 Overview

This server receives HTTP POST requests with block/unblock commands and executes them locally using:
- **Linux**: iptables
- **Windows**: netsh firewall rules
- **macOS/Other**: Logging only (for testing)

### Key Features

✅ **Modular Architecture** - Clean separation of concerns (routes, controllers, services)
✅ **Multi-Platform Support** - Linux, Windows, macOS
✅ **Authentication** - Optional webhook secret validation
✅ **Comprehensive Logging** - Console + file logging
✅ **IP Validation** - Validates IPv4 and IPv6 addresses
✅ **In-Memory Blocklist** - Tracks all blocked IPs
✅ **RESTful API** - Simple JSON endpoints
✅ **Health Checks** - Built-in monitoring endpoints
✅ **React Dashboard** - Real-time monitoring and management UI
✅ **Advanced Blocking** - IP, port, domain, application, protocol support
✅ **Attack Detection** - SQLi, XSS, Brute Force, DDoS detection
✅ **MongoDB Support** - Persistent storage and analytics

---

## 📋 Project Structure

```
webhook-server/
├── src/
│   ├── controllers/        → Request handlers
│   ├── routes/             → API endpoint definitions
│   ├── services/           → Business logic (firewall actions)
│   ├── middlewares/        → CORS, Auth, Body parsing
│   ├── utils/             → Helpers (logger, response, constants)
│   └── app.js             → Application setup
├── config/                 → Environment configs
├── MongoDB `ips_logs`      → Webhook & server activity logs
├── tests/                  → API tests & examples
├── .env                    → Environment variables
├── package.json            → Dependencies
├── server.js               → Entry point
└── README.md               → Documentation
```

---

## � Dashboard Features

The included React dashboard provides:

### Real-time Monitoring
- **Live Blocklist** - View all active blocks with search and filtering
- **Auto-refresh** - Updates every 5 seconds
- **Server Stats** - CPU, uptime, enforcement method
- **Health Check** - Server status indicator

### Block Management
- **Add Blocks** - UI form to block IP, port, domain, application
- **Remove Blocks** - Quick unblock with confirmation
- **Search & Filter** - Find blocks by IP, domain, reason
- **Sort Options** - By date, IP, type

### Analytics
- **Statistics** - Block counts by type (IP, domain, app, port)
- **Method Breakdown** - View enforcement method usage
- **Protocol Stats** - TCP/UDP/ICMP distribution
- **Recent Activity** - Timeline of block events

### Server Info
- **Platform Details** - OS, architecture, enforcement method
- **API Commands** - Quick curl examples
- **Uptime Tracking** - Server availability
- **Feature Checklist** - Supported capabilities

---

## 🚀 Getting Started (Both Server & Dashboard)

### Backend Setup

```bash
# Install backend dependencies
npm install

# Create environment config on a new setup (preserve an existing .env)
cp -n .env.example .env

# Edit .env: set MONGO_URI and IPS_WEBHOOK_SECRET to match backend/.env.
# Set MAIN_DB_NAME to the database used by the main backend.

# Start the webhook server (port 5050)
npm start
```

The server loads `ipsserver/back-end/.env` regardless of the working directory.
MongoDB stores IPS data in `soc4_ips` and reads company records from
`MAIN_DB_NAME`. Without `MONGO_URI`, it runs in memory-only mode and loses
in-memory blocks on restart.

### Dashboard Setup

```bash
# Navigate to dashboard
cd dashboard

# Install frontend dependencies
npm install

# Copy environment config
cp .env.example .env

# Start the React dashboard (port 3000)
npm start
```

Now open your browser:
- **Dashboard**: http://localhost:3000
- **API**: http://localhost:5050
- **Health**: http://localhost:5050/health

---

---

## 🎯 Advanced Features (v2.0+)

### Block by Multiple Criteria

In addition to IP blocking, the server now supports:

#### 1. **Port-Specific Blocking**
Block traffic on specific ports:

```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "203.0.113.45",
    "port": 22,
    "protocol": "tcp",
    "reason": "SSH brute force"
  }'
```

#### 2. **Domain Blocking**
Block malicious domains:

```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "domain": "malicious.example.com",
    "reason": "Known malware distribution domain"
  }'
```

#### 3. **Application Blocking**
Block specific applications from executing:

```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "application": "/usr/bin/suspicious-app",
    "reason": "Unauthorized application"
  }'
```

#### 4. **Attack Type Detection**
Submit detected attack types for smarter blocking:

```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "action": "block",
    "ip": "10.0.0.50",
    "port": 443,
    "attackType": "SQL Injection",
    "reason": "SQL injection attempt detected"
  }'
```

### Attack Detection System

The server includes built-in attack pattern detection for:

- **SQL Injection** - Detects common SQLi patterns (`UNION SELECT`, `DROP TABLE`, etc.)
- **Cross-Site Scripting (XSS)** - Detects `<script>` tags, event handlers (`onerror`, `onclick`, etc.)
- **Brute Force** - Detects multiple failed login attempts
- **DDoS** - Detects abnormal request rates
- **Command Injection** - Detects shell command patterns
- **Web Shell** - Detects script execution attempts

**Usage**:

```javascript
const attackDetection = require('./src/utils/attackDetection');

const threatAnalysis = attackDetection.classifyThreat({
  failedAttempts: 10,
  requestsPerSecond: 500,
  payload: 'SELECT * FROM users WHERE id=1 OR 1=1',
  ipReputation: 'malicious'
});

console.log(threatAnalysis);
// Output:
// {
//   threatLevel: 'critical',
//   attackType: 'SQL Injection',
//   confidence: { sql_injection: 95, ... },
//   recommendedAction: ['block_ip', 'alert_soc', 'log_forensics']
// }
```

---

## 📊 Database Integration (MongoDB)

### Setup MongoDB Connection

Install MongoDB:

```bash
npm install mongodb
```

Configure in your application:

```javascript
const mongoService = require('./src/services/mongoService');
const { MongoClient } = require('mongodb');

const client = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017');
await mongoService.connect(client, 'ips_webhook');
```

### Database Collections

The MongoDB integration provides three collections:

#### 1. **blocks** - Stores all blocking events
```json
{
  "blockKey": "ip:203.0.113.45|port:22|proto:tcp",
  "type": "ip",
  "ip": "203.0.113.45",
  "port": 22,
  "domain": null,
  "application": null,
  "protocol": "tcp",
  "reason": "SSH brute force",
  "timestamp": "2024-04-03T10:25:00.000Z",
  "method": "iptables",
  "status": "blocked"
}
```

#### 2. **logs** - Stores all server logs
```json
{
  "level": "BLOCK",
  "message": "✅ iptables: Blocked 203.0.113.45 — SSH brute force",
  "timestamp": "2024-04-03T10:25:00.000Z"
}
```

#### 3. **threats** - Stores threat intelligence
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

### Query Examples

```javascript
// Get all blocks for an IP
const blocks = await mongoService.getBlocksByIP('203.0.113.45');

// Get threat statistics (last 24 hours)
const stats = await mongoService.getThreatStats(86400000);

// Cleanup old resolved blocks
await mongoService.cleanup(2592000000); // 30 days
```

---

## 🔐 API Key Authentication

Enable webhook authentication in `.env`:

```bash
IPS_WEBHOOK_SECRET=your-super-secret-key-here
```

All requests must include the secret:

```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: your-super-secret-key-here" \
  -d '{"action": "block", "ip": "192.168.1.100"}'
```

---

## 🧠 Roadmap (Planned Features)

- ✅ IP Blocking
- ✅ Port-Specific Blocking
- ✅ Domain Blocking
- ✅ Application Blocking
- ✅ Attack Type Detection (SQLi, XSS, Brute Force, etc.)
- ✅ MongoDB Integration
- ⏳ React Admin Dashboard (Coming Soon)
- ⏳ Real-time Alerts (Telegram, Email, Slack)
- ⏳ pfSense/OPNsense Direct API Integration
- ⏳ GeoIP-based Blocking
- ⏳ Machine Learning Threat Classification
- ⏳ REST API Rate Limiting Per IP
- ⏳ Whitelist Management

---

## 🔌 API Endpoints

### GET `/health`
Simple health check.

**Response (200)**:
```json
{
  "ok": true,
  "timestamp": "2024-04-03T10:30:00.000Z",
  "uptime": 123.45
}
```

---

### GET `/`
Get server status and current blocklist.

**Response (200)**:
```json
{
  "ok": true,
  "status": "running",
  "platform": "linux",
  "enforcement": "iptables",
  "uptime": 123.45,
  "blockedCount": 2,
  "blocklist": [
    {
      "ip": "203.0.113.45",
      "reason": "Brute force",
      "ts": "2024-04-03T10:25:00.000Z",
      "method": "iptables"
    }
  ]
}
```

---

### POST `/webhook` or POST `/`
Block or unblock a target (IP, port, domain, application, or protocol).

**Request**:
```json
{
  "action": "block",
  "ip": "203.0.113.45",
  "port": 22,
  "domain": "malicious.com",
  "application": "/usr/bin/app",
  "protocol": "tcp",
  "reason": "SSH brute force detected",
  "attackType": "Brute Force"
}
```

**Parameters**:
- `action` (required): `"block"` or `"unblock"`
- `ip` (optional): IPv4 or IPv6 address
- `port` (optional): Port number (1-65535)
- `domain` (optional): Domain/hostname to block
- `application` (optional): Application path to block
- `protocol` (optional): tcp, udp, icmp, all (default: tcp)
- `reason` (optional): Description of the action
- `attackType` (optional): Detected attack type (SQL Injection, XSS, Brute Force, etc.)

*At least one of: `ip`, `domain`, or `application` is required*

**Response (200)**:
```json
{
  "ok": true,
  "action": "block",
  "blockKey": "ip:203.0.113.45|port:22|proto:tcp",
  "description": "IP: 203.0.113.45, Port: 22, Protocol: TCP",
  "method": "iptables",
  "reason": "SSH brute force detected"
}
```

**Error Response (400)**:
```json
{
  "ok": false,
  "error": "Invalid port number: 99999"
}
```

---

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Server port
IPS_WEBHOOK_PORT=5050

# Authentication secret (optional)
# If set, all requests must include: X-Webhook-Secret: <value>
IPS_WEBHOOK_SECRET=super-secret-key

# Runtime logs are stored in MongoDB: soc4_ips.ips_logs

# Node environment
NODE_ENV=production
```

---

## 🔐 Authentication

### Enable Webhook Secret (Optional)

Set `IPS_WEBHOOK_SECRET` in `.env`:

```bash
IPS_WEBHOOK_SECRET=my-secure-secret-key-123
```

### Making Authenticated Requests

Include the `X-Webhook-Secret` header:

```bash
curl -X POST http://localhost:5050/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: my-secure-secret-key-123" \
  -d '{"action": "block", "ip": "192.168.1.100"}'
```

---

## 📊 Process Flow

```
Firewall / IDS / SOC
       ↓
   Sends HTTP POST
       ↓
Routes (/webhook)
       ↓
CORS & Auth Middleware
       ↓
Controller (Validation)
       ↓
Service Layer (Business Logic)
       ↓
   ┌───┴────────┐
   ↓            ↓
Firewall API  Logger
(iptables)   (File/DB)
   ↓            ↓
   └───┬────────┘
       ↓
   Response (Success/Failure)
```

---

## 🛡️ Platform-Specific Behavior

### Linux (iptables)

Adds/removes firewall rules:

```bash
# Block: insert rule at top of INPUT/FORWARD chains
iptables -I INPUT 1 -s 203.0.113.45 -j DROP
iptables -I FORWARD 1 -s 203.0.113.45 -j DROP

# Unblock: delete rule
iptables -D INPUT -s 203.0.113.45 -j DROP
iptables -D FORWARD -s 203.0.113.45 -j DROP
```

**Note**: Requires root or sudo privileges.

### Windows (netsh)

Adds/removes firewall rules:

```powershell
# Block
netsh advfirewall firewall add rule name="SOC4_BLOCK_203_0_113_45" dir=in action=block remoteip=203.0.113.45

# Unblock
netsh advfirewall firewall delete rule name="SOC4_BLOCK_203_0_113_45"
```

**Note**: Requires Administrator privileges.

### macOS / Unsupported Platforms

Logs actions but doesn't modify firewall (log-only mode).

---

## 📝 Logging

Logs are written to:
- **Console**: Real-time output
- **MongoDB**: `soc4_ips.ips_logs`

**Log Format**:
```
[2024-04-03T10:30:45.123Z] [INFO] Server starting on port 5050
[2024-04-03T10:30:46.456Z] [BLOCK] ✅ iptables: Blocked 203.0.113.45 — SSH brute force
[2024-04-03T10:30:50.789Z] [UNBLOCK] ✅ iptables: Unblocked 203.0.113.45
```

---

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch
```

See [tests/API_EXAMPLES.md](tests/API_EXAMPLES.md) for example requests.

---

## 🔗 Integration Examples

### pfSense/OPNsense Firewall

Configure a webhook in your firewall:

**Destination URL**:
```
http://your-webhook-server:5050/webhook
```

**Payload Example**:
```json
{
  "action": "block",
  "ip": "{{ATTACKER_IP}}",
  "reason": "{{ALERT_TYPE}} detected at {{TIMESTAMP}}"
}
```

### Suricata IDS

Add to `suricata-update/modules`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert: yes
      webhook:
        enabled: yes
        url: http://your-webhook-server:5050/webhook
        action: block
```

### Fortinet FortiGate

Create a Security Profile with webhook action:

```
FortiGate → Policy & Objects → Automation Stitch
  Trigger: IDS Alert
  Actions: POST to http://your-webhook-server:5050/webhook
  Body: {"action":"block","ip":"<source_ip>","reason":"<event_type>"}
```

---

## 🚨 Security Considerations

1. **Authentication**: Always use `IPS_WEBHOOK_SECRET` in production
2. **Network**: Keep webhook server in secure network segment
3. **Firewall Rules**: Test carefully before blocking production traffic
4. **Logging**: Monitor logs for failed blocks or suspicious patterns
5. **IP Validation**: Server performs IP format validation
6. **Timeout**: Command execution timeout is 5 seconds (configurable)

---

## 🐛 Troubleshooting

### "Permission denied" on Linux

The server needs iptables access. Run with sudo or setcap:

```bash
# Option 1: Run with sudo
sudo npm start

# Option 2: Grant capabilities (more secure)
sudo setcap cap_net_admin=ep $(which node)
```

### Server won't start on Windows

Ensure you have Administrator privileges for netsh commands.

### Firewall rules not being applied

1. Check the `soc4_ips.ips_logs` MongoDB collection
2. Verify IP format (valid IPv4/IPv6)
3. Confirm firewall rules: `iptables -L` (Linux) or `netsh advfirewall firewall show rule all` (Windows)

### "Invalid JSON" error

Ensure request body is valid JSON and `Content-Type: application/json` header is set.

---

## 📦 Dependencies

- **dotenv**: Environment variable management
- **nodemon** (dev): Auto-reload on file changes
- **jest** (dev): Testing framework
- **eslint** (dev): Code linting

---

## 📄 License

MIT

---

## 🆘 Support

For issues or feature requests, create an issue in the repository.

---

## 🔄 Workflow Overview

1. **Threat Detected** → Security tool (pfSense, Suricata, etc.) detects malicious activity
2. **Webhook Call** → POSTs JSON with `action`, `ip`, `reason` to `/webhook`
3. **Validation** → Server validates action, IP format, authentication
4. **Execution** → Service layer executes appropriate firewall command
5. **Logging** → Action logged to console and file
6. **Response** → Server returns success/failure JSON
7. **Monitoring** → Admin can query `/` to see all blocked IPs

---

## Advanced Setup (Optional)

### Database Integration

Extend `firewallService.js` to save blocks to MongoDB:

```javascript
const blockHistoryDB = db.collection('blocks');

async function blockIP(ip, reason) {
  // ... existing code ...
  
  // Save to DB
  await blockHistoryDB.insertOne({
    ip,
    reason,
    timestamp: new Date(),
    method,
    status: 'blocked'
  });
  
  return result;
}
```

### Alert System

Add Telegram/Email notifications:

```javascript
const sendAlert = async (action, ip, reason) => {
  // Send to Telegram bot
  // Or Email service
};
```

### Dashboard

Consider building a React dashboard to:
- View current blocklist
- Manual block/unblock
- Historical analysis
- Alert configuration

---

**Happy blocking! 🛡️**
