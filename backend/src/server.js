require('dotenv').config({ path: require('path').resolve(__dirname, '..', '.env') });
require('./observability/runtimeLogging').installConsolePolicy();
require('./observability/telemetry').startTelemetry();
const express = require('express'); // application HTTP server
const http = require('http');
const https = require('https');
const fs = require('fs');
const { fork } = require('child_process');
const path = require('path');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const cors = require('cors');
const connectDB = require('./config/db');
const Company = require('./models/Company.model');
const Department = require('./models/Department.model');
const System = require('./models/System.model');
const {
  canJoinCompany,
  canJoinDepartment,
  canJoinPartner,
  canJoinSystem,
  canJoinGlobalFraud,
} = require('./security/socketAuthorization');
const { SOC_ROLES, allowedCompanyIds } = require('./services/socAccess.service');

const authRoutes = require('./routes/auth.routes');
const companyRoutes = require('./routes/company.routes');
const departmentRoutes = require('./routes/department.routes');
const systemRoutes = require('./routes/system.routes');
const alertRoutes = require('./routes/alert.routes');
const agentRoutes = require('./routes/agent.routes');
const paymentRoutes = require('./routes/payment.routes');
const superadminRoutes = require('./routes/superadmin.routes');
const soarRoutes = require('./routes/soar.routes');
const reportRoutes = require('./routes/report.routes');
const userRoutes = require('./routes/user.routes');
const dashboardRoutes = require('./routes/dashboard.routes');
const logMonitorRoutes = require('./routes/logmonitor.routes');
const complianceRoutes = require('./routes/compliance.routes');
const idsRoutes = require('./routes/ids.routes');
const correlationRoutes = require('./routes/correlation.routes');
const aiRoutes = require('./routes/ai.routes');
const logsRoutes = require('./routes/logs.routes');
const edrRoutes = require('./routes/edr.routes');
const forensicsRoutes = require('./routes/forensics.routes');
const scoreRoutes = require('./routes/security-score.routes');
const ipsRoutes = require('./routes/ips.routes');
const firewallRoutes = require('./routes/firewall.routes');
const monitoringRoutes = require('./routes/monitoring.routes');
const ipsProxyRoutes = require('./routes/ips-proxy.routes');
const idsipsRoutes = require('./routes/idsips.routes');
const socEdrRoutes = require('./routes/soc-agent-edr.routes');
const edrCapRoutes = require('./routes/edr-capabilities.routes');
const emailThreatRoutes = require('./routes/email-threat.routes');
const lateralMovementRoutes = require('./routes/lateral-movement.routes');
const credentialSecurityRoutes = require('./routes/credential-security.routes');
const dataSecurityRoutes = require('./routes/data-security.routes');
const uebaRoutes = require('./routes/ueba.routes');
const persistenceRoutes = require('./routes/persistence.routes');
const systemChangesRoutes = require('./routes/system-changes.routes');
const registryMonitoringRoutes = require('./routes/registry-monitoring.routes');
const advancedRoutes = require('./routes/advanced-threats.routes');
const planRoutes = require('./routes/plan.routes');
const ipsEngineRoutes = require('./routes/ips-engine.routes');
const pricingRoutes = require('./routes/pricing.routes');
const twofaRoutes = require('./routes/twofa.routes');
const addSystemRoutes = require('./routes/add-system.routes');
const tenantRoutes = require('./routes/tenant.routes');
const partnerRoutes = require('./routes/partner.routes');
const wafRoutes = require('./routes/waf.routes');
const fraudRoutes = require('./routes/fraud.routes');
const autoResponseRoutes = require('./routes/auto-response.routes');
const lolbinsRoutes = require('./routes/lolbins.routes');
const ransomwareRoutes = require('./routes/ransomware.routes');
const socRoutes = require('./routes/soc.routes');
const socDashboardRoutes = require('./routes/soc-dashboard.routes');
const hashSignatureRoutes = require('./routes/hash-signature.routes');
const encryptionRoutes = require('./routes/encryption.routes');
const networkRoutes = require('./routes/network.routes');
const serviceMonitoringRoutes = require('./routes/service-monitoring.routes');
const timeAnomalyRoutes = require('./routes/time-anomaly.routes');
const scriptMonitoringRoutes = require('./routes/script-monitoring.routes');
const apiMonitoringRoutes = require('./routes/api-monitoring.routes');
const kernelMonitoringRoutes = require('./routes/kernel-monitoring.routes');
const {
  scalableReadCache,
  closeScalableReadCache,
} = require('./middleware/scalableReadCache');

const app = express();
function createApplicationServer(application) {
  if (process.env.TLS_ENABLED !== 'true') return http.createServer(application);
  const keyFile = process.env.TLS_PRIVATE_KEY_FILE;
  const certFile = process.env.TLS_CERTIFICATE_FILE;
  if (!keyFile || !certFile) throw new Error('TLS_PRIVATE_KEY_FILE and TLS_CERTIFICATE_FILE are required when TLS_ENABLED=true');
  const options = {
    key: fs.readFileSync(keyFile),
    cert: fs.readFileSync(certFile),
    minVersion: 'TLSv1.3',
    requestCert: process.env.AGENT_MTLS_ENABLED === 'true' || process.env.AGENT_MTLS_REQUIRED === 'true',
    // Browser/API clients may not carry a client certificate. Agent endpoints
    // enforce req.socket.authorized separately when mTLS is mandatory.
    rejectUnauthorized: false,
  };
  if (process.env.TLS_CA_FILE) options.ca = fs.readFileSync(process.env.TLS_CA_FILE);
  return https.createServer(options, application);
}

const server = createApplicationServer(app);
let shuttingDown = false;

server.requestTimeout = Number(process.env.HTTP_REQUEST_TIMEOUT_MS || 30_000);
server.headersTimeout = Number(process.env.HTTP_HEADERS_TIMEOUT_MS || 15_000);
server.keepAliveTimeout = Number(process.env.HTTP_KEEP_ALIVE_TIMEOUT_MS || 65_000);

function validateCriticalConfig() {
  const production = process.env.NODE_ENV === 'production';
  const problems = [];
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    problems.push('JWT_SECRET must contain at least 32 characters');
  }
  if (!process.env.AGENT_STORAGE_MASTER_KEY || Buffer.byteLength(process.env.AGENT_STORAGE_MASTER_KEY, 'utf8') < 32) {
    problems.push('AGENT_STORAGE_MASTER_KEY must contain at least 32 characters');
  }
  for (const name of ['SERVER_PROTO', 'SERVER_IP', 'SERVER_PORT', 'APP_PROTO', 'ROOT_DOMAIN', 'MAIN_TENANT_SUBDOMAIN']) {
    if (!String(process.env[name] || '').trim()) problems.push(`${name} is required`);
  }
  if (!/^https?$/.test(String(process.env.SERVER_PROTO || ''))) {
    problems.push('SERVER_PROTO must be http or https');
  }
  if (!/^https?$/.test(String(process.env.APP_PROTO || ''))) {
    problems.push('APP_PROTO must be http or https');
  }
  if (!Number.isInteger(Number(process.env.SERVER_PORT)) || Number(process.env.SERVER_PORT) < 1 || Number(process.env.SERVER_PORT) > 65535) {
    problems.push('SERVER_PORT must be an integer from 1 to 65535');
  }
  if (production && (!process.env.INTEGRATION_KEY_SECRET || process.env.INTEGRATION_KEY_SECRET.length < 32)) {
    problems.push('INTEGRATION_KEY_SECRET must contain at least 32 characters in production');
  }
  if (production && process.env.ALLOW_LEGACY_GLOBAL_INTEGRATION_SECRET === 'true'
    && (!process.env.INTEGRATION_SECRET || process.env.INTEGRATION_SECRET.length < 32)) {
    problems.push('INTEGRATION_SECRET must contain at least 32 characters when legacy integration auth is enabled');
  }
  if (production && (!process.env.METRICS_BEARER_TOKEN || process.env.METRICS_BEARER_TOKEN.length < 32)) {
    problems.push('METRICS_BEARER_TOKEN must contain at least 32 characters in production');
  }
  if (production && !process.env.WEB_TRANSPORT_PRIVATE_KEY_FILE && !process.env.WEB_TRANSPORT_PRIVATE_KEY_PEM) {
    problems.push('WEB_TRANSPORT_PRIVATE_KEY_FILE or WEB_TRANSPORT_PRIVATE_KEY_PEM is required in production');
  }
  if (production && process.env.TLS_ENABLED !== 'true' && process.env.TRUSTED_TLS_PROXY !== 'true') {
    problems.push('TLS 1.3 must be enabled directly or terminated by a trusted proxy in production');
  }
  if (production && !['true'].includes(process.env.AGENT_MTLS_REQUIRED) && process.env.AGENT_MTLS_AT_PROXY !== 'true') {
    problems.push('Agent mTLS must be enforced directly or by a trusted proxy in production');
  }
  if (production && (process.env.KMS_PROVIDER || 'local-file') === 'local-file' && !process.env.KMS_MASTER_KEY_FILE) {
    problems.push('KMS_MASTER_KEY_FILE is required for the local KMS provider in production');
  }
  if (production && !process.env.ENCRYPTION_AUDIT_KEY_FILE) {
    problems.push('ENCRYPTION_AUDIT_KEY_FILE is required in production');
  }

  if (process.env.INGESTION_MODE === 'broker' && !process.env.KAFKA_BROKERS) {
    problems.push('KAFKA_BROKERS is required in broker ingestion mode');
  }
  if (production && process.env.INGESTION_MODE === 'broker') {
    if (process.env.KAFKA_SSL !== 'true') {
      problems.push('KAFKA_SSL=true is required for broker ingestion in production');
    }
    if (process.env.KAFKA_SSL_REJECT_UNAUTHORIZED === 'false') {
      problems.push('KAFKA_SSL_REJECT_UNAUTHORIZED cannot be false in production');
    }
    const kafkaSaslConfigured = Boolean(process.env.KAFKA_SASL_USERNAME && process.env.KAFKA_SASL_PASSWORD);
    const kafkaMtlsConfigured = Boolean(process.env.KAFKA_SSL_CERT_FILE && process.env.KAFKA_SSL_KEY_FILE);
    if (!kafkaSaslConfigured && !kafkaMtlsConfigured) {
      problems.push('Kafka SASL credentials or Kafka mTLS certificate/key are required in production');
    }
  }
  if (process.env.ARCHIVE_ENABLED === 'true' && !process.env.ARCHIVE_S3_BUCKET) {
    problems.push('ARCHIVE_S3_BUCKET is required when archival is enabled');
  }
  if (process.env.OTEL_ENABLED === 'true' && !process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) {
    problems.push('OTEL_EXPORTER_OTLP_TRACES_ENDPOINT is required when tracing is enabled');
  }
  if (process.env.SOCKET_ADAPTER === 'redis' && !(process.env.SOCKET_REDIS_URL || process.env.REDIS_URL)) {
    problems.push('SOCKET_REDIS_URL or REDIS_URL is required for the Redis socket adapter');
  }

  if (['clickhouse', 'dual'].includes(process.env.HOT_EVENT_STORE) && process.env.INGESTION_MODE !== 'broker') {
    problems.push('ClickHouse hot storage requires INGESTION_MODE=broker');
  }
  if (problems.length) {
    throw new Error(`Unsafe backend configuration: ${problems.join('; ')}. Check backend/.env; for a new local setup, run npm run setup:env in backend.`);
  }
}

validateCriticalConfig();

// ── Allowed origins ────────────────────────────────────
// Auto-build origins from SERVER_IP so changing SERVER_IP in .env
// automatically updates all CORS — no need to edit SUPERADMIN_ORIGIN / COMPANY_ORIGIN separately.
const SERVER_PROTO = process.env.SERVER_PROTO;
const SERVER_IP = process.env.SERVER_IP;

const companyOrigins = process.env.COMPANY_ORIGIN ? process.env.COMPANY_ORIGIN.split(',') : [];
const superadminOrigins = process.env.SUPERADMIN_ORIGIN ? process.env.SUPERADMIN_ORIGIN.split(',') : [];

const ALLOWED_ORIGINS = [
  // Always allow localhost for local dev
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:3002',
  'https://localhost:8443',
  'https://127.0.0.1:8443',
  // Auto-derived from SERVER_IP (works when you change SERVER_IP in .env)
  `${SERVER_PROTO}://${SERVER_IP}:3000`,
  `${SERVER_PROTO}://${SERVER_IP}:3001`,
  `${SERVER_PROTO}://${SERVER_IP}:3002`,
  // Still respect explicit overrides if set in .env
  ...companyOrigins,
  ...superadminOrigins,
].filter(Boolean).filter((v, i, arr) => arr.indexOf(v) === i); // deduplicate

const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (curl, Postman, SOC Agent)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'x-integration-secret',
    'x-razorpay-signature',
    'x-webhook-secret',
    'X-Webhook-Secret',
    'x-company-id',
    'X-Company-ID',
    'X-Company',
    'x-tenant-id',
    'X-Tenant-ID',
    'X-AJNAT-Web-Encryption',
    'X-AJNAT-Wrapped-Key',
    'X-AJNAT-Encrypted-Meta',
    'X-AJNAT-Payload-Encryption',
    'X-Agent-System-ID',
  ],
  exposedHeaders: [
    'Content-Disposition',
    'Digest',
    'Content-Digest',
    'X-AJNAT-Artifact-SHA256',
    'X-AJNAT-Web-Encryption',
    'X-AJNAT-Original-Content-Type',
    'X-AJNAT-Transport-Key-Id',
  ],
};

// ── Socket.IO ──────────────────────────────────────────
const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

app.set('io', io);

io.use(async (socket, next) => {
  try {
    const auth = socket.handshake.auth || {};
    const authorization = String(socket.handshake.headers?.authorization || '');
    const token = auth.token || (authorization.startsWith('Bearer ') ? authorization.slice(7) : '');
    if (token) {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      socket.principal = { kind: 'user', ...payload };
      return next();
    }

    const agentKey = String(auth.agentKey || '');
    if (agentKey) {
      const system = await System.findOne({ agentKey, isActive: true })
        .select('_id tenantId partnerId companyId departmentId')
        .lean();
      if (!system) return next(new Error('Unauthorized socket agent'));
      socket.principal = {
        kind: 'agent',
        systemId: system._id,
        tenantId: system.tenantId,
        partnerId: system.partnerId,
        companyId: system.companyId,
        departmentId: system.departmentId,
      };
      return next();
    }

    return next(new Error('Socket authentication required'));
  } catch {
    return next(new Error('Invalid or expired socket credentials'));
  }
});

io.on('connection', (socket) => {
  const rejectRoom = (room, ack) => {
    socket.emit('room:error', { room, message: 'Room access denied' });
    if (typeof ack === 'function') ack({ ok: false, message: 'Room access denied' });
  };
  const acceptRoom = (room, ack) => {
    socket.join(room);
    if (typeof ack === 'function') ack({ ok: true });
  };

  if (socket.principal?.kind === 'agent' && socket.principal.systemId) {
    socket.join(`system:${socket.principal.systemId}`);
  }

  if (socket.principal?.kind === 'user' && socket.principal.id) {
    socket.join(`user:${socket.principal.id}`);
  }

  // SOC users may be assigned to several companies. Join every authorized
  // company room so dashboards receive updates even when the JWT only carries
  // one legacy companyId.
  if (socket.principal?.kind === 'user' && SOC_ROLES.includes(socket.principal.role)) {
    allowedCompanyIds(socket.principal)
      .then(companyIds => companyIds.forEach(id => socket.join(`company:${id}`)))
      .catch(error => console.warn('[socket] SOC scope rooms unavailable:', error.message));
  }

  socket.on('join:company', async (id, ack) => {
    const company = await Company.findById(id).select('_id tenantId partnerId').lean().catch(() => null);
    if (!canJoinCompany(socket.principal, company)) return rejectRoom(`company:${id}`, ack);
    acceptRoom(`company:${id}`, ack);
  });
  socket.on('join:department', async (id, ack) => {
    const department = await Department.findById(id).select('_id companyId').lean().catch(() => null);
    if (!canJoinDepartment(socket.principal, department)) return rejectRoom(`dept:${id}`, ack);
    acceptRoom(`dept:${id}`, ack);
  });
  socket.on('join:superadmin', (ack) => {
    if (!canJoinGlobalFraud(socket.principal)) return rejectRoom('superadmin', ack);
    acceptRoom('superadmin', ack);
  });
  socket.on('join:fraud', (data, ack) => {
    const { partnerId } = data || {};
    if (partnerId) {
      if (!canJoinPartner(socket.principal, partnerId)) {
        return rejectRoom(`partner:${partnerId}:fraud`, ack);
      }
      return acceptRoom(`partner:${partnerId}:fraud`, ack);
    }
    if (!canJoinGlobalFraud(socket.principal)) return rejectRoom('fraud:stream', ack);
    return acceptRoom('fraud:stream', ack);
  });
  socket.on('join:partner', (id, ack) => {
    if (!canJoinPartner(socket.principal, id)) return rejectRoom(`partner:${id}`, ack);
    acceptRoom(`partner:${id}`, ack);
  });
  // Agent/system command rooms are restricted to the authenticated endpoint.
  socket.on('join', async (room, ack) => {
    if (!room || !room.startsWith('system_')) return rejectRoom(String(room || ''), ack);
    const systemId = room.slice('system_'.length);
    const system = await System.findById(systemId)
      .select('_id tenantId partnerId companyId departmentId')
      .lean()
      .catch(() => null);
    if (!canJoinSystem(socket.principal, system)) return rejectRoom(room, ack);
    acceptRoom(room, ack);
  });
});

// ── Razorpay webhook needs raw body BEFORE cors/json ──
app.use('/api/payment/webhook', express.raw({ type: 'application/json' }));

// ── Global middleware ──────────────────────────────────
app.use(cors(corsOptions));
// Note: cors() middleware already handles OPTIONS preflight — no separate handler needed
const { captureSignedJsonBody } = require('./utils/agentRequestAuth');
const { agentPayloadEncryption } = require('./utils/agentPayloadEncryption');
const { webPayloadEncryption, publicKeyResponse } = require('./utils/webPayloadEncryption');
app.use('/api/logs', express.json({
  limit: process.env.INGEST_BODY_LIMIT || '5mb', strict: true, verify: captureSignedJsonBody,
}));
app.use('/api/alerts', express.json({
  limit: process.env.INGEST_BODY_LIMIT || '5mb', strict: true, verify: captureSignedJsonBody,
}));
app.use(express.json({
  limit: process.env.API_BODY_LIMIT || '1mb', strict: true, verify: captureSignedJsonBody,
}));
app.use(express.urlencoded({ extended: true, limit: process.env.API_BODY_LIMIT || '1mb' }));
// Browser API payload encryption bootstraps with a public key; only public key
// material is returned by this unencrypted endpoint.
app.get('/api/transport/public-key', publicKeyResponse);
app.use('/api', webPayloadEncryption);
// New agents encrypt every JSON API payload with per-endpoint AES-256-GCM.
// Browser/API traffic without the transport marker remains unchanged.
app.use('/api', agentPayloadEncryption);
app.use(require('./observability/httpObservability').httpObservability);

// ── Serve uploaded files (agreement PDFs, etc.) ────────
const uploadsDir = path.join(__dirname, '../uploads');
app.use('/uploads', (req, res, next) => {
  if (!['GET', 'HEAD'].includes(req.method)) return next();

  let relativePath = '';
  try {
    relativePath = decodeURIComponent(req.path).replace(/^\/+/, '');
  } catch {
    return next();
  }

  const requestedPath = path.resolve(uploadsDir, relativePath);
  if (!requestedPath.startsWith(path.resolve(uploadsDir) + path.sep)) return next();
  if (fs.existsSync(requestedPath)) return next();

  const match = relativePath.match(/^partner-docs\/(doc-[a-f0-9]{24}-[A-Za-z0-9_-]+-)\d+(\.[A-Za-z0-9]+)$/);
  if (!match) return next();

  const partnerDocsDir = path.join(uploadsDir, 'partner-docs');
  fs.readdir(partnerDocsDir, (err, files) => {
    if (err) return next();
    const [, prefix, ext] = match;
    const candidates = files
      .filter(file => file.startsWith(prefix) && file.endsWith(ext))
      .sort((a, b) => {
        const aTime = Number((a.match(/-(\d+)\.[^.]+$/) || [])[1] || 0);
        const bTime = Number((b.match(/-(\d+)\.[^.]+$/) || [])[1] || 0);
        return bTime - aTime;
      });
    if (!candidates.length) return next();
    res.sendFile(path.join(partnerDocsDir, candidates[0]));
  });
});
app.use('/uploads', express.static(uploadsDir));

app.use((req, res, next) => {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return next();

  try {
    const jwt = require('jsonwebtoken');
    const payload = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
    if (!payload.impersonatedBy) return next();

    const path = req.path || '';
    const isDangerousPayment = req.method !== 'GET' && (path.startsWith('/api/payment') || path.startsWith('/api/add-system'));
    const isPasswordChange = req.method !== 'GET' && (
      path === '/api/users/change-password' ||
      path === '/api/users/reset-password' ||
      path.startsWith('/api/2fa')
    );
    const isDelete = req.method === 'DELETE';

    if (isDangerousPayment || isPasswordChange || isDelete) {
      const LoginActivity = require('./models/LoginActivity.model');
      LoginActivity.create({
        userId: payload.id,
        companyId: payload.companyId || null,
        email: payload.email || 'impersonated-partner',
        action: 'superadmin_impersonation_blocked',
        success: false,
        failReason: `${req.method} ${req.originalUrl}`,
        ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
        userAgent: req.get('user-agent') || '',
      }).catch(err => console.error('[impersonation-block-audit]', err.message));
      return res.status(403).json({ message: 'This action is disabled during Super Admin partner login.' });
    }
  } catch {
    return next();
  }

  next();
});

// ── Routes ─────────────────────────────────────────────
app.use(require('./middleware/protocolLogger'));
app.use(scalableReadCache);

app.get('/metrics', require('./observability/httpObservability').metricsHandler);


app.use('/api/auth', authRoutes);
app.use('/api/company', companyRoutes);
app.use('/api/department', departmentRoutes);
app.use('/api/system', systemRoutes);
// Backward-compatible plural alias used by existing Company dashboard pages.
app.use('/api/systems', systemRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/agent', agentRoutes);
app.use('/api/email-threat', emailThreatRoutes);
app.use('/api/lateral-movement', lateralMovementRoutes);
app.use('/api/credential-security', credentialSecurityRoutes);
app.use('/api/data-security', dataSecurityRoutes);
app.use('/api/ueba', uebaRoutes);
app.use('/api/persistence', persistenceRoutes);
app.use('/api/system-changes', systemChangesRoutes);
app.use('/api/registry-monitoring', registryMonitoringRoutes);
app.use('/api/payment', paymentRoutes);
app.use('/api/superadmin', superadminRoutes);
app.use('/api/soar', soarRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/users', userRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/log-monitor', logMonitorRoutes);
app.use('/api/vt', require('./routes/vt.routes'));
app.use('/api/ip', require('./routes/ip.routes'));
app.use('/api/daily-report', require('./routes/dailyReport.routes'));
app.use('/api/compliance', complianceRoutes);
app.use('/api/ids', idsRoutes);
app.use('/api/correlation', correlationRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api/logs', logsRoutes);
app.use('/api/edr', edrRoutes);
app.use('/api/forensics', forensicsRoutes);
app.use('/api/security-score', scoreRoutes);
app.use('/api/ips', ipsRoutes);
app.use('/api/ips-proxy', ipsProxyRoutes);
app.use('/api/firewall', firewallRoutes);
app.use('/api/monitoring', monitoringRoutes);
app.use('/api/threats', require('./routes/threats.routes'));
// Unified IDS/IPS dynamic endpoints (replaces hardcoded data)
app.use('/api', idsipsRoutes);   // serves /api/idsips/status, /api/ipserver/status, /api/idsips/logs, /api/idsips/threats, /api/idsips/summary
app.use('/api/soc-edr', socEdrRoutes);
app.use('/api/edr-cap', edrCapRoutes);
app.use('/api/plans', planRoutes);
app.use('/api/ips-engine', ipsEngineRoutes);
app.use('/api/pricing', pricingRoutes);
app.use('/api/2fa', twofaRoutes);
app.use('/api/add-system', addSystemRoutes);
app.use('/api/advanced', advancedRoutes);
app.use('/api/tenant', tenantRoutes);
app.use('/api/partner', partnerRoutes);
app.use('/api/waf', wafRoutes);
app.use('/api/fraud', fraudRoutes);
app.use('/api/auto-response', autoResponseRoutes);
app.use('/api/lolbins', lolbinsRoutes);
app.use('/api/ransomware', ransomwareRoutes);
app.use('/api/soc', socRoutes);
app.use('/api/soc-dashboard', socDashboardRoutes);
app.use('/api/hash-signature', hashSignatureRoutes);
app.use('/api/encryption', encryptionRoutes);
app.use('/api/network', networkRoutes);
app.use('/api/service-monitoring', serviceMonitoringRoutes);
app.use('/api/time-anomaly', timeAnomalyRoutes);
app.use('/api/script-monitoring', scriptMonitoringRoutes);
app.use('/api/api-monitoring', apiMonitoringRoutes);
app.use('/api/kernel-monitoring', kernelMonitoringRoutes);
app.use('/api/dns-sinkhole', require('./routes/dns-sinkhole.routes'));
app.use('/api/dns-cache-poisoning', require('./routes/dns-cache-poisoning.routes'));
app.use('/api/memory-overflow', require('./routes/memory-overflow.routes'));
app.use('/api/memory-activity', require('./routes/memory-activity.routes'));
app.use('/api/authentication-monitoring', require('./routes/authentication-monitoring.routes'));
app.use('/api/usb-policies', require('./routes/usb-policy.routes'));
app.use('/api/geolocation', require('./routes/geolocation.routes'));
app.use('/api/soc-manager', require('./routes/soc-manager.routes'));
app.use('/api/l1', require('./routes/l1.routes'));
app.use('/api/l2', require('./routes/l2.routes'));
app.use('/api/l3', require('./routes/l3.routes'));
app.use('/api/super-admin', require('./routes/superadmin-monitoring.routes'));
app.use('/api/soc-chat', require('./routes/soc-chat.routes'));

app.get('/health/live', (_req, res) => res.json({ status: 'ok', ts: new Date() }));
app.get('/health/ready', (_req, res) => {
  const ready = !shuttingDown && mongoose.connection.readyState === 1;
  res.status(ready ? 200 : 503).json({
    status: ready ? 'ready' : 'not_ready',
    database: mongoose.connection.readyState,
    shuttingDown,
    ts: new Date(),
  });
});
app.get('/health', (_req, res) => {
  const ready = !shuttingDown && mongoose.connection.readyState === 1;
  res.status(ready ? 200 : 503).json({ status: ready ? 'ok' : 'not_ready', ts: new Date() });
});
// This release value also drives enrolled desktop-agent update discovery.
app.get('/', (_req, res) => res.json({ name: 'SOC4 Backend API', status: 'running', version: process.env.AGENT_VERSION || '0.1.13', docs: '/api', ts: new Date() }));

// ── 404 ────────────────────────────────────────────────
app.use((req, res) => {
  console.log(`[404] ${req.method} ${req.originalUrl}`);
  res.status(404).json({ message: `Route not found: ${req.method} ${req.originalUrl}` });
});

// ── Error handler ──────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('[500]', err.message);
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ message: 'Request payload too large' });
  }
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : (err.message || 'Internal server error');
  res.status(err.statusCode || 500).json({ message });
});

// ── Initialize superadmin ─────────────────────────────
async function initializeSuperAdmin() {
  const User = require('./models/User.model');
  const Company = require('./models/Company.model');
  const System = require('./models/System.model');
  const Alert = require('./models/Alert.model');
  const Log = require('./models/Log.model');
  const { getOrCreateMainTenant } = require('./utils/tenant');
  try {
    const mainTenant = await getOrCreateMainTenant();
    const existing = await User.findOne({ role: 'superadmin' });
    if (!existing) {
      const bootstrapEmail = String(process.env.SUPERADMIN_EMAIL || '').trim().toLowerCase();
      const bootstrapPassword = String(process.env.SUPERADMIN_INITIAL_PASSWORD || '');
      if (!bootstrapEmail || bootstrapPassword.length < 16) {
        console.error(
          '❌ Superadmin bootstrap skipped. Set SUPERADMIN_EMAIL and a '
          + 'SUPERADMIN_INITIAL_PASSWORD of at least 16 characters, then restart.'
        );
      } else {
        await User.create({
          name: 'Super Admin',
          email: bootstrapEmail,
          password: bootstrapPassword,
          role: 'superadmin',
          tenantId: mainTenant._id,
          isActive: true,
          isEmailVerified: true,
          forcePasswordReset: true,
        });
        console.log('✅ Bootstrap superadmin created; password reset is required on first login');
      }
    } else {
      // Already exists — patch to ensure login works (handles legacy records)
      const needsPatch = !existing.isActive || !existing.isEmailVerified;
      if (needsPatch || !existing.tenantId) {
        await User.findByIdAndUpdate(existing._id, {
          isActive: true,
          isEmailVerified: true,
          tenantId: existing.tenantId || mainTenant._id,
        });
        console.log('✅ Superadmin record patched (isActive + isEmailVerified set)');
      }
    }

    if (process.env.RUN_LEGACY_STARTUP_MIGRATIONS !== 'true') {
      return;
    }
    console.warn('[Migration] Running explicitly enabled legacy startup migrations');

    await Company.updateMany(
      { $or: [{ tenantId: null }, { tenantId: { $exists: false } }] },
      { $set: { tenantId: mainTenant._id, source: 'public' } }
    );
    await User.updateMany(
      {
        role: { $ne: 'superadmin' },
        $or: [{ tenantId: null }, { tenantId: { $exists: false } }],
      },
      { $set: { tenantId: mainTenant._id } }
    );

    const companiesForScope = await Company.find().select('_id tenantId partnerId').lean();
    for (const company of companiesForScope) {
      const scope = {
        tenantId: company.tenantId || mainTenant._id,
        partnerId: company.partnerId || null,
      };
      const missingTenant = {
        companyId: company._id,
        $or: [{ tenantId: null }, { tenantId: { $exists: false } }],
      };
      await Promise.all([
        System.updateMany(missingTenant, { $set: scope }),
        Alert.updateMany(missingTenant, { $set: scope }),
        Log.updateMany(missingTenant, { $set: scope }),
      ]);
    }

    // Historical one-time migration must never rescan the alerts collection on
    // every backend restart. Opt in only while performing that migration.
    if (process.env.RUN_LEGACY_SEVERITY_MIGRATION === 'true') try {
      console.log('[Migration] Updating legacy alert severities to prevent false-positive High stats...');
      const u1 = await Alert.updateMany({ source: 'suricata', severity: 'medium' }, { $set: { severity: 'low' } });
      const u2 = await Alert.updateMany({ source: 'suricata', severity: 'high' }, { $set: { severity: 'medium' } });
      console.log(`[Migration] Done. Shifts: med->low = ${u1.modifiedCount}, high->med = ${u2.modifiedCount}`);
    } catch (migErr) {
      console.error('⚠️  Severity migration error:', migErr.message);
    }
  } catch (err) {
    console.error('⚠️  Superadmin init error:', err.message);
  }
}

// ── Start ──────────────────────────────────────────────
const cluster = require('cluster');
const os = require('os');

const CLUSTER_MODE = process.env.CLUSTER_MODE === 'true';
const isMaster = cluster.isPrimary || cluster.isMaster;

if (CLUSTER_MODE && isMaster) {
  // Generate one development transport key in the primary and pass it to all
  // workers. Production deployments should still configure a persistent key,
  // but this prevents cross-worker authentication failures when the fallback
  // ephemeral key is used.
  const { ensureSharedTransportKeyEnvironment } = require('./utils/webPayloadEncryption');
  const transportKeyId = ensureSharedTransportKeyEnvironment();
  const numCPUs = Math.max(1, Math.min(os.cpus().length, Number(process.env.WEB_CONCURRENCY || os.cpus().length)));
  console.log(`[Cluster] Master process ${process.pid} is running`);
  console.log(`[Cluster] Shared web transport key ${transportKeyId}`);
  console.log(`[Cluster] Forking ${numCPUs} worker processes...`);

  // Track the designated scheduler worker
  let schedulerWorkerId = null;

  function designateScheduler() {
    const workers = Object.values(cluster.workers).filter(w => w.state === 'listening' || w.state === 'online');
    if (workers.length > 0) {
      const selected = workers[0];
      schedulerWorkerId = selected.id;
      selected.send({ type: 'start_scheduler' });
      console.log(`[Cluster] Designated Worker ${selected.id} (PID ${selected.process.pid}) as background scheduler`);
    }
  }

  // Fork workers
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  // Handle messages from workers for cross-process socket and cache sync
  cluster.on('message', (worker, msg) => {
    if (msg && (msg.type === 'socket_broadcast' || msg.type === 'block_cache_sync')) {
      for (const id in cluster.workers) {
        const w = cluster.workers[id];
        if (w && w.process.pid !== msg.senderPid) {
          w.send(msg);
        }
      }
    }
  });

  cluster.on('online', (worker) => {
    console.log(`[Cluster] Worker ${worker.id} (PID ${worker.process.pid}) is online`);
    if (!schedulerWorkerId) {
      designateScheduler();
    }
  });

  cluster.on('exit', (worker, code, signal) => {
    if (shuttingDown) return;
    console.log(`[Cluster] Worker ${worker.id} (PID ${worker.process.pid}) died (code: ${code}, signal: ${signal}). Forking replacement...`);
    cluster.fork();
    if (worker.id === schedulerWorkerId) {
      schedulerWorkerId = null;
      setTimeout(designateScheduler, 1000);
    }
  });

  const shutdownMaster = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[Shutdown] ${signal}: draining cluster workers`);
    for (const worker of Object.values(cluster.workers)) {
      if (worker) worker.process.kill('SIGTERM');
    }
    const forceTimer = setTimeout(() => process.exit(1), 30_000);
    forceTimer.unref();
    cluster.disconnect(() => process.exit(0));
  };
  process.once('SIGTERM', () => shutdownMaster('SIGTERM'));
  process.once('SIGINT', () => shutdownMaster('SIGINT'));

} else {
  // WORKER PROCESS or SINGLE PROCESS MODE
  const PORT = Number(process.env.SERVER_PORT);
  connectDB().then(async () => {
    const { backfillFimBaselines } = require('./services/fimBaseline.service');
    const runFimBaselineBackfill = async () => {
      try {
        const result = await backfillFimBaselines();
        if (result.modified > 0) console.log(`[agent] FIM baseline backfilled for ${result.modified} system(s)`);
      } catch (err) {
        console.warn('[agent] FIM baseline backfill deferred:', err.message);
      }
    };
    await runFimBaselineBackfill();
    mongoose.connection.on('reconnected', runFimBaselineBackfill);

    await require('./infrastructure/socketAdapter').configureSocketAdapter(io);
    const socNotificationService = require('./services/socNotification.service');
    socNotificationService.attachIO(io);
    await socNotificationService.ensureIndexes().catch(error => {
      console.warn('[SOC notifications] index migration deferred:', error.message);
    });
    await wafRoutes.ensureIndexes().catch(error => {
      console.warn('[WAF] index migration deferred:', error.message);
    });
    await initializeSuperAdmin();

    // Load block cache in all workers on start
    const ipsService = require('./services/ips.service');
    await ipsService.loadBlockCache();

    // ── Register IPS Engine globally (for cross-service simulate endpoint) ──
    const ipsEngine = require('./services/ipsEngine.service');
    ipsEngine.attachIO(io);
    global._ipsEngineRef = ipsEngine;
    console.log('[IPS Engine] Registered globally ✅');

    // ── Register Fraud Service IO + seed default rules ──
    const fraudService = require('./services/fraud.service');
    fraudService.attachIO(io);
    const seedFraudRules = require('../scripts/seedFraudRules');
    await seedFraudRules();
    console.log('[Fraud] Service registered and rules seeded ✅');

    // ── Register SOAR Service IO (for real block_ip / isolate dispatch) ──
    const soarService = require('./services/soar.service');
    soarService.attachIO(io);
    console.log('[SOAR] Socket.IO attached — real-time agent dispatch enabled ✅');

    // ── Monkey patch Socket.IO for Cluster IPC Sync ──────────────────────
    if (CLUSTER_MODE && cluster.isWorker && !require('./infrastructure/socketAdapter').redisSocketEnabled()) {
      const originalTo = io.to;
      io.to = function (room) {
        const operator = originalTo.call(io, room);
        operator.emit = function (event, ...args) {
          operator.local.emit(event, ...args);
          if (process.send) {
            process.send({
              type: 'socket_broadcast',
              room,
              event,
              args,
              senderPid: process.pid
            });
          }
          return this;
        };
        return operator;
      };

      const originalEmit = io.emit;
      io.emit = function (event, ...args) {
        io.local.emit(event, ...args);
        if (process.send) {
          process.send({
            type: 'socket_broadcast',
            room: null,
            event,
            args,
            senderPid: process.pid
          });
        }
        return this;
      };

      // Listen for broadcasts from other workers via the master
      process.on('message', (msg) => {
        if (!msg) return;

        if (msg.type === 'socket_broadcast') {
          const { room, event, args } = msg;
          if (room) {
            originalTo.call(io, room).local.emit(event, ...args);
          } else {
            io.local.emit(event, ...args);
          }
        } else if (msg.type === 'block_cache_sync') {
          const { action, ip, ips } = msg;
          if (action === 'delete_multiple') {
            ipsService.syncBlockCache('delete_multiple', ips);
          } else {
            ipsService.syncBlockCache(action, ip);
          }
        }
      });
    }

    // Background tasks function
    const startBackgroundSchedulers = () => {
      require('./services/dailyReport.service').scheduleDailyReports();
      require('./services/correlation.service').scheduleCorrelation(io);
      ipsService.startExpirySweeper();
      ipsEngine.startAutoRecoverySweeper();
      require('./services/heartbeatSweeper.service').startSweeper(io);
      require('./services/tenantKms.service').startKeyRotationScheduler(io);
      encryptionRoutes.resumePendingEvidenceJobs(io).catch(error => console.warn('[Encryption] resume deferred:', error.message));
    };

    if (CLUSTER_MODE && cluster.isWorker) {
      process.on('message', (msg) => {
        if (msg && msg.type === 'start_scheduler') {
          startBackgroundSchedulers();
        }
      });
    } else {
      startBackgroundSchedulers();
    }

    server.listen(PORT, () => {
      console.log(`🚀 Backend → ${process.env.TLS_ENABLED === 'true' ? 'https' : 'http'}://localhost:${PORT} (PID ${process.pid})`);

      // ── Auto-spawn Kafka ingestion worker ────────────────────────────────
      // When INGESTION_MODE=broker, alerts land in Kafka and the worker
      // is the only process that persists them to MongoDB. Fork it here so
      // a single `npm run dev` / `npm start` is all you need to run.
      if (process.env.INGESTION_MODE === 'broker' && process.env.KAFKA_AUTO_START_WORKER !== 'false') {
        const workerPath = path.join(__dirname, 'workers', 'alertIngestion.worker.js');
        let workerRestarts = 0;

        const spawnWorker = () => {
          if (shuttingDown) return;
          const startedAt = Date.now();
          const worker = fork(workerPath, [], {
            env: process.env,
            silent: false,
          });
          console.log(`[Kafka Worker] Started (PID ${worker.pid})`);

          worker.on('exit', (code, signal) => {
            if (shuttingDown) return; // parent is shutting down — expected
            if (Date.now() - startedAt >= 60_000) workerRestarts = 0;
            workerRestarts += 1;
            // A prolonged infrastructure outage must not permanently disable
            // ingestion. Retry with capped backoff; shutdown stops the timer.
            const delay = Math.min(1000 * 2 ** Math.min(workerRestarts - 1, 6), 60_000);
            console.warn(`[Kafka Worker] Exited (code=${code}, signal=${signal}). Restart #${workerRestarts} in ${delay}ms…`);
            const restartTimer = setTimeout(spawnWorker, delay);
            restartTimer.unref();
          });

          // Expose reference so the shutdown handler can kill it cleanly
          server._kafkaWorker = worker;
        };

        spawnWorker();
      }
    });


    const shutdownWorker = async (signal) => {
      if (shuttingDown) return;
      shuttingDown = true;
      console.log(`[Shutdown] ${signal}: stopping new traffic and draining connections`);
      const forceTimer = setTimeout(() => process.exit(1), 30_000);
      forceTimer.unref();
      server.close(async () => {
        try {
          io.close();
          await require('./infrastructure/socketAdapter').closeSocketAdapter();
          await require('./infrastructure/nonceStore').closeNonceStore();
          await closeScalableReadCache();
          // Kill the Kafka worker child process cleanly
          if (server._kafkaWorker && !server._kafkaWorker.killed) {
            server._kafkaWorker.kill('SIGTERM');
          }
          await require('./services/eventBroker.service').disconnectEventBroker();
          await require('./observability/telemetry').stopTelemetry();
          await mongoose.disconnect();
          clearTimeout(forceTimer);
          process.exit(0);
        } catch (err) {
          console.error('[Shutdown]', err.message);
          process.exit(1);
        }
      });
    };
    process.once('SIGTERM', () => shutdownWorker('SIGTERM'));
    process.once('SIGINT', () => shutdownWorker('SIGINT'));
  }).catch(err => {
    console.error('[Startup] MongoDB connection could not be established:', err.message);
    process.exitCode = 1;
  });
}
