const crypto = require('crypto');
const client = require('prom-client');
const { context, trace } = require('@opentelemetry/api');
const { accessLogsEnabled, isLevelEnabled } = require('./runtimeLogging');

const registry = new client.Registry();
client.collectDefaultMetrics({ register: registry, prefix: 'soc_' });
const requests = new client.Counter({
  name: 'soc_http_requests_total', help: 'Completed HTTP requests',
  labelNames: ['method', 'route', 'status'], registers: [registry],
});
const duration = new client.Histogram({
  name: 'soc_http_request_duration_seconds', help: 'HTTP request duration',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10], registers: [registry],
});
const ingestionEvents = new client.Counter({
  name: 'soc_ingestion_events_total', help: 'Ingestion event outcomes',
  labelNames: ['kind', 'mode', 'outcome'], registers: [registry],
});

function normalizeRoute(req) {
  if (req.route?.path) return `${req.baseUrl || ''}${req.route.path}`;
  return String(req.path || '/').replace(/[a-f0-9]{24}/gi, ':id').replace(/\d{4,}/g, ':n');
}

function log(level, event, fields = {}) {
  if (!isLevelEnabled(level)) return;
  const activeSpan = trace.getSpan(context.active());
  const traceId = activeSpan?.spanContext().traceId;
  process.stdout.write(`${JSON.stringify({
    timestamp: new Date().toISOString(), level, event,
    service: process.env.OTEL_SERVICE_NAME || 'soc-backend',
    ...(traceId && { trace_id: traceId }), ...fields,
  })}\n`);
}

function httpObservability(req, res, next) {
  const started = process.hrtime.bigint();
  req.id = String(req.headers['x-request-id'] || crypto.randomUUID()).slice(0, 128);
  res.setHeader('x-request-id', req.id);
  res.once('finish', () => {
    const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
    const route = normalizeRoute(req);
    const labels = { method: req.method, route, status: String(res.statusCode) };
    requests.inc(labels);
    duration.observe(labels, elapsed);
    if (accessLogsEnabled() || res.statusCode >= 500) {
      log(res.statusCode >= 500 ? 'error' : 'info', 'http_request', {
        request_id: req.id, method: req.method, route, status: res.statusCode,
        duration_ms: Math.round(elapsed * 1000),
        tenant_id: req.user?.tenantId ? String(req.user.tenantId) : undefined,
        company_id: req.user?.companyId ? String(req.user.companyId) : undefined,
        actor_role: req.user?.role,
      });
    }
  });
  next();
}

function metricsHandler(req, res) {
  const required = process.env.METRICS_BEARER_TOKEN;
  if (required) {
    const supplied = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const a = Buffer.from(supplied);
    const b = Buffer.from(required);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).end();
  }
  res.setHeader('Content-Type', registry.contentType);
  return registry.metrics().then(body => res.end(body));
}

module.exports = { registry, requests, duration, ingestionEvents, normalizeRoute, log, httpObservability, metricsHandler };
