#!/usr/bin/env node
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const zlib = require('zlib');

function canonicalize(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(function (key) {
      return JSON.stringify(key) + ':' + canonicalize(value[key]);
    }).join(',') + '}';
  }
  return JSON.stringify(value);
}

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = values.slice().sort(function (a, b) { return a - b; });
  return sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p))];
}

const targetUrl = new URL(process.env.TARGET_URL || 'http://127.0.0.1:5000/api/alerts/batch');
const durationSeconds = Number(process.env.DURATION_SECONDS || 30);
const targetEps = Number(process.env.TARGET_EPS || 1000);
const batchSize = Math.min(50, Math.max(1, Number(process.env.BATCH_SIZE || 20)));
const maxInflight = Number(process.env.MAX_INFLIGHT || 200);
const keysFile = process.env.AGENT_KEYS_FILE;

if (!keysFile) {
  console.error('AGENT_KEYS_FILE is required (JSON array of test-only agent keys).');
  process.exit(2);
}

const agentKeys = JSON.parse(fs.readFileSync(keysFile, 'utf8'));
if (!Array.isArray(agentKeys) || !agentKeys.length) {
  console.error('AGENT_KEYS_FILE must contain a non-empty JSON array.');
  process.exit(2);
}

const transport = targetUrl.protocol === 'https:' ? https : http;
const agent = targetUrl.protocol === 'https:'
  ? new https.Agent({ keepAlive: true, maxSockets: maxInflight })
  : new http.Agent({ keepAlive: true, maxSockets: maxInflight });

let keyIndex = 0;
let inFlight = 0;
let requests = 0;
let acceptedEvents = 0;
let duplicateEvents = 0;
let failedEvents = 0;
let locallyShedEvents = 0;
let bytesSent = 0;
const latencies = [];
const statusCounts = {};
const startedAt = Date.now();

function createBatch(agentKey) {
  const alerts = [];
  const now = new Date().toISOString();
  for (let index = 0; index < batchSize; index += 1) {
    alerts.push({
      event_id: crypto.randomUUID(),
      agent_key: agentKey,
      rule_id: 'LOAD_TEST_EVENT',
      category: 'system',
      severity: 'low',
      description: 'Authorized synthetic load-test event',
      timestamp: now,
      raw_log: 'load-test',
    });
  }
  return { alerts: alerts };
}

function sendBatch() {
  if (inFlight >= maxInflight) {
    locallyShedEvents += batchSize;
    return;
  }
  const agentKey = agentKeys[keyIndex++ % agentKeys.length];
  const payload = createBatch(agentKey);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID().replace(/-/g, '');
  const signature = crypto.createHmac('sha256', agentKey)
    .update(timestamp + '.' + nonce + '.' + canonicalize(payload))
    .digest('hex');
  const compressed = zlib.gzipSync(Buffer.from(JSON.stringify(payload)));
  bytesSent += compressed.length;
  inFlight += 1;
  requests += 1;
  const requestStarted = process.hrtime.bigint();

  const req = transport.request({
    protocol: targetUrl.protocol,
    hostname: targetUrl.hostname,
    port: targetUrl.port,
    path: targetUrl.pathname + targetUrl.search,
    method: 'POST',
    agent: agent,
    headers: {
      'content-type': 'application/json',
      'content-encoding': 'gzip',
      'content-length': compressed.length,
      'x-agent-timestamp': timestamp,
      'x-agent-nonce': nonce,
      'x-agent-signature': signature,
    },
    timeout: 15000,
  }, function (res) {
    const chunks = [];
    res.on('data', function (chunk) { chunks.push(chunk); });
    res.on('end', function () {
      const latencyMs = Number(process.hrtime.bigint() - requestStarted) / 1e6;
      latencies.push(latencyMs);
      statusCounts[res.statusCode] = (statusCounts[res.statusCode] || 0) + 1;
      let body = {};
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
      if (res.statusCode === 200 || res.statusCode === 201 || res.statusCode === 202) {
        acceptedEvents += Number(body.inserted || body.accepted || 0);
        duplicateEvents += Number(body.duplicates || 0);
      } else {
        failedEvents += batchSize;
      }
      inFlight -= 1;
    });
  });
  req.on('timeout', function () { req.destroy(new Error('timeout')); });
  req.on('error', function () {
    failedEvents += batchSize;
    inFlight -= 1;
  });
  req.end(compressed);
}

const tickMs = 100;
const requestsPerTick = Math.max(1, Math.ceil((targetEps / batchSize) * (tickMs / 1000)));
const ticker = setInterval(function () {
  for (let index = 0; index < requestsPerTick; index += 1) sendBatch();
}, tickMs);

setTimeout(function () {
  clearInterval(ticker);
  const drain = setInterval(function () {
    if (inFlight !== 0) return;
    clearInterval(drain);
    agent.destroy();
    const elapsedSeconds = (Date.now() - startedAt) / 1000;
    console.log(JSON.stringify({
      targetEps: targetEps,
      batchSize: batchSize,
      logicalAgents: agentKeys.length,
      elapsedSeconds: Number(elapsedSeconds.toFixed(2)),
      requests: requests,
      acceptedEvents: acceptedEvents,
      duplicateEvents: duplicateEvents,
      failedEvents: failedEvents,
      locallyShedEvents: locallyShedEvents,
      acceptedEps: Number((acceptedEvents / elapsedSeconds).toFixed(2)),
      compressedBytesPerSecond: Number((bytesSent / elapsedSeconds).toFixed(2)),
      latencyMs: {
        p50: Number(percentile(latencies, 0.50).toFixed(2)),
        p95: Number(percentile(latencies, 0.95).toFixed(2)),
        p99: Number(percentile(latencies, 0.99).toFixed(2)),
      },
      statusCounts: statusCounts,
    }, null, 2));
  }, 100);
}, durationSeconds * 1000);
