const axios = require('axios');
const { execFile } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');
const Log = require('../models/Log.model');
const System = require('../models/System.model');
const ForensicHunt = require('../models/ForensicHunt.model');
const ForensicEvidence = require('../models/ForensicEvidence.model');

const recentScans = new Map();
let clientsCache = { expiresAt: 0, clients: [], pending: null };

function isConfigured() {
  const apiConfig = process.env.VELOCIRAPTOR_API_CONFIG;
  const serverConfig = process.env.VELOCIRAPTOR_SERVER_CONFIG;
  const hasCliConfig = Boolean(
    (apiConfig && fs.existsSync(apiConfig))
    || (serverConfig && fs.existsSync(serverConfig))
    || decodeApiConfig(process.env.VELOCIRAPTOR_KEY)
  );
  const hasRestConfig = Boolean(
    process.env.VELOCIRAPTOR_URL
    && (process.env.VELOCIRAPTOR_USERNAME || (process.env.VELOCIRAPTOR_KEY && !decodeApiConfig(process.env.VELOCIRAPTOR_KEY)))
  );
  return hasCliConfig || hasRestConfig;
}

function isSiemAutoScanEnabled() {
  return String(process.env.VELOCIRAPTOR_SIEM_AUTOSCAN || 'true').toLowerCase() !== 'false';
}

function throttleMs() {
  const seconds = Number(process.env.VELOCIRAPTOR_SIEM_THROTTLE_SECONDS || 60);
  return Math.max(5, seconds) * 1000;
}

function artifactForLog(log) {
  const text = [
    log.logType,
    log.source,
    log.program,
    log.message,
    Array.isArray(log.tags) ? log.tags.join(' ') : '',
  ].filter(Boolean).join(' ').toLowerCase();

  if (/yara|malware|ransom|virus|trojan|ioc|hash/.test(text)) {
    return 'Generic.Detection.Yara.Glob';
  }
  if (/auth|login|logon|failed|sudo|privilege|account/.test(text)) {
    return 'Windows.EventLogs.Evtx';
  }
  if (/network|dns|conn|firewall|ids|ips|suricata|zeek|beacon|c2|ip /.test(text)) {
    return 'Linux.Network.Netstat';
  }
  if (/file|created|modified|deleted|fim|download|tmp|var\/tmp/.test(text)) {
    return 'Generic.Forensic.LocalHashes';
  }
  if (/process|command|exec|powershell|bash|shell|service/.test(text)) {
    return 'Linux.Sys.Pslist';
  }
  return 'Generic.Client.Info';
}

function artifactForCorrelation(finding) {
  const text = [
    finding.patternId,
    finding.patternName,
    finding.category,
    finding.title,
    finding.description,
    finding.severity,
    finding.mitreTechnique,
  ].filter(Boolean).join(' ').toLowerCase();

  if (/ransom|encrypt|mass file|exfil|usb/.test(text)) return 'Generic.Forensic.LocalHashes';
  if (/brute|auth|login|credential|mimikatz|lsass/.test(text)) return 'Windows.EventLogs.Evtx';
  if (/malware|yara|ioc|hash/.test(text)) return 'Generic.Detection.Yara.Glob';
  if (/network|c2|beacon|port scan|lateral|rdp|smb|psexec/.test(text)) return 'Linux.Network.Netstat';
  if (/priv|exec|process|service|persistence|scheduled/.test(text)) return 'Linux.Sys.Pslist';
  return 'Generic.Client.Info';
}

function decodeApiConfig(value) {
  if (!value) return '';
  const raw = String(value).trim();
  if (/^ca_certificate:\s*\|/m.test(raw)) return raw;

  try {
    const decoded = Buffer.from(raw, 'base64').toString('utf8');
    return /^ca_certificate:\s*\|/m.test(decoded) ? decoded : '';
  } catch {
    return '';
  }
}

function cliConfigArgs() {
  if (process.env.VELOCIRAPTOR_API_CONFIG && fs.existsSync(process.env.VELOCIRAPTOR_API_CONFIG)) {
    return ['--api_config', process.env.VELOCIRAPTOR_API_CONFIG];
  }
  if (decodeApiConfig(process.env.VELOCIRAPTOR_KEY)) {
    return ['--api_config'];
  }
  if (process.env.VELOCIRAPTOR_SERVER_CONFIG && fs.existsSync(process.env.VELOCIRAPTOR_SERVER_CONFIG)) {
    return ['--config', process.env.VELOCIRAPTOR_SERVER_CONFIG];
  }
  return null;
}

function serverConfigPath() {
  if (process.env.VELOCIRAPTOR_SERVER_CONFIG && fs.existsSync(process.env.VELOCIRAPTOR_SERVER_CONFIG)) {
    return process.env.VELOCIRAPTOR_SERVER_CONFIG;
  }
  return '';
}

function clientsFromDatastore() {
  const configPath = serverConfigPath();
  if (!configPath) return [];

  const datastore = path.dirname(configPath);
  const clientsDir = path.join(datastore, 'clients');
  try {
    return fs.readdirSync(clientsDir, { withFileTypes: true })
      .filter(entry => entry.isDirectory() && /^C\./.test(entry.name))
      .map(entry => ({
        client_id: entry.name,
        id: entry.name,
        hostname: '',
        source: 'datastore',
      }));
  } catch {
    return [];
  }
}

function runVelociraptorQuery(query, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const config = decodeApiConfig(process.env.VELOCIRAPTOR_KEY);
    const args = cliConfigArgs();
    if (!args) return reject(new Error('Velociraptor CLI config not available'));

    let tempConfig = '';
    const finalArgs = [];
    if (args[0] === '--api_config' && !args[1]) {
      tempConfig = path.join(os.tmpdir(), `soc4-velo-api-${process.pid}-${Date.now()}.yaml`);
      fs.writeFileSync(tempConfig, config, { mode: 0o600 });
      finalArgs.push('--api_config', tempConfig);
    } else {
      finalArgs.push(...args);
    }

    finalArgs.push('query', '--format=json', query);

    execFile(process.env.VELOCIRAPTOR_CLI || 'velociraptor', finalArgs, { timeout }, (err, stdout, stderr) => {
      if (tempConfig) fs.rm(tempConfig, { force: true }, () => {});
      if (err) {
        const detail = String(stderr || err.message || 'Velociraptor query failed').trim();
        return reject(new Error(friendlyVelociraptorError(detail)));
      }
      try {
        resolve(JSON.parse(stdout || '[]'));
      } catch {
        reject(new Error('Velociraptor returned invalid JSON'));
      }
    });
  });
}

function vqlString(value) {
  return JSON.stringify(String(value || ''));
}

function vqlList(values) {
  return `[${values.map(vqlString).join(', ')}]`;
}

function friendlyVelociraptorError(detail) {
  const text = String(detail || '');
  if (/server\.config\.yaml.*no such file|no such file or directory/i.test(text)) {
    return 'Velociraptor server config file is missing. Set VELOCIRAPTOR_API_CONFIG/VELOCIRAPTOR_KEY or a valid VELOCIRAPTOR_SERVER_CONFIG path.';
  }
  if (/connection refused|Error while dialing|code = Unavailable/i.test(text)) {
    return 'Velociraptor server/API is not running or not reachable. Start the Velociraptor server/API and verify api_connection_string.';
  }
  return text || 'Velociraptor query failed';
}

function restOptions(timeout) {
  const headers = {};
  const options = {
    headers,
    timeout,
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  };

  if (process.env.VELOCIRAPTOR_USERNAME || process.env.VELOCIRAPTOR_PASSWORD) {
    options.auth = {
      username: process.env.VELOCIRAPTOR_USERNAME || '',
      password: process.env.VELOCIRAPTOR_PASSWORD || '',
    };
  } else if (process.env.VELOCIRAPTOR_KEY && !decodeApiConfig(process.env.VELOCIRAPTOR_KEY)) {
    headers.Authorization = process.env.VELOCIRAPTOR_KEY.toLowerCase().startsWith('bearer ')
      ? process.env.VELOCIRAPTOR_KEY
      : `Bearer ${process.env.VELOCIRAPTOR_KEY}`;
  }

  return options;
}

async function fetchVelociraptorClients() {
  if (!isConfigured()) return [];

  if (cliConfigArgs()) {
    const rows = await runVelociraptorQuery(
      'SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, last_seen_at FROM clients() LIMIT 100',
      10000
    );
    if (Array.isArray(rows) && rows.length) return rows;
    return clientsFromDatastore();
  }

  const { data } = await axios.get(`${process.env.VELOCIRAPTOR_URL}/api/v1/SearchClients`, restOptions(8000));
  return data?.items || [];
}

async function veloListClients({ fresh = false } = {}) {
  const now = Date.now();
  if (!fresh && clientsCache.expiresAt > now) return clientsCache.clients;
  if (clientsCache.pending) return clientsCache.pending;
  clientsCache.pending = fetchVelociraptorClients()
    .then(clients => {
      clientsCache = { expiresAt: Date.now() + 15000, clients, pending: null };
      return clients;
    })
    .catch(error => {
      clientsCache.pending = null;
      throw error;
    });
  return clientsCache.pending;
}

async function veloRunHunt({ name, artifactName, artifacts, clientId }) {
  if (!isConfigured()) throw new Error('Velociraptor not configured');

  const artifactList = Array.isArray(artifacts) && artifacts.length
    ? artifacts.map(a => String(a).trim()).filter(Boolean)
    : String(artifactName || '').split(/[\n,]+/).map(a => a.trim()).filter(Boolean);

  if (!artifactList.length) throw new Error('At least one artifact is required');

  if (cliConfigArgs()) {
    const query = clientId
      ? `SELECT collect_client(client_id=${vqlString(clientId)}, artifacts=${vqlList(artifactList)}) AS collection FROM scope()`
      : `SELECT hunt(description=${vqlString(name || 'SOC4 Velociraptor hunt')}, artifacts=${vqlList(artifactList)}) AS hunt FROM scope()`;
    const rows = await runVelociraptorQuery(query, 15000);
    return rows?.[0]?.hunt || rows?.[0]?.collection || rows;
  }

  const payload = {
    hunt_description: name,
    description: name,
    artifacts: artifactList,
    start_request: { artifacts: artifactList },
    condition: { os: { os: 'ALL' } },
  };

  if (clientId) payload.client_id = clientId;

  const { data } = await axios.post(
    `${process.env.VELOCIRAPTOR_URL}/api/v1/CreateHunt`,
    payload,
    restOptions(10000)
  );
  return data;
}

async function veloGetFlow({ clientId, flowId, includeResults = false }) {
  if (!clientId || !flowId) throw new Error('Velociraptor client ID and flow ID are required');
  const rows = await runVelociraptorQuery(
    `SELECT * FROM flows(client_id=${vqlString(clientId)}) WHERE session_id=${vqlString(flowId)} LIMIT 1`,
    12000
  );
  const flow = rows?.[0] || null;
  if (!flow || !includeResults || !Array.isArray(flow.artifacts_with_results)) return { flow, results: {} };

  const results = {};
  for (const artifact of flow.artifacts_with_results.slice(0, 20)) {
    results[artifact] = await runVelociraptorQuery(
      `SELECT * FROM flow_results(client_id=${vqlString(clientId)}, flow_id=${vqlString(flowId)}, artifact=${vqlString(artifact)}) LIMIT 200`,
      15000
    );
  }
  return { flow, results };
}

async function resolveClientId(log) {
  if (log.fields?.velociraptor_client_id) return log.fields.velociraptor_client_id;
  if (log.fields?.velociraptorClientId) return log.fields.velociraptorClientId;
  if (log.velociraptor_client_id) return log.velociraptor_client_id;

  const filter = {};
  if (log.systemId) filter._id = log.systemId;
  else if (log.agentKey && log.companyId) {
    filter.agentKey = log.agentKey;
    filter.companyId = log.companyId;
  } else {
    return '';
  }

  const system = await System.findOne(filter).select('velociraptorClientId hostname name').lean();
  if (!system) return '';
  try {
    const clients = await veloListClients();
    const clientId = system.velociraptorClientId || '';
    if (clientId && clients.some(client => (client.client_id || client.id) === clientId)) return clientId;
    const names = [system.hostname, system.name, log.hostname, log.agentName]
      .filter(Boolean).map(value => String(value).toLowerCase());
    const match = clients.find(client => names.includes(String(client.hostname || client.os_info?.hostname || '').toLowerCase()));
    if (match) return match.client_id || match.id || '';
  } catch {
    // Preserve legacy mapped client ID when the server cannot be queried.
  }
  return system.velociraptorClientId || '';
}

async function emitLog(io, log) {
  if (!io || !log?.companyId) return;
  io.to(`company:${log.companyId}`).emit('log:new', typeof log.toObject === 'function' ? log.toObject() : log);
}

async function createScanLog(originalLog, fields, level = 'info') {
  const message = level === 'error'
    ? `Velociraptor SIEM auto-scan failed: ${fields.error || 'unknown error'}`
    : `Velociraptor SIEM auto-scan launched: ${fields.artifactName}`;

  return Log.create({
    companyId: originalLog.companyId,
    departmentId: originalLog.departmentId,
    systemId: originalLog.systemId,
    source: 'velociraptor',
    agentKey: originalLog.agentKey,
    agentName: originalLog.agentName,
    hostname: originalLog.hostname,
    ipAddress: originalLog.ipAddress,
    logType: 'edr',
    level,
    message,
    program: 'velociraptor',
    logTime: new Date(),
    receivedAt: new Date(),
    fields: {
      action: level === 'error' ? 'siem_auto_scan_failed' : 'siem_auto_scan_launched',
      sourceLogId: originalLog._id,
      sourceLogType: originalLog.logType,
      sourceLogLevel: originalLog.level,
      sourceLogMessage: originalLog.message,
      ...fields,
    },
    raw: JSON.stringify({ sourceLogId: originalLog._id, ...fields }),
    format: 'json',
    tags: ['siem', 'velociraptor', 'auto-scan'].concat(level === 'error' ? ['error'] : []),
  });
}

async function autoScanSiemLog(log, { io } = {}) {
  if (!isSiemAutoScanEnabled()) return { skipped: 'disabled' };
  if (!isConfigured()) return { skipped: 'not_configured' };
  if (!log?.companyId) return { skipped: 'missing_company' };
  if (log.source === 'velociraptor') return { skipped: 'velociraptor_log' };

  const artifactName = artifactForLog(log);
  const clientId = await resolveClientId(log);
  const hostKey = clientId || log.systemId || log.hostname || log.agentName || log.ipAddress || 'fleet';
  const key = `${log.companyId}:${hostKey}:${artifactName}`;
  const now = Date.now();
  const last = recentScans.get(key) || 0;

  if (now - last < throttleMs()) {
    return { skipped: 'throttled', artifactName };
  }

  recentScans.set(key, now);

  try {
    const huntName = `SIEM auto-scan: ${log.logType || 'log'} ${log.hostname || log.agentName || hostKey}`;
    const result = await veloRunHunt({ name: huntName, artifactName, clientId });
    const scanLog = await createScanLog(log, { artifactName, clientId, result });
    await emitLog(io, scanLog);
    return { ok: true, artifactName, result };
  } catch (err) {
    const scanLog = await createScanLog(log, { artifactName, clientId, error: err.message }, 'error');
    await emitLog(io, scanLog);
    return { ok: false, artifactName, error: err.message };
  }
}

async function autoScanCorrelationFinding(finding, { io, source = 'correlation' } = {}) {
  if (!isSiemAutoScanEnabled()) return { skipped: 'disabled' };
  if (!isConfigured()) return { skipped: 'not_configured' };
  if (!finding?.companyId) return { skipped: 'missing_company' };

  const artifactName = artifactForCorrelation(finding);
  const clientId = await resolveClientId(finding);
  const hostKey = clientId || finding.systemId || finding.agentName || finding.affectedEndpoint || 'fleet';
  const findingId = finding._id?.toString?.() || finding.patternId || finding.category || source;
  const key = `${finding.companyId}:${hostKey}:${source}:${artifactName}:${findingId}`;
  const now = Date.now();
  const last = recentScans.get(key) || 0;

  if (now - last < throttleMs()) {
    return { skipped: 'throttled', artifactName };
  }

  recentScans.set(key, now);

  const name = `Correlation auto-scan: ${finding.patternName || finding.title || finding.category || source}`;

  try {
    const result = await veloRunHunt({ name, artifactName, clientId });
    const scanLog = await Log.create({
      companyId: finding.companyId,
      departmentId: finding.departmentId,
      systemId: finding.systemId,
      source: 'velociraptor',
      agentName: finding.agentName || finding.affectedEndpoint,
      hostname: finding.affectedEndpoint,
      logType: 'edr',
      level: 'info',
      message: `Velociraptor correlation auto-scan launched: ${artifactName}`,
      program: 'velociraptor',
      logTime: new Date(),
      receivedAt: new Date(),
      fields: {
        action: 'correlation_auto_scan_launched',
        source,
        findingId,
        patternId: finding.patternId,
        patternName: finding.patternName,
        incidentTitle: finding.title,
        category: finding.category,
        severity: finding.severity,
        confidence: finding.confidence || finding.confidenceScore,
        artifactName,
        clientId,
        result,
      },
      raw: JSON.stringify({ source, findingId, artifactName, clientId, result }),
      format: 'json',
      tags: ['correlation', 'siem', 'velociraptor', 'auto-scan'],
    });
    await emitLog(io, scanLog);
    return { ok: true, artifactName, result };
  } catch (err) {
    const scanLog = await Log.create({
      companyId: finding.companyId,
      departmentId: finding.departmentId,
      systemId: finding.systemId,
      source: 'velociraptor',
      agentName: finding.agentName || finding.affectedEndpoint,
      hostname: finding.affectedEndpoint,
      logType: 'edr',
      level: 'error',
      message: `Velociraptor correlation auto-scan failed: ${err.message}`,
      program: 'velociraptor',
      logTime: new Date(),
      receivedAt: new Date(),
      fields: {
        action: 'correlation_auto_scan_failed',
        source,
        findingId,
        patternId: finding.patternId,
        patternName: finding.patternName,
        incidentTitle: finding.title,
        category: finding.category,
        severity: finding.severity,
        artifactName,
        clientId,
        error: err.message,
      },
      raw: JSON.stringify({ source, findingId, artifactName, clientId, error: err.message }),
      format: 'json',
      tags: ['correlation', 'siem', 'velociraptor', 'auto-scan', 'error'],
    });
    await emitLog(io, scanLog);
    return { ok: false, artifactName, error: err.message };
  }
}

async function syncHuntIfFinished(hunt, { io } = {}) {
  if (!hunt || hunt.status === 'completed') return hunt;
  const clientId = hunt.clientId;
  const flowId = hunt.providerResult?.launch?.flow_id || hunt.providerResult?.launch?.session_id;
  if (!clientId || !flowId) return hunt;

  try {
    const checked = await veloGetFlow({ clientId, flowId, includeResults: false });
    const flowState = checked?.flow;
    const state = String(flowState?.state || '').toUpperCase();
    if (state === 'FINISHED') {
      const full = await veloGetFlow({ clientId, flowId, includeResults: true });
      const result = { launch: hunt.providerResult?.launch || { flow_id: flowId, session_id: flowId }, ...full };
      const serialized = JSON.stringify(result || {});
      const sha256 = crypto.createHash('sha256').update(serialized).digest('hex');

      let evidence = await ForensicEvidence.findOne({ huntId: hunt._id });
      if (!evidence) {
        const target = hunt.systemId ? await System.findById(hunt.systemId).lean() : null;
        evidence = await ForensicEvidence.create({
          companyId: hunt.companyId,
          departmentId: hunt.departmentId || target?.departmentId || null,
          systemId: hunt.systemId || null,
          huntId: hunt._id,
          evidenceId: `EVD-${crypto.randomUUID()}`,
          name: `${hunt.name} result`,
          type: 'Velociraptor Collection',
          sourceHost: target?.hostname || target?.name || (clientId || 'Fleet'),
          artifactName: Array.isArray(hunt.artifacts) ? hunt.artifacts.join(', ') : String(hunt.artifacts || ''),
          sizeBytes: Buffer.byteLength(serialized),
          sha256,
          collectedBy: hunt.requestedBy,
          custody: [{ action: 'collected', actorId: hunt.requestedBy, actorRole: hunt.requestedByRole, sourceIp: hunt.sourceIp, note: `Collected by hunt ${hunt._id}` }],
        });
        const { enqueueForensicEvidenceAnalysis } = require('./azureAi.service');
        const actor = { id: hunt.requestedBy, role: hunt.requestedByRole };
        enqueueForensicEvidenceAnalysis(evidence, { io, user: actor, sourceIp: hunt.sourceIp })
          .catch(error => console.error('[forensics/ai]', error.message));
      }

      const updated = await ForensicHunt.findByIdAndUpdate(hunt._id, {
        $set: {
          status: 'completed',
          providerResult: result,
          error: null,
          completedAt: new Date(),
        },
      }, { new: true }).lean();

      io?.to(`company:${hunt.companyId}`).emit('forensics:updated', { huntId: hunt._id, evidenceId: evidence._id });
      io?.to('superadmin').emit('forensics:updated', { companyId: hunt.companyId, huntId: hunt._id, evidenceId: evidence._id });
      return updated || hunt;
    }
  } catch (err) {
    // Retain existing hunt record on transient lookup failure
  }
  return hunt;
}

module.exports = {
  autoScanCorrelationFinding,
  autoScanSiemLog,
  artifactForCorrelation,
  artifactForLog,
  isConfigured,
  veloListClients,
  veloGetFlow,
  veloRunHunt,
  syncHuntIfFinished,
};
