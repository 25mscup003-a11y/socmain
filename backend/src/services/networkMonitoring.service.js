const crypto = require('crypto');
const net = require('net');
const NetworkConnection = require('../models/NetworkConnection.model');
const NetworkPolicy = require('../models/NetworkPolicy.model');

const REMOTE_ADMIN_PORTS = new Set([22, 135, 139, 445, 3389, 5985, 5986]);
const COMMON_PORTS = new Set([22, 25, 53, 80, 110, 123, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 27017]);
const BEACON_HISTORY_MS = 6 * 60 * 60 * 1000;
const BEACON_STATE_TTL_MS = 24 * 60 * 60 * 1000;
const BEACON_POLICY_PREFIX = '[Beaconing] ';
const BEACON_BASE_NAME = `${BEACON_POLICY_PREFIX}Baseline Configuration`;
const BEACON_CUSTOM_PREFIX = `${BEACON_POLICY_PREFIX}Custom: `;
const DEFAULT_BEACON_CONFIG = Object.freeze({
  enabled: true,
  minimumConnections: 6,
  minimumIntervalSeconds: 5,
  maximumIntervalSeconds: 3600,
  minimumObservationSeconds: 60,
  consistencyThreshold: 75,
  alertThreshold: 70,
  cooldownSeconds: 1800,
});
const BEACON_BUILTIN_RULES = Object.freeze([
  { id: 'exact-periodic-callback', name: 'Exact Periodic Callback', category: 'Timing', description: 'Detects highly consistent repeated callbacks with minimal interval variance.', severity: 'high', riskScore: 75, conditions: [{ field: 'beaconing', operator: 'eq', value: true }, { field: 'connectionCount', operator: 'gte', value: 6 }, { field: 'intervalConsistency', operator: 'gte', value: 90 }, { field: 'jitterSeconds', operator: 'lte', value: 5 }] },
  { id: 'jittered-c2-beacon', name: 'Jittered C2 Beacon', category: 'Timing', description: 'Detects periodic callbacks that deliberately vary their timing.', severity: 'high', riskScore: 70, conditions: [{ field: 'beaconing', operator: 'eq', value: true }, { field: 'connectionCount', operator: 'gte', value: 6 }, { field: 'intervalConsistency', operator: 'gte', value: 65 }, { field: 'jitterSeconds', operator: 'lte', value: 30 }] },
  { id: 'low-and-slow-beacon', name: 'Low-and-Slow Beacon', category: 'Behavior', description: 'Detects long-running callbacks with low frequency and low traffic volume.', severity: 'medium', riskScore: 55, conditions: [{ field: 'beaconing', operator: 'eq', value: true }, { field: 'connectionCount', operator: 'gte', value: 5 }, { field: 'averageInterval', operator: 'gte', value: 300 }, { field: 'observationSeconds', operator: 'gte', value: 1800 }] },
  { id: 'dns-periodic-beacon', name: 'DNS Periodic Beacon', category: 'DNS', description: 'Detects repeated DNS callbacks and possible DNS-based C2 activity.', severity: 'high', riskScore: 75, conditions: [{ field: 'beaconing', operator: 'eq', value: true }, { field: 'protocol', operator: 'eq', value: 'dns' }, { field: 'connectionCount', operator: 'gte', value: 6 }] },
  { id: 'http-https-beacon', name: 'HTTP / HTTPS Beacon', category: 'Web', description: 'Detects repeated web-protocol callbacks using connection metadata.', severity: 'high', riskScore: 70, conditions: [{ field: 'beaconing', operator: 'eq', value: true }, { field: 'protocol', operator: 'in', value: ['http', 'https', 'tls'] }, { field: 'connectionCount', operator: 'gte', value: 6 }] },
  { id: 'suspicious-process-beacon', name: 'Suspicious Process Beacon', category: 'Process', description: 'Raises confidence when script engines or LOLBins repeatedly contact an external destination.', severity: 'critical', riskScore: 85, conditions: [{ field: 'beaconing', operator: 'eq', value: true }, { field: 'processName', operator: 'contains', value: 'script-or-lolbin' }] },
]);
const beaconStates = new Map();
const beaconWarmups = new Map();

function number(value, fallback = 0) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function date(value, fallback = new Date()) {
  const parsed = value ? new Date(value) : fallback;
  return Number.isNaN(parsed.getTime()) ? fallback : parsed;
}

function isPrivateIp(value = '') {
  const ip = String(value).split('%', 1)[0];
  if (!net.isIP(ip)) return false;
  const normalized = ip.toLowerCase();
  if (normalized.startsWith('::ffff:')) return isPrivateIp(normalized.slice(7));
  if (normalized === '::' || normalized === '::1' || normalized.startsWith('fe80:') || normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  const octets = ip.split('.').map(Number);
  return octets.length === 4 && (
    octets[0] === 10 || octets[0] === 127 ||
    (octets[0] === 192 && octets[1] === 168) ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
  );
}

function severityForRisk(score) {
  if (score >= 81) return 'critical';
  if (score >= 61) return 'high';
  if (score >= 41) return 'elevated';
  if (score >= 21) return 'medium';
  return 'low';
}

function median(values = []) {
  if (!values.length) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

function calculateBeaconMetrics(timestamps = []) {
  const samples = [...new Set(timestamps.map(value => date(value).getTime()))]
    .filter(Number.isFinite)
    .sort((left, right) => left - right);
  const intervals = samples.slice(1).map((value, index) => (value - samples[index]) / 1000)
    .filter(value => value > 0);
  if (!intervals.length) {
    return {
      count: samples.length,
      averageInterval: 0,
      medianInterval: 0,
      jitterSeconds: 0,
      intervalConsistency: 0,
      periodicityScore: 0,
      observationSeconds: 0,
    };
  }
  const averageInterval = intervals.reduce((sum, value) => sum + value, 0) / intervals.length;
  const variance = intervals.reduce((sum, value) => sum + ((value - averageInterval) ** 2), 0) / intervals.length;
  const jitterSeconds = Math.sqrt(variance);
  const intervalConsistency = Math.max(0, Math.min(100, 100 - ((jitterSeconds / Math.max(averageInterval, 1)) * 100)));
  return {
    count: samples.length,
    averageInterval,
    medianInterval: median(intervals),
    jitterSeconds,
    intervalConsistency,
    periodicityScore: Math.round(intervalConsistency * 0.25),
    observationSeconds: (samples[samples.length - 1] - samples[0]) / 1000,
  };
}

function beaconConfigFor(alert, policies = []) {
  const scoped = policies.filter(policy => {
    const assets = Array.isArray(policy.scope?.assetIds) ? policy.scope.assetIds.map(String) : [];
    return !assets.length || assets.includes(String(alert.systemId || ''));
  });
  const baselinePolicy = scoped.find(policy => policy.name === BEACON_BASE_NAME);
  const activePolicies = scoped.filter(policy => policy.enabled !== false);
  const conditionValues = (field, operator) => activePolicies
    .flatMap(policy => policy.conditions || [])
    .filter(condition => condition.field === field && (!operator || condition.operator === operator))
    .map(condition => Number(condition.value))
    .filter(Number.isFinite);
  const configuredNumber = (field, operator, fallback, reducer = Math.min) => {
    const values = conditionValues(field, operator);
    return values.length ? values.reduce((left, right) => reducer(left, right)) : fallback;
  };
  const actionThresholds = activePolicies
    .filter(policy => policy.actions?.createAlert !== false)
    .map(policy => Number(policy.actions?.riskScore))
    .filter(Number.isFinite);
  const cooldowns = activePolicies.map(policy => Number(policy.suppressionSeconds)).filter(Number.isFinite);
  const enabledRuleSettings = BEACON_BUILTIN_RULES.flatMap(rule => {
    const stored = scoped.find(policy => policy.name === `${BEACON_POLICY_PREFIX}${rule.name}`);
    if (stored?.enabled === false) return [];
    return [{
      ...rule,
      severity: stored?.actions?.severity || rule.severity,
      riskScore: number(stored?.actions?.riskScore, rule.riskScore),
      conditions: stored?.conditions?.length ? stored.conditions : rule.conditions,
    }];
  });
  for (const policy of activePolicies.filter(item => String(item.name || '').startsWith(BEACON_CUSTOM_PREFIX))) {
    enabledRuleSettings.push({
      id: `custom:${policy._id}`,
      name: String(policy.name).slice(BEACON_CUSTOM_PREFIX.length),
      severity: policy.actions?.severity || 'medium',
      riskScore: number(policy.actions?.riskScore, DEFAULT_BEACON_CONFIG.alertThreshold),
      conditions: policy.conditions || [],
      custom: true,
    });
  }
  return {
    enabled: baselinePolicy ? baselinePolicy.enabled !== false : DEFAULT_BEACON_CONFIG.enabled,
    minimumConnections: Math.max(4, configuredNumber('connectionCount', 'gte', DEFAULT_BEACON_CONFIG.minimumConnections)),
    minimumInterval: Math.max(1, configuredNumber('averageInterval', 'gte', DEFAULT_BEACON_CONFIG.minimumIntervalSeconds)),
    maximumInterval: Math.max(1, configuredNumber('averageInterval', 'lte', DEFAULT_BEACON_CONFIG.maximumIntervalSeconds, Math.max)),
    minimumObservation: Math.max(0, configuredNumber('observationSeconds', 'gte', DEFAULT_BEACON_CONFIG.minimumObservationSeconds)),
    consistencyThreshold: Math.min(100, Math.max(0, configuredNumber('intervalConsistency', 'gte', DEFAULT_BEACON_CONFIG.consistencyThreshold))),
    alertThreshold: Math.min(100, Math.max(25, number(baselinePolicy?.actions?.riskScore, actionThresholds.length ? Math.min(...actionThresholds) : number(process.env.BEACON_ALERT_THRESHOLD, DEFAULT_BEACON_CONFIG.alertThreshold)))),
    cooldownSeconds: Math.max(60, cooldowns.length ? Math.min(...cooldowns) : number(process.env.BEACON_ALERT_COOLDOWN_SECONDS, DEFAULT_BEACON_CONFIG.cooldownSeconds)),
    enabledRules: enabledRuleSettings,
  };
}

function matchedBeaconRules(sample, metrics, enabledRules = []) {
  const destinationPort = number(sample.remote_port ?? sample.destinationPort ?? sample.dst_port);
  const protocol = String(sample.protocol || (destinationPort === 53 ? 'dns' : destinationPort === 443 ? 'https' : 'tcp')).toLowerCase();
  const processText = `${sample.process_name || sample.processName || ''} ${sample.executable || sample.executablePath || ''}`.toLowerCase();
  const matches = {
    'exact-periodic-callback': metrics.intervalConsistency >= 90 && metrics.jitterSeconds <= 5,
    'jittered-c2-beacon': metrics.intervalConsistency >= 65 && metrics.jitterSeconds <= 30,
    'low-and-slow-beacon': metrics.averageInterval >= 300 && metrics.observationSeconds >= 1800,
    'dns-periodic-beacon': protocol === 'dns' || destinationPort === 53,
    'http-https-beacon': ['http', 'https', 'tls'].includes(protocol) || [80, 443].includes(destinationPort),
    'suspicious-process-beacon': /powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|python|node|\/tmp\//.test(processText),
  };
  const evidence = {
    beaconing: true,
    connectionCount: metrics.count,
    averageInterval: metrics.averageInterval,
    jitterSeconds: metrics.jitterSeconds,
    intervalConsistency: metrics.intervalConsistency,
    observationSeconds: metrics.observationSeconds,
    destinationIp: sample.remote_ip || sample.destinationIp || sample.dst_ip || '',
    destinationPort,
    protocol,
    processName: sample.process_name || sample.processName || '',
  };
  const conditionMatches = condition => {
    const actual = evidence[condition.field];
    const expected = condition.value;
    switch (condition.operator) {
      case 'eq': return String(actual).toLowerCase() === String(expected).toLowerCase();
      case 'ne': return String(actual).toLowerCase() !== String(expected).toLowerCase();
      case 'gt': return number(actual) > number(expected);
      case 'gte': return number(actual) >= number(expected);
      case 'lt': return number(actual) < number(expected);
      case 'lte': return number(actual) <= number(expected);
      case 'in': return (Array.isArray(expected) ? expected : [expected]).map(value => String(value).toLowerCase()).includes(String(actual).toLowerCase());
      case 'not_in': return !(Array.isArray(expected) ? expected : [expected]).map(value => String(value).toLowerCase()).includes(String(actual).toLowerCase());
      case 'contains': {
        if (condition.field === 'processName' && expected === 'script-or-lolbin') {
          return /powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|python|node|\/tmp\//.test(String(actual || '').toLowerCase());
        }
        return String(actual || '').toLowerCase().includes(String(expected || '').toLowerCase());
      }
      default: return false;
    }
  };
  return enabledRules.filter(rule => (rule.conditions || []).length
    ? (rule.conditions || []).every(conditionMatches)
    : matches[rule.id]);
}

function beaconRows(raw = {}) {
  const detailed = Array.isArray(raw.connections) ? raw.connections : [];
  const fallback = Array.isArray(raw.external_peers) ? raw.external_peers : [];
  return (detailed.length ? detailed : fallback).filter(row => {
    const destination = row.remote_ip || row.destinationIp || row.dst_ip;
    return destination && !isPrivateIp(destination) && (row.pid || row.process_name || row.processName);
  });
}

function observeBeaconSnapshot(alert, rows, config) {
  const enabledRules = config.enabledRules || BEACON_BUILTIN_RULES;
  if (config.enabled === false || !enabledRules.length) return [];
  const observedAt = date(alert.createdAt).getTime();
  const groups = new Map();
  for (const row of rows) {
    const destinationIp = String(row.remote_ip || row.destinationIp || row.dst_ip || '').slice(0, 64);
    const destinationPort = number(row.remote_port ?? row.destinationPort ?? row.dst_port);
    const processIdentity = row.pid || row.process_name || row.processName;
    if (!destinationIp || !processIdentity || isPrivateIp(destinationIp)) continue;
    const protocol = String(row.protocol || (destinationPort === 53 ? 'dns' : destinationPort === 443 ? 'https' : 'tcp')).toLowerCase();
    const key = [alert.companyId, alert.systemId || alert.agentId || alert.hostname, processIdentity, destinationIp, destinationPort, protocol].join('|');
    const group = groups.get(key) || { key, rows: [], ports: new Set() };
    group.rows.push(row);
    group.ports.add(number(row.local_port ?? row.sourcePort));
    groups.set(key, group);
  }

  const candidates = [];
  for (const group of groups.values()) {
    const sample = group.rows[0];
    const existing = beaconStates.get(group.key) || {
      previousPorts: new Set(), timestamps: [], lastSnapshotAt: 0, lastSeenAt: 0,
    };
    if (existing.lastSnapshotAt === observedAt) continue;
    const newConnectionObserved = existing.lastSnapshotAt > 0
      && [...group.ports].some(port => port && !existing.previousPorts.has(port));
    if (newConnectionObserved) existing.timestamps.push(observedAt);
    existing.timestamps = existing.timestamps.filter(value => value >= observedAt - BEACON_HISTORY_MS).slice(-256);
    existing.previousPorts = group.ports;
    existing.lastSnapshotAt = observedAt;
    existing.lastSeenAt = Date.now();
    beaconStates.set(group.key, existing);

    const metrics = calculateBeaconMetrics(existing.timestamps);
    if (
      metrics.count < config.minimumConnections
      || metrics.averageInterval < config.minimumInterval
      || metrics.averageInterval > config.maximumInterval
      || metrics.observationSeconds < config.minimumObservation
      || metrics.intervalConsistency < config.consistencyThreshold
    ) continue;

    const matchedRules = matchedBeaconRules(sample, metrics, enabledRules);
    if (!matchedRules.length) continue;
    const processText = `${sample.process_name || sample.processName || ''} ${sample.executable || sample.executablePath || ''}`.toLowerCase();
    const processRisk = /powershell|pwsh|wscript|cscript|mshta|rundll32|python|node|\/tmp\//.test(processText) ? 15 : 0;
    const portRisk = COMMON_PORTS.has(number(sample.remote_port ?? sample.destinationPort ?? sample.dst_port)) ? 0 : 10;
    const volumeRisk = Math.min(10, Math.max(0, metrics.count - config.minimumConnections + 1) * 2);
    const lowAndSlowRisk = metrics.averageInterval >= 300 ? 5 : 0;
    const riskScore = Math.min(100, metrics.periodicityScore + processRisk + portRisk + volumeRisk + lowAndSlowRisk);
    candidates.push({ sample, metrics, riskScore, config, matchedRules, key: group.key, observedAt: new Date(observedAt) });
  }

  const now = Date.now();
  for (const [key, state] of beaconStates) {
    if (now - state.lastSeenAt > BEACON_STATE_TTL_MS) beaconStates.delete(key);
  }
  return candidates;
}

async function warmBeaconState(alert, config) {
  const warmupKey = `${alert.companyId}|${alert.systemId || alert.agentId || alert.hostname}`;
  if (beaconWarmups.has(warmupKey)) {
    await beaconWarmups.get(warmupKey);
    return [];
  }
  const task = (async () => {
    const Alert = require('../models/Alert.model');
    const since = new Date(date(alert.createdAt).getTime() - BEACON_HISTORY_MS);
    const history = await Alert.find({
      companyId: alert.companyId,
      ...(alert.systemId ? { systemId: alert.systemId } : { agentId: alert.agentId }),
      ruleId: 'NET_CONNECTION_SUMMARY',
      createdAt: { $gte: since, $lte: date(alert.createdAt) },
    }).select('companyId tenantId partnerId departmentId systemId endpointId agentId agentName hostname osType createdAt rawEvent').sort({ createdAt: 1 }).limit(720).lean();
    const candidatesByKey = new Map();
    for (const snapshot of history) {
      const rawEvent = snapshot.rawEvent || {};
      const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : rawEvent;
      for (const candidate of observeBeaconSnapshot(snapshot, beaconRows(raw), config)) {
        candidatesByKey.set(candidate.key, candidate);
      }
    }
    return [...candidatesByKey.values()];
  })().catch(error => {
    beaconWarmups.delete(warmupKey);
    throw error;
  });
  beaconWarmups.set(warmupKey, task);
  return task;
}

async function persistBeaconCandidates(alert, candidates, io = null) {
  if (!candidates.length) return [];
  const Alert = require('../models/Alert.model');
  const created = [];
  for (const candidate of candidates.slice(0, 25)) {
    const { sample, metrics, config, riskScore, matchedRules = [] } = candidate;
    const observedAt = date(candidate.observedAt || alert.createdAt);
    const destinationIp = String(sample.remote_ip || sample.destinationIp || sample.dst_ip || '').slice(0, 64);
    const destinationPort = number(sample.remote_port ?? sample.destinationPort ?? sample.dst_port);
    const protocol = String(sample.protocol || (destinationPort === 443 ? 'https' : 'tcp')).toLowerCase();
    const bucket = Math.floor(observedAt.getTime() / (config.cooldownSeconds * 1000));
    const fingerprint = crypto.createHash('sha256').update([
      'beacon-correlation', alert.companyId, alert.systemId || alert.agentId,
      sample.pid || sample.process_name || sample.processName, destinationIp, destinationPort, bucket,
    ].join('|')).digest('hex');
    const actionable = riskScore >= config.alertThreshold;
    const configuredSeverity = matchedRules
      .map(rule => String(rule.severity || '').toLowerCase())
      .sort((left, right) => ['low', 'medium', 'high', 'critical'].indexOf(right) - ['low', 'medium', 'high', 'critical'].indexOf(left))[0];
    const severity = actionable && configuredSeverity
      ? configuredSeverity
      : riskScore >= 85 ? 'critical' : riskScore >= 70 ? 'high' : riskScore >= 50 ? 'medium' : 'low';
    const result = await Alert.updateOne(
      { companyId: alert.companyId, eventFingerprint: fingerprint },
      { $setOnInsert: {
        tenantId: alert.tenantId || null,
        partnerId: alert.partnerId || null,
        companyId: alert.companyId,
        departmentId: alert.departmentId || null,
        systemId: alert.systemId || null,
        endpointId: alert.endpointId || String(alert.systemId || ''),
        eventId: `beacon-correlation-${fingerprint}`,
        eventFingerprint: fingerprint,
        agentId: alert.agentId,
        agentName: alert.agentName || alert.hostname,
        hostname: alert.hostname || alert.agentName,
        osType: alert.osType,
        capabilityId: 26,
        capabilityIds: [1, 3, 26],
        ruleId: 'BEACON_PERIODIC_CONNECTION',
        type: actionable ? 'BEACONING_ALERT' : 'BEACONING_OBSERVATION',
        eventCategory: 'network',
        subCategory: 'beaconing-detection',
        eventType: actionable ? 'Periodic Network Beacon' : 'Periodic Network Beacon Observation',
        source: 'beaconing',
        severity,
        status: actionable ? 'open' : 'under_observation',
        underObservation: !actionable,
        actionable,
        riskScore,
        confidenceScore: Math.round(metrics.intervalConsistency),
        description: `Repeated ${protocol.toUpperCase()} callbacks to ${destinationIp}:${destinationPort}: ${metrics.count} new connections, average interval ${metrics.averageInterval.toFixed(1)}s, jitter ${metrics.jitterSeconds.toFixed(1)}s`,
        srcip: sample.local_ip || sample.sourceIp,
        sourcePort: number(sample.local_port ?? sample.sourcePort),
        destip: destinationIp,
        destPort: destinationPort,
        protocol,
        processName: sample.process_name || sample.processName,
        processExe: sample.executable || sample.executablePath,
        processCmdline: sample.command_line || sample.commandLine,
        pid: number(sample.pid, undefined),
        parentPid: number(sample.parent_pid ?? sample.parentPid, undefined),
        parentProcessName: sample.parent_process || sample.parentProcessName,
        username: sample.username,
        processExecutableSha256: sample.process_hash || sample.processHash,
        processSignatureStatus: sample.signature_status || sample.signatureStatus,
        connectionCount: metrics.count,
        averageInterval: metrics.averageInterval,
        medianInterval: metrics.medianInterval,
        jitterSeconds: metrics.jitterSeconds,
        intervalConsistency: metrics.intervalConsistency,
        periodicityScore: metrics.periodicityScore,
        observationSeconds: metrics.observationSeconds,
        firstSeen: new Date(observedAt.getTime() - (metrics.observationSeconds * 1000)),
        lastSeen: observedAt,
        threatCategory: actionable ? 'Possible C2 Beaconing' : 'Periodic callback under observation',
        matchedPatterns: matchedRules.map(rule => rule.id),
        mitreId: 'T1071',
        mitreTechnique: 'Application Layer Protocol',
        recommendedAction: 'Validate the owning process and destination reputation before containment.',
        dataOrigin: 'agent',
        createdAt: observedAt,
        rawEvent: {
          correlationSource: 'NET_CONNECTION_SUMMARY',
          correlationMode: 'new-local-port-callbacks',
          sourceAlertId: alert._id,
          metrics,
          matchedRules: matchedRules.map(rule => ({ id: rule.id, name: rule.name, severity: rule.severity })),
          connection: sample,
        },
      } },
      { upsert: true, setDefaultsOnInsert: true },
    );
    if (!result.upsertedCount || !result.upsertedId) continue;
    const inserted = await Alert.findById(result.upsertedId);
    if (!inserted) continue;
    created.push(inserted);
    if (io) {
      io.to(`company:${inserted.companyId}`).emit('alert:new', inserted);
      io.to(`company:${inserted.companyId}`).emit('beaconing:event', inserted);
    }
    setImmediate(() => require('./automatedResponse.service').evaluatePlaybooksForAlert(inserted, io)
      .catch(error => console.error('[beaconing automated response]', error.message)));
  }
  return created;
}

function calculateNetworkRisk(connection = {}) {
  const reasons = [];
  let score = 0;
  const intel = connection.threatIntel || connection.threat_intel || {};
  const reputation = String(intel.verdict || intel.reputation || connection.reputation || '').toLowerCase();
  const threatScore = number(intel.score ?? intel.threatScore ?? connection.threat_score);
  const destinationPort = number(connection.destinationPort ?? connection.remote_port ?? connection.dst_port);
  const processText = `${connection.processName || connection.process_name || ''} ${connection.executablePath || connection.executable || ''}`.toLowerCase();

  if (['malicious', 'c2', 'botnet'].includes(reputation) || threatScore >= 70) {
    score += 55;
    reasons.push('Destination has high-confidence threat-intelligence evidence');
  } else if (reputation === 'suspicious' || threatScore >= 30) {
    score += 25;
    reasons.push('Destination has suspicious reputation evidence');
  }
  if (connection.beaconing || connection.periodic) {
    score += 25;
    reasons.push('Repeated communication has a consistent periodic interval');
  }
  if (connection.scanning) {
    score += 30;
    reasons.push('Connection fan-out crossed the configured scanning threshold');
  }
  if (connection.lateralMovement || connection.lateral_movement) {
    score += 30;
    reasons.push('Remote-service activity spans multiple internal hosts');
  }
  if (connection.transferAnomaly || connection.transfer_anomaly) {
    score += 25;
    reasons.push('Outbound volume exceeded the learned baseline');
  }
  if (destinationPort && !COMMON_PORTS.has(destinationPort)) {
    score += 5;
    reasons.push('Destination port is uncommon for this environment');
  }
  if (REMOTE_ADMIN_PORTS.has(destinationPort) && isPrivateIp(connection.destinationIp || connection.remote_ip)) {
    score += 10;
    reasons.push('Internal remote-administration service was contacted');
  }
  if (/powershell|pwsh|wscript|cscript|mshta|rundll32/.test(processText) && !isPrivateIp(connection.destinationIp || connection.remote_ip)) {
    score += 15;
    reasons.push('A script-capable process opened an external connection');
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return { riskScore: score, severity: severityForRisk(score), reasons };
}

function policyConditionMatches(connection, condition = {}) {
  const aliases = {
    destinationReputation: connection.destinationReputation
      || connection.threatIntel?.verdict
      || connection.threatIntel?.reputation
      || connection.reputation,
    newDestination: connection.newDestination ?? connection.rawMetadata?.newDestination,
    newCountry: connection.newCountry ?? connection.rawMetadata?.newCountry,
    beaconing: connection.beaconing ?? connection.periodic,
    scanning: connection.scanning,
    lateralMovement: connection.lateralMovement ?? connection.lateral_movement,
  };
  const actual = Object.prototype.hasOwnProperty.call(aliases, condition.field)
    ? aliases[condition.field]
    : connection[condition.field];
  const expected = condition.value;
  switch (condition.operator) {
    case 'eq': return String(actual) === String(expected);
    case 'ne': return String(actual) !== String(expected);
    case 'gt': return number(actual) > number(expected);
    case 'gte': return number(actual) >= number(expected);
    case 'lt': return number(actual) < number(expected);
    case 'lte': return number(actual) <= number(expected);
    case 'in': return (Array.isArray(expected) ? expected : [expected]).map(String).includes(String(actual));
    case 'not_in': return !(Array.isArray(expected) ? expected : [expected]).map(String).includes(String(actual));
    case 'contains': return String(actual || '').toLowerCase().includes(String(expected || '').toLowerCase());
    default: return false;
  }
}

function applyNetworkPolicies(connection, policies = []) {
  const severityFloor = { low: 0, medium: 21, elevated: 41, high: 61, critical: 81 };
  const matched = [];
  for (const policy of policies) {
    const scope = policy.scope || {};
    const endpointGroup = String(connection.endpointGroup || connection.rawMetadata?.endpointGroup || '');
    const serverGroup = String(connection.serverGroup || connection.rawMetadata?.serverGroup || '');
    if (scope.endpointGroups?.length
        && !scope.endpointGroups.map(String).includes(endpointGroup)) continue;
    if (scope.serverGroups?.length
        && !scope.serverGroups.map(String).includes(serverGroup)) continue;
    if (scope.assetIds?.length && !scope.assetIds.map(String).includes(String(connection.systemId || ''))) continue;
    if (scope.users?.length && !scope.users.map(String).includes(String(connection.username || ''))) continue;
    if (!(policy.conditions || []).every(condition => policyConditionMatches(connection, condition))) continue;
    matched.push(policy);
    connection.riskScore = Math.max(
      connection.riskScore || 0,
      number(policy.actions?.riskScore, 70),
      severityFloor[policy.actions?.severity] || 0,
    );
    connection.severity = severityForRisk(connection.riskScore);
    connection.detectionReasons = [...new Set([...(connection.detectionReasons || []), `Matched network policy: ${policy.name}`])];
  }
  return matched;
}

function connectionFingerprint(scope, row) {
  // A kernel socket id (or a hash containing PID/client port/start time) is
  // not a durable network identity. Browsers and workers continuously recycle
  // those values and used to create a fresh dashboard row for an unchanged
  // process -> service path. Keep the latest PID and observed source port in
  // the document, but key storage by the stable topology/process attributes.
  const state = String(row.state || '').toUpperCase();
  const direction = String(row.direction || '').toLowerCase();
  const listener = Boolean(row.listener) || state === 'LISTEN' || direction === 'inbound';
  const localPort = listener ? number(row.local_port ?? row.sourcePort) : 0;
  return crypto.createHash('sha256').update([
    scope.systemId || scope.agentId || scope.hostname,
    String(row.protocol || 'other').toLowerCase(),
    listener ? 'inbound' : (direction || 'outbound'),
    row.local_ip || row.sourceIp || '', localPort,
    row.remote_ip || row.destinationIp || '', row.remote_port ?? row.destinationPort ?? 0,
    row.process_name || row.processName || '',
    row.executable || row.executablePath || '',
    row.username || '',
  ].join('|')).digest('hex').slice(0, 32);
}

function inferAssetType(alert, row) {
  const explicit = row.asset_type || row.assetType || alert.rawEvent?.assetType;
  if (['endpoint', 'server', 'user-device', 'virtual-machine'].includes(explicit)) return explicit;
  const process = String(row.process_name || '').toLowerCase();
  const localPort = number(row.local_port);
  if (/nginx|apache|httpd|iis|mysql|postgres|mongod|redis|java/.test(process) || [80, 443, 1433, 3306, 5432, 6379, 8080, 27017].includes(localPort)) return 'server';
  return 'endpoint';
}

function normalizeConnection(alert, row, closed = false) {
  const observedAt = date(row.observed_at || row.observedAt || alert.createdAt);
  const startTime = date(row.start_time || row.startTime, observedAt);
  const endTime = closed || String(row.state || '').toUpperCase() === 'CLOSED'
    ? date(row.end_time || row.endTime, observedAt)
    : null;
  const destinationIp = String(row.remote_ip || row.destinationIp || row.dst_ip || '').slice(0, 64);
  const sourceIp = String(row.local_ip || row.sourceIp || row.src_ip || '').slice(0, 64);
  const protocolRaw = String(row.protocol || 'other').toLowerCase();
  const protocol = ['tcp', 'udp', 'icmp'].includes(protocolRaw) ? protocolRaw : 'other';
  const listener = Boolean(row.listener) || String(row.state || '').toUpperCase() === 'LISTEN';
  const direction = listener ? 'inbound' : isPrivateIp(destinationIp) ? 'internal' : destinationIp ? 'outbound' : 'unknown';
  const risk = calculateNetworkRisk({ ...row, destinationIp });
  const bytesReported = ['bytes_sent', 'bytesSent', 'bytes_received', 'bytesReceived']
    .some(field => Object.prototype.hasOwnProperty.call(row, field) && row[field] !== null && row[field] !== undefined);
  const retentionDays = Math.max(1, Math.min(3650, number(process.env.NETWORK_RETENTION_DAYS, process.env.LOG_RETENTION_DAYS || 30)));
  const agentId = String(alert.agentId || alert.endpointId || alert.systemId || alert.hostname || 'unknown').slice(0, 128);
  const scope = { systemId: alert.systemId, agentId, hostname: alert.hostname || alert.agentName || 'unknown' };

  return {
    tenantId: alert.tenantId || null,
    partnerId: alert.partnerId || null,
    companyId: alert.companyId,
    departmentId: alert.departmentId || null,
    systemId: alert.systemId || null,
    endpointId: String(alert.endpointId || alert.systemId || '').slice(0, 128),
    agentId,
    connectionId: connectionFingerprint(scope, row),
    eventId: String(alert.eventId || '').slice(0, 128),
    hostname: String(alert.hostname || alert.agentName || 'unknown').slice(0, 253),
    assetType: inferAssetType(alert, row),
    osType: String(alert.osType || row.os_type || row.platform || 'unknown').slice(0, 64),
    username: String(row.username || '').slice(0, 512),
    userId: String(row.user_sid || row.user_uid || '').slice(0, 256),
    loginSession: String(row.login_session || '').slice(0, 256),
    processName: String(row.process_name || row.processName || '').slice(0, 512),
    pid: number(row.pid, null),
    parentPid: number(row.parent_pid ?? row.parentPid, null),
    parentProcessName: String(row.parent_process || row.parentProcessName || '').slice(0, 512),
    executablePath: String(row.executable || row.executablePath || '').slice(0, 4096),
    commandLine: String(row.command_line || row.commandLine || '').slice(0, 8192),
    processHash: String(row.process_hash || row.processHash || '').slice(0, 128),
    signatureStatus: String(row.signature_status || row.signatureStatus || 'unknown').slice(0, 128),
    processStartTime: row.process_start_time ? date(row.process_start_time) : null,
    sourceIp,
    sourcePort: number(row.local_port || row.observed_local_port || row.sourcePort),
    destinationIp,
    destinationPort: number(row.remote_port ?? row.destinationPort),
    protocol,
    state: String(closed ? 'CLOSED' : (listener ? 'LISTEN' : (row.state || 'UNKNOWN'))).toUpperCase().slice(0, 64),
    direction,
    ipVersion: number(row.ip_version || (net.isIP(destinationIp) || net.isIP(sourceIp) || 4), 4),
    interfaceName: String(row.interface || row.interfaceName || '').slice(0, 256),
    networkAdapter: String(row.network_adapter || row.networkAdapter || row.interface || '').slice(0, 256),
    bytesSent: Math.max(0, number(row.bytes_sent ?? row.bytesSent)),
    bytesReceived: Math.max(0, number(row.bytes_received ?? row.bytesReceived)),
    domain: String(row.domain || '').slice(0, 1024),
    dnsQueryType: String(row.query_type || row.queryType || '').slice(0, 32),
    startTime,
    endTime,
    observedAt,
    durationSeconds: Math.max(0, number(row.duration ?? row.durationSeconds)),
    firstSeen: startTime,
    lastSeen: observedAt,
    geo: row.geo || {},
    threatIntel: row.threat_intel || row.threatIntel || {},
    newDestination: Boolean(row.new_destination ?? row.newDestination),
    newCountry: Boolean(row.new_country ?? row.newCountry),
    beaconing: Boolean(row.beaconing || row.periodic),
    scanning: Boolean(row.scanning),
    lateralMovement: Boolean(row.lateral_movement ?? row.lateralMovement),
    transferAnomaly: Boolean(row.transfer_anomaly ?? row.transferAnomaly),
    riskScore: risk.riskScore,
    severity: risk.severity,
    detectionReasons: risk.reasons,
    mitre: Array.isArray(row.mitre) ? row.mitre.slice(0, 20) : [],
    rawMetadata: {
      attributionConfidence: row.attribution_confidence || '',
      bytesScope: row.bytes_scope || (bytesReported ? 'connection' : 'not_available'),
      endpointGroup: row.endpoint_group || row.endpointGroup || '',
      serverGroup: row.server_group || row.serverGroup || '',
    },
    expiresAt: new Date(observedAt.getTime() + retentionDays * 86400000),
  };
}

async function ingestNetworkTelemetry(alert, io = null) {
  if (!alert || !alert.companyId || alert.ruleId !== 'NET_CONNECTION_SUMMARY') return { upserted: 0 };
  const rawEvent = alert.rawEvent || {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : rawEvent;
  const peerMetadata = new Map((Array.isArray(raw.external_peers) ? raw.external_peers : []).map(peer => [
    [peer.local_ip || '', peer.remote_ip || '', peer.remote_port || 0].join('|'),
    peer,
  ]));
  const domainsByAddress = new Map();
  for (const [domain, addresses] of Object.entries(raw.dns_answer_map || {})) {
    for (const address of Array.isArray(addresses) ? addresses : []) {
      if (address && !domainsByAddress.has(String(address))) domainsByAddress.set(String(address), String(domain));
    }
  }
  const detailedActive = Array.isArray(raw.connections) ? raw.connections.slice(0, 1000).map(row => {
    const peer = peerMetadata.get([row.local_ip || '', row.remote_ip || '', row.remote_port || 0].join('|')) || {};
    const geo = peer.geo || {
      city: peer.city || '',
      country: peer.country || '',
      countryCode: peer.countryCode || '',
      isp: peer.isp || '',
    };
    return {
      ...row,
      domain: row.domain || peer.domain || peer.host || domainsByAddress.get(String(row.remote_ip || '')) || '',
      geo: Object.values(geo).some(Boolean) ? geo : (row.geo || {}),
      threat_intel: row.threat_intel || peer.threat_intel || peer.threatIntel || {},
    };
  }) : [];
  // Older deployed agents send privacy-safe external peer metadata without
  // the full connection array. It still contains the socket tuple required
  // for server-side timing correlation and keeps capability 26 operational
  // without forcing an agent version change.
  const active = detailedActive.length
    ? detailedActive
    : (Array.isArray(raw.external_peers) ? raw.external_peers.slice(0, 1000) : []);
  const listeners = Array.isArray(raw.listeners) ? raw.listeners.slice(0, 500) : [];
  const closed = Array.isArray(raw.closed_connections) ? raw.closed_connections.slice(0, 500) : [];
  const documents = [
    ...active.map(row => normalizeConnection(alert, row, false)),
    ...listeners.map(row => normalizeConnection(alert, { ...row, listener: true, state: 'LISTEN' }, false)),
    ...closed.map(row => normalizeConnection(alert, row, true)),
  ].filter(row => row.sourceIp && (row.destinationIp || row.state === 'LISTEN'));
  const allPolicies = await NetworkPolicy.find({ companyId: alert.companyId }).lean();
  const policies = allPolicies.filter(policy => policy.enabled !== false);
  const beaconPolicies = allPolicies.filter(policy => (policy.conditions || []).some(condition => condition.field === 'beaconing'));
  const beaconConfig = beaconConfigFor(alert, beaconPolicies);
  const warmedCandidates = await warmBeaconState(alert, beaconConfig);
  const liveCandidates = observeBeaconSnapshot(alert, beaconRows(raw), beaconConfig);
  const beaconCandidates = liveCandidates.length ? liveCandidates : warmedCandidates;
  const createdBeacons = await persistBeaconCandidates(alert, beaconCandidates, io);
  if (!documents.length) return { upserted: 0, beaconEvents: createdBeacons.length };

  const matches = [];
  for (const document of documents) {
    for (const policy of applyNetworkPolicies(document, policies)) {
      if (policy.actions?.createAlert !== false) matches.push({ document, policy });
    }
  }

  await NetworkConnection.bulkWrite(documents.map(document => {
    const { firstSeen, startTime, ...mutable } = document;
    return {
      updateOne: {
        filter: { companyId: document.companyId, connectionId: document.connectionId },
        update: { $set: mutable, $min: { startTime }, $setOnInsert: { firstSeen } },
        upsert: true,
      },
    };
  }), { ordered: false });

  if (matches.length) {
    const Alert = require('../models/Alert.model');
    const created = [];
    for (const { document, policy } of matches.slice(0, 100)) {
      const suppressionSeconds = Math.max(60, number(policy.suppressionSeconds, 900));
      const bucket = Math.floor(document.observedAt.getTime() / (suppressionSeconds * 1000));
      const fingerprint = crypto.createHash('sha256')
        .update(`${document.companyId}|${policy._id}|${document.hostname}|${document.destinationIp}|${bucket}`)
        .digest('hex');
      const result = await Alert.updateOne(
        { companyId: document.companyId, eventFingerprint: fingerprint },
        { $setOnInsert: {
          tenantId: document.tenantId, partnerId: document.partnerId,
          companyId: document.companyId, departmentId: document.departmentId,
          systemId: document.systemId, endpointId: document.endpointId,
          eventId: `network-policy-${fingerprint}`, eventFingerprint: fingerprint,
          agentId: document.agentId, agentName: document.hostname, hostname: document.hostname,
          osType: document.osType, ruleId: `NETWORK_POLICY_${String(policy._id).slice(-8)}`,
          description: `Network policy "${policy.name}" matched: ${document.detectionReasons.join('; ')}`,
          source: 'network-policy', type: 'NETWORK_POLICY_MATCH', eventCategory: 'network',
          subCategory: 'policy', severity: document.severity === 'elevated' ? 'high' : document.severity,
          riskScore: document.riskScore, srcip: document.sourceIp, sourcePort: document.sourcePort,
          destip: document.destinationIp, destPort: document.destinationPort, protocol: document.protocol,
          processName: document.processName, pid: document.pid, username: document.username,
          mitreId: document.mitre[0], recommendedAction: 'Review policy evidence and confirm before any blocking action.',
          dataOrigin: 'agent', actionable: true, createdAt: document.observedAt,
          rawEvent: { networkConnectionId: document.connectionId, policyId: policy._id, evidence: document.detectionReasons },
        } },
        { upsert: true, setDefaultsOnInsert: true },
      );
      if (result.upsertedCount && result.upsertedId) {
        const inserted = await Alert.findById(result.upsertedId);
        if (inserted) created.push(inserted);
      }
    }
    if (io) created.forEach(item => io.to(`company:${item.companyId}`).emit('alert:new', item));
  }

  if (io) {
    io.to(`company:${alert.companyId}`).emit('network:event', {
      companyId: alert.companyId,
      count: documents.length,
      observedAt: new Date(),
    });
  }
  return { upserted: documents.length, beaconEvents: createdBeacons.length };
}

module.exports = {
  BEACON_BASE_NAME,
  BEACON_BUILTIN_RULES,
  BEACON_CUSTOM_PREFIX,
  BEACON_POLICY_PREFIX,
  DEFAULT_BEACON_CONFIG,
  calculateNetworkRisk,
  applyNetworkPolicies,
  beaconConfigFor,
  calculateBeaconMetrics,
  ingestNetworkTelemetry,
  isPrivateIp,
  normalizeConnection,
  observeBeaconSnapshot,
  severityForRisk,
};
