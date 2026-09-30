'use strict';

function hasCapability(alert = {}, capabilityId) {
  return Number(alert.capabilityId) === capabilityId
    || (Array.isArray(alert.capabilityIds) && alert.capabilityIds.map(Number).includes(capabilityId));
}

function isRoutineApiTelemetry(alert = {}) {
  if (!hasCapability(alert, 20)) return false;
  const ruleId = String(alert.ruleId || alert.rule_id || alert.type || '').toUpperCase();
  if (['API_CALL_TELEMETRY', 'WAF_AGENT_STATUS'].includes(ruleId)) return true;
  const severity = String(alert.severity || 'low').toLowerCase();
  const evidence = `${alert.attackType || alert.attack_type || ''} ${alert.description || ''} ${alert.matchedSignature || alert.matched_signature || ''}`.toLowerCase();
  return alert.blocked !== true
    && !['high', 'critical'].includes(severity)
    && !/sql injection|sqli|xss|command injection|rce|xxe|ssrf|path traversal|file inclusion|credential stuffing|brute force|api abuse|malicious/.test(evidence);
}

function isRoutineKernelTelemetry(alert = {}) {
  if (!hasCapability(alert, 19)) return false;
  const ruleId = String(alert.ruleId || alert.rule_id || alert.type || '').toUpperCase();
  return ruleId === 'KERNEL_INVENTORY_SNAPSHOT';
}

const ROUTINE_NETWORK_RULES = new Set([
  'NET_CONNECTION_SUMMARY',
  'NET_DNS_SUMMARY',
  'NET_EXPOSURE_SUMMARY',
  'NET_THREAT_INTEL_SUMMARY',
]);

const ROUTINE_ENDPOINT_RULES = new Set([
  'PROC_STARTED',
  'PROC_TERMINATED',
  'PROC_INVENTORY_SUMMARY',
  'PROC_WORKLOAD_ACTIVITY_SUMMARY',
  'PROC_DNS_ATTRIBUTED',
  'MEM_PROCESS_METRIC',
  'MEM_HOST_METRIC',
  'MEM_TOP_CONSUMER',
]);

function isRoutineNetworkTelemetry(alert = {}) {
  const ruleId = String(alert.ruleId || alert.rule_id || alert.type || '').toUpperCase();
  if (!ROUTINE_NETWORK_RULES.has(ruleId)) return false;
  // These records remain persisted and visible as network state. They only
  // bypass expensive alert correlation/SOAR fan-out. A blocked or escalated
  // detection must always retain the full security workflow.
  const severity = String(alert.severity || 'low').toLowerCase();
  return alert.blocked !== true && !['high', 'critical'].includes(severity);
}

function isRoutineEndpointTelemetry(alert = {}) {
  const ruleId = String(alert.ruleId || alert.rule_id || alert.type || '').toUpperCase();
  if (!ROUTINE_ENDPOINT_RULES.has(ruleId)) return false;
  const severity = String(alert.severity || 'low').toLowerCase();
  return alert.actionable !== true
    && alert.blocked !== true
    && alert.quarantined !== true
    && !['high', 'critical'].includes(severity);
}

function isRoutineSecurityTelemetry(alert = {}) {
  return isRoutineApiTelemetry(alert)
    || isRoutineKernelTelemetry(alert)
    || isRoutineNetworkTelemetry(alert)
    || isRoutineEndpointTelemetry(alert);
}

module.exports = {
  hasCapability,
  isRoutineApiTelemetry,
  isRoutineKernelTelemetry,
  isRoutineNetworkTelemetry,
  isRoutineEndpointTelemetry,
  isRoutineSecurityTelemetry,
};
