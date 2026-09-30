const test = require('node:test');
const assert = require('node:assert/strict');
const kernelMonitoring = require('../src/routes/kernel-monitoring.routes');

const { canonicalKernelEvent, evidenceFilter, summarize, reconstructCurrentInventory } = kernelMonitoring._private;
const {
  isRoutineKernelTelemetry,
  isRoutineNetworkTelemetry,
  isRoutineEndpointTelemetry,
  isRoutineSecurityTelemetry,
} = require('../src/utils/routineTelemetry');

test('normalizes native kernel inventory fields without invented values', () => {
  const row = canonicalKernelEvent({
    _id: '507f1f77bcf86cd799439011', ruleId: 'KERNEL_DRIVER_LOADED',
    rawEvent: { driver_name: 'example', driver_path: '/lib/modules/example.ko', sha256: 'a'.repeat(64), signature_status: 'unsigned' },
  });
  assert.equal(row.driverName, 'example');
  assert.equal(row.driverPath, '/lib/modules/example.ko');
  assert.equal(row.signatureStatus, 'unsigned');
});

test('kernel evidence query remains capability-index bounded', () => {
  assert.deepEqual(evidenceFilter(), { $or: [{ capabilityId: 19 }, { capabilityIds: 19 }] });
});

test('summarizes kernel signals from supplied telemetry only', () => {
  const result = summarize([
    { severity: 'critical', ruleId: 'KERNEL_ROOTKIT_DETECTED', description: 'Hidden module detected' },
    { severity: 'high', ruleId: 'KERNEL_SYSCALL_HOOK', description: 'sys_call_table hook' },
  ], [{ driverName: 'good', signatureStatus: 'valid' }, { driverName: 'bad', signatureStatus: 'unsigned', vulnerableDriver: true }], [{ status: 'active' }]);
  assert.equal(result.rootkitAlerts, 1);
  assert.equal(result.syscallHooks, 1);
  assert.equal(result.unsignedDrivers, 1);
  assert.equal(result.vulnerableDrivers, 1);
});

test('reconstructs every batch of a large kernel inventory by snapshot ID', () => {
  const makeBatch = (batch, size, milliseconds) => ({
    agentId: 'agent-one', ruleId: 'KERNEL_INVENTORY_SNAPSHOT',
    createdAt: new Date(1_800_000_000_000 + milliseconds),
    inventorySnapshotId: 'snapshot-205', inventoryBatchIndex: batch, inventoryBatchCount: 3,
    inventoryItems: Array.from({ length: size }, (_, index) => ({
      id: `module-${batch}-${index}`, name: `module-${batch}-${index}`,
    })),
  });
  const inventory = reconstructCurrentInventory([
    makeBatch(3, 5, 30), makeBatch(2, 100, 20), makeBatch(1, 100, 10),
  ]);
  assert.equal(inventory.modules.length, 205);
  assert.deepEqual(new Set(inventory.modules.map(item => item.inventorySnapshotId)), new Set(['snapshot-205']));
});

test('kernel inventory is dashboard telemetry and never actionable automation input', () => {
  const inventory = { capabilityId: 19, ruleId: 'KERNEL_INVENTORY_SNAPSHOT', severity: 'low' };
  assert.equal(isRoutineKernelTelemetry(inventory), true);
  assert.equal(isRoutineSecurityTelemetry(inventory), true);
  assert.equal(isRoutineKernelTelemetry({ capabilityId: 19, ruleId: 'KERNEL_BYOVD_DETECTED', severity: 'critical' }), false);
});

test('network state summaries persist without triggering correlation or SOAR', () => {
  for (const ruleId of [
    'NET_CONNECTION_SUMMARY', 'NET_DNS_SUMMARY',
    'NET_EXPOSURE_SUMMARY', 'NET_THREAT_INTEL_SUMMARY',
  ]) {
    const snapshot = { capabilityId: 3, ruleId, severity: 'medium', blocked: false };
    assert.equal(isRoutineNetworkTelemetry(snapshot), true, ruleId);
    assert.equal(isRoutineSecurityTelemetry(snapshot), true, ruleId);
  }
  assert.equal(isRoutineNetworkTelemetry({ ruleId: 'NET_SCAN_BEHAVIOR', severity: 'high' }), false);
  assert.equal(isRoutineNetworkTelemetry({ ruleId: 'NET_THREAT_INTEL_SUMMARY', severity: 'high' }), false);
  assert.equal(isRoutineNetworkTelemetry({ ruleId: 'NET_EXPOSURE_SUMMARY', severity: 'medium', blocked: true }), false);
});

test('high-volume endpoint inventory remains visible without blocking broker ingestion', () => {
  for (const ruleId of [
    'PROC_STARTED', 'PROC_TERMINATED', 'PROC_INVENTORY_SUMMARY',
    'PROC_WORKLOAD_ACTIVITY_SUMMARY', 'PROC_DNS_ATTRIBUTED',
    'MEM_PROCESS_METRIC', 'MEM_HOST_METRIC', 'MEM_TOP_CONSUMER',
  ]) {
    assert.equal(isRoutineEndpointTelemetry({ ruleId, severity: 'low' }), true, ruleId);
  }
  assert.equal(isRoutineEndpointTelemetry({ ruleId: 'PROC_STARTED', severity: 'high' }), false);
  assert.equal(isRoutineEndpointTelemetry({ ruleId: 'PROC_STARTED', severity: 'low', actionable: true }), false);
});
