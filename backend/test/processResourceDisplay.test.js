const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Exercise the actual UI's pure metric readers without requiring a DOM.
const source = fs.readFileSync(path.join(__dirname, '../../company/src/pages/edrdashbordpage/Process Activity Monitoring.jsx'), 'utf8');
const helpers = source.slice(source.indexOf('function resourceMetric('), source.indexOf('function ProcessResources('));
const { cpuValue, ramValue, ramPercentValue, formatCpuRam } = vm.runInNewContext(`${helpers}\n({ cpuValue, ramValue, ramPercentValue, formatCpuRam })`);

test('reported zero CPU and RAM remain visible', () => {
  assert.equal(formatCpuRam({ processCpuPercent: 0, processMemoryMb: 89.5 }), '0% / 89.5 MB');
  assert.equal(formatCpuRam({ processCpuPercent: 0, processMemoryMb: 0, rawEvent: { cpu_percent: 20, memory_mb: 50 } }), '0% / 0 MB');
});

test('outer raw metrics remain readable when a nested raw payload is present', () => {
  assert.equal(formatCpuRam({ rawEvent: { cpu_percent: 2.75, memory_mb: 48.25, raw: { event_type: 'process' } } }), '2.75% / 48.25 MB');
  assert.equal(formatCpuRam({ rawEvent: { raw: { process_cpu_percent: 0.04, process_memory_mb: 12.75 } } }), '0.04% / 12.75 MB');
});

test('process RSS bytes convert to MB while percentages retain their units', () => {
  assert.equal(ramValue({ processRssBytes: 64 * 1024 * 1024 }), 64);
  assert.equal(formatCpuRam({ process: { cpu_percent: 1.25, memory_info: { rss: 32 * 1024 * 1024 } } }), '1.25% / 32 MB');
  assert.equal(ramPercentValue({ rawEvent: { raw: { memory_percent: 0.28 } } }), 0.28);
  assert.equal(formatCpuRam({ cpu_percent: 0.05, memory_percent: 0.28 }), '0.05% / 0.28%');
});

test('missing and invalid measurements never become fabricated zero usage', () => {
  assert.equal(formatCpuRam({ ruleId: 'PROC_DNS_ATTRIBUTED' }), 'Not reported / Not reported');
  assert.equal(cpuValue({ processCpuPercent: false }), null);
  assert.equal(cpuValue({ processCpuPercent: ' ', rawEvent: { cpu_percent: 'n/a' } }), null);
  assert.equal(cpuValue({ processCpuPercent: -1, rawEvent: { cpu_percent: 5 } }), 5);
  assert.equal(ramValue({ processMemoryMb: 'invalid', rawEvent: { memory_mb: 22.5 } }), 22.5);
});
