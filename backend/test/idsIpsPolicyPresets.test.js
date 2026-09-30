const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { POLICY_PRESETS, effectivePresetMode } = require('../src/constants/idsIpsPolicyPresets');

test('policy preset catalog is unique and limited to supported sensors', () => {
  const required = [
    'suricata-scan', 'suricata-brute-force', 'suricata-sqli', 'suricata-xss',
    'suricata-command-injection', 'suricata-exploit', 'suricata-malware',
    'zeek-c2', 'suricata-exploit-kit', 'zeek-dns-tunnel',
    'suricata-http-attacks', 'suricata-smb-exploit', 'suricata-ftp-attack',
    'suricata-ssh-brute-force', 'suricata-rdp-brute-force', 'suricata-dos',
    'suricata-ddos', 'zeek-arp-spoofing', 'zeek-beaconing',
    'zeek-data-exfiltration', 'zeek-tls',
  ];
  assert.deepEqual(required.filter(id => !POLICY_PRESETS.some(item => item.id === id)), []);
  assert.equal(new Set(POLICY_PRESETS.map(item => item.id)).size, POLICY_PRESETS.length);
  for (const preset of POLICY_PRESETS) {
    assert.match(preset.id, /^(suricata|zeek|windivert)-[a-z0-9-]+$/);
    assert.ok(['suricata', 'zeek'].includes(preset.sensor));
    assert.ok(['detect', 'block'].includes(preset.defaultMode));
    assert.ok(['low', 'medium', 'high', 'critical'].includes(preset.minimumSeverity));
    assert.ok(preset.name && preset.attackPattern && preset.description);
    assert.ok(publicPlatformSupport(preset).some(platform => ['linux', 'windows', 'macos'].includes(platform)));
  }
});

function publicPlatformSupport(preset) {
  const { publicPreset } = require('../src/constants/idsIpsPolicyPresets');
  return publicPreset(preset).supportedPlatforms;
}

test('Windows exposes only Suricata-compatible policy presets', () => {
  const { publicPreset } = require('../src/constants/idsIpsPolicyPresets');
  const windows = POLICY_PRESETS.map(publicPreset)
    .filter(item => item.supportedPlatforms.includes('windows'));
  assert.ok(windows.length > 0);
  assert.ok(windows.every(item => item.sensor === 'suricata'));
  assert.ok(windows.some(item => item.enforcement === 'windivert'));
  assert.ok(windows.filter(item => item.enforcement === 'windivert')
    .every(item => item.supportedPlatforms.length === 1 && item.supportedPlatforms[0] === 'windows'));
});

test('macOS exposes passive Suricata policies but never WinDivert or Zeek policies', () => {
  const { publicPreset } = require('../src/constants/idsIpsPolicyPresets');
  const macos = POLICY_PRESETS.map(publicPreset)
    .filter(item => item.supportedPlatforms.includes('macos'));
  assert.ok(macos.length > 0);
  assert.ok(macos.every(item => item.sensor === 'suricata'));
  assert.ok(macos.every(item => item.enforcement !== 'windivert'));
});

test('Zeek policies remain detect-only even when a block mode is requested', () => {
  const zeekPreset = POLICY_PRESETS.find(item => item.id === 'zeek-c2');
  const suricataPreset = POLICY_PRESETS.find(item => item.id === 'suricata-sqli');

  assert.equal(zeekPreset.defaultMode, 'detect');
  assert.equal(effectivePresetMode(zeekPreset, 'block'), 'detect');
  assert.equal(effectivePresetMode(suricataPreset, 'block'), 'block');
});

test('Android policies use server evaluation and durable agent enforcement', () => {
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/ids.routes.js'), 'utf8');
  const agentRoutes = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  assert.match(routes, /targetPlatform === 'android' \? 'server_enforced' : 'pending'/);
  assert.match(routes, /systemPlatform === 'android'/);
  assert.match(agentRoutes, /ips_whitelist:/);
});
