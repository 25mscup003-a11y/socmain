const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const previousFeedSetting = process.env.THREAT_INTEL_PUBLIC_FEEDS_ENABLED;
process.env.THREAT_INTEL_PUBLIC_FEEDS_ENABLED = 'false';
const {
  parsePublicFeed, fetchPublicFeed, loadPublicFeeds, normalizeThreatLabels, verifyPublicFeeds, publicFeedVerification,
} = require('../src/services/threat-intel.service');
const Alert = require('../src/models/Alert.model');
if (previousFeedSetting === undefined) delete process.env.THREAT_INTEL_PUBLIC_FEEDS_ENABLED;
else process.env.THREAT_INTEL_PUBLIC_FEEDS_ENABLED = previousFeedSetting;

test('public feed parser keeps valid unique IPs only', () => {
  const parsed = parsePublicFeed('# comment\n1.1.1.1\ninvalid\n1.1.1.1\n2001:4860:4860::8888\n');
  assert.deepEqual([...parsed], ['1.1.1.1', '2001:4860:4860::8888']);
});

test('public feed retries a transient timeout and then succeeds', async () => {
  let calls = 0;
  const client = {
    get: async () => {
      calls += 1;
      if (calls === 1) throw new Error('timeout');
      return { data: '8.8.8.8\n' };
    },
  };
  const result = await fetchPublicFeed(
    { name: 'test-feed', url: 'https://example.invalid/feed' },
    { client, retries: 2, retryDelayMs: 0, waitFn: async () => {} },
  );
  assert.equal(calls, 2);
  assert.equal(result.attempts, 2);
  assert.deepEqual([...result.ips], ['8.8.8.8']);
});

test('public feed bypasses a broken system resolver with explicit DNS fallback', async () => {
  let calls = 0;
  const client = {
    get: async (_url, config) => {
      calls += 1;
      if (calls === 1) {
        throw Object.assign(new Error('temporary DNS failure'), { code: 'EAI_AGAIN' });
      }
      assert.ok(config.httpAgent, 'fallback request must have a custom HTTP DNS lookup');
      assert.ok(config.httpsAgent, 'fallback request must have a custom HTTPS DNS lookup');
      return { data: '9.9.9.9\n' };
    },
  };

  const result = await fetchPublicFeed(
    { name: 'test-feed', url: 'https://example.invalid/feed' },
    { client, retries: 0, waitFn: async () => {} },
  );

  assert.equal(calls, 2);
  assert.deepEqual([...result.ips], ['9.9.9.9']);
});

test('public feed retries are bounded and identify the failed feed', async () => {
  let calls = 0;
  const client = { get: async () => { calls += 1; throw new Error('offline'); } };
  await assert.rejects(
    fetchPublicFeed(
      { name: 'test-feed', url: 'https://example.invalid/feed' },
      { client, retries: 2, retryDelayMs: 0, waitFn: async () => {} },
    ),
    /test-feed: offline/,
  );
  assert.equal(calls, 3);
});

test('system-wide DNS failures are reported once instead of once per feed', async () => {
  const error = Object.assign(new Error('temporary DNS failure'), { code: 'EAI_AGAIN' });
  const client = { get: async () => { throw error; } };
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = message => warnings.push(message);
  try {
    await loadPublicFeeds({ client, schedule: false, waitFn: async () => {} });
  } finally {
    console.warn = originalWarn;
  }
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /system DNS lookup failed/);
  assert.match(warnings[0], /feodo, emergingThreats, tor/);
});

test('verification waits for all startup feeds and reports individual readiness', async () => {
  const pending = [];
  const client = { get: async () => new Promise(resolve => pending.push(resolve)) };
  const loading = loadPublicFeeds({ client, schedule: false });
  let finished = false;
  const checking = verifyPublicFeeds('45.77.1.23').then(result => { finished = true; return result; });
  await Promise.resolve();
  assert.equal(pending.length, 3);
  pending[0]({ data: '45.77.1.23\n' });
  pending[1]({ data: '45.77.1.24\n' });
  await Promise.resolve();
  assert.equal(finished, false);
  pending[2]({ data: '45.77.1.25\n' });
  await loading;
  const checks = await checking;
  assert.ok(checks.every(check => check.status === 'checked'));
  assert.equal(checks.find(check => check.provider === 'feodo').matched, true);
  assert.ok(checks.every(check => check.checkedAt && check.expiresAt));
});

test('failed refresh retains lookup data but cannot pass mandatory verification', async () => {
  await loadPublicFeeds({ client: { get: async () => { throw new Error('offline'); } }, schedule: false, waitFn: async () => {} });
  const checks = publicFeedVerification('45.77.1.23');
  assert.ok(checks.every(check => check.status === 'unavailable'));
  assert.equal(checks.find(check => check.provider === 'feodo').matched, true);
});

test('OTX object malware families are normalized to stable strings', () => {
  const labels = normalizeThreatLabels([
    { id: 'fallback-id', display_name: 'StealthWorker / GoBrut', target: '/malware/test' },
    { id: 'MD5 Hash: f8add7e7161460ea2b1970cf4ca535bf', target: null },
    'plain-family',
  ]);
  assert.deepEqual(labels, [
    'StealthWorker / GoBrut',
    'MD5 Hash: f8add7e7161460ea2b1970cf4ca535bf',
    'plain-family',
  ]);
});

test('OTX stringified object arrays never reach Mongoose as one invalid value', () => {
  const value = "[{ id: 'one', display_name: 'Family One' }, { id: 'two', display_name: 'Family Two' }]";
  assert.deepEqual(normalizeThreatLabels(value), ['Family One', 'Family Two']);
});

test('Alert schema defensively casts raw OTX family objects to string labels', () => {
  const alert = new Alert({
    companyId: new mongoose.Types.ObjectId(),
    tiFeeds: {
      malwareFamilies: [
        { id: 'fallback', display_name: 'Family From Schema' },
        { id: 'Family ID Only' },
      ],
    },
  });
  assert.deepEqual(alert.tiFeeds.malwareFamilies, ['Family From Schema', 'Family ID Only']);
  assert.equal(alert.$errors?.['tiFeeds.malwareFamilies.0'], undefined);
});
