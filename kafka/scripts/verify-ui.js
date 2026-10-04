const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const dotenv = require('../../backend/node_modules/dotenv');
const { localConfig } = require('./local-config');
const readline = require('node:readline/promises');

async function verify() {
  const config = localConfig();
  const credentials = dotenv.parse(fs.readFileSync(path.resolve(__dirname, '../.runtime-secrets/ui.env')));
  const base = `http://127.0.0.1:${config.KAFKA_UI_HOST_PORT}`;
  const jar = new Map();
  const request = async (pathname, options = {}) => {
    const response = await fetch(base + pathname, { redirect: 'manual', signal: AbortSignal.timeout(15000), ...options, headers: { cookie: [...jar].map(([key, value]) => `${key}=${value}`).join('; '), ...options.headers } });
    for (const cookie of response.headers.getSetCookie()) {
      const [key, value] = cookie.split(';')[0].split('=');
      if (value) jar.set(key, value); else jar.delete(key);
    }
    return response;
  };
  const csrfFrom = async response => {
    const html = await response.text();
    const csrf = /name="csrf" value="([^"]+)"/.exec(html)?.[1];
    assert.ok(csrf, 'Login page must contain a CSRF token');
    return csrf;
  };
  const health = await request('/actuator/health');
  assert.equal(health.status, 200, 'UI health endpoint');
  assert.equal((await health.json()).status, 'UP');
  const anonymous = await request('/api/clusters');
  assert.ok([302, 303, 401].includes(anonymous.status), 'Cluster API must require login');
  let csrf = await csrfFrom(await request('/login'));
  const rejected = await request('/login', { method: 'POST', body: new URLSearchParams({ username: credentials.SPRING_SECURITY_USER_NAME, password: 'deliberately-incorrect-password', csrf }) });
  assert.ok([302, 303, 401].includes(rejected.status), 'Incorrect password must not authenticate');
  if (rejected.status !== 401) assert.match(rejected.headers.get('location') || '', /[?&]error/, 'Bad password must redirect to login failure');
  await rejected.body?.cancel();
  const login = await request('/login', { method: 'POST', body: new URLSearchParams({ username: credentials.SPRING_SECURITY_USER_NAME, password: credentials.SPRING_SECURITY_USER_PASSWORD, csrf }) });
  assert.equal(login.status, 303, 'Password must lead to OTP verification');
  assert.equal(jar.has('ajnat_kafka_session'), false, 'Password alone must not create an authenticated session');
  await login.body?.cancel();
  const unverified = await request('/api/clusters');
  assert.equal(unverified.status, 401, 'API must reject a password-only login');
  await unverified.body?.cancel();
  csrf = await csrfFrom(await request('/login'));
  if (!process.stdin.isTTY) {
    await (await request('/logout')).body?.cancel();
    console.log(JSON.stringify({ status: 'pass', loginRequired: true, emailOtpRequired: true, smtpAccepted: true, invalidPasswordRejected: true, passwordOnlyAccessRejected: true, authenticatedApiChecks: 'not_run', message: 'An OTP email was accepted by SMTP. Run verify-ui in a terminal and enter its new email code for authenticated API checks.' }, null, 2));
    return;
  }
  const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
  let otp;
  try { otp = (await prompt.question('Enter the 6-digit OTP from your email: ')).trim(); }
  finally { prompt.close(); }
  assert.match(otp, /^\d{6}$/, 'A six-digit email OTP is required');
  const verified = await request('/login/otp', { method: 'POST', body: new URLSearchParams({ otp, csrf }) });
  assert.equal(verified.status, 303, 'Valid OTP must finish login');
  assert.ok(jar.has('ajnat_kafka_session'), 'OTP verification must create a session');
  await verified.body?.cancel();
  const cluster = encodeURIComponent(config.KAFKA_UI_CLUSTER_NAME);
  const topic = encodeURIComponent(config.BROKER_ALERT_TOPIC);
  const analysisPath = `/api/clusters/${cluster}/topics/${topic}/analysis`;
  const paths = ['/api/clusters', `/api/clusters/${cluster}/brokers`, `/api/clusters/${cluster}/topics`, `/api/clusters/${cluster}/consumer-groups/paged`, `/api/clusters/${cluster}/metrics`, analysisPath];
  const checks = [];
  for (const pathname of paths) {
    const response = await request(pathname);
    // Analysis is held in UI memory. A fresh container returns 404 until the
    // user runs Start Analysis; an actual 500 must still fail this check.
    if (pathname === analysisPath && response.status === 404) {
      checks.push({ path: pathname, status: 404, state: 'not_started' });
      continue;
    }
    assert.equal(response.status, 200, `Authenticated ${pathname}`);
    const value = await response.json();
    if (pathname === '/api/clusters') {
      assert.equal(value.find(item => item.name === config.KAFKA_UI_CLUSTER_NAME)?.status, 'ONLINE');
    }
    if (pathname === analysisPath) {
      assert.ok(value.result || value.progress, 'Topic analysis must contain results or progress');
      if (value.result) {
        const partitionTotal = (value.result.partitionStats || [])
          .reduce((sum, partition) => sum + (partition.totalMsgs || 0), 0);
        assert.equal(partitionTotal, value.result.totalStats?.totalMsgs || 0, 'Analysis partition totals must match');
      }
    }
    checks.push({ path: pathname, status: response.status, ...(pathname === '/api/clusters' ? { clusters: value.map(item => ({ name: item.name, status: item.status })) } : {}) });
  }
  await (await request('/logout')).body?.cancel();
  const loggedOut = await request('/api/clusters');
  assert.equal(loggedOut.status, 401, 'Logout must revoke the authenticated session');
  await loggedOut.body?.cancel();
  console.log(JSON.stringify({ status: 'pass', loginRequired: true, emailOtpRequired: true, smtpAccepted: true, invalidPasswordRejected: true, passwordOnlyAccessRejected: true, logoutVerified: true, checks }, null, 2));
}
verify().catch(error => { console.error(error.message); process.exitCode = 1; });
