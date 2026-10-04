const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { once } = require('node:events');
const { createGateway } = require('../ui-auth/server');
const { mailConfigFromBackend, createEmailSender } = require('../ui-auth/mailer');

async function fixture(t, { upstreamFailure = false, mailFailure = false } = {}) {
  const emails = [];
  let time = 1234567890000;
  let upstreamLogins = 0;
  const upstream = http.createServer(async (req, res) => {
    if (req.url === '/actuator/health') { res.writeHead(200); return res.end('{"status":"UP"}'); }
    if (req.url === '/login' && req.method === 'POST') {
      let body = '';
      for await (const part of req) body += part;
      const form = new URLSearchParams(body);
      assert.equal(form.get('username'), 'admin');
      assert.equal(form.get('password'), 'test-password');
      upstreamLogins++;
      if (upstreamFailure) { res.writeHead(503); return res.end(); }
      res.writeHead(302, { location: '/', 'set-cookie': 'SESSION=private-upstream-cookie; HttpOnly' });
      return res.end();
    }
    if (req.headers.cookie !== 'SESSION=private-upstream-cookie') { res.writeHead(401); return res.end(); }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ clusters: ['ajnat-local'], authorization: req.headers.authorization || null, forwarded: req.headers['x-forwarded-user'] || null }));
  });
  upstream.listen(0, '127.0.0.1');
  await once(upstream, 'listening');
  let gateway;
  const start = async () => {
    gateway = createGateway({ upstream: `http://127.0.0.1:${upstream.address().port}`, username: 'admin', password: 'test-password', recipient: 'admin@example.com', sendOTP: async message => { if (mailFailure) throw new Error('SMTP unavailable'); emails.push(message); }, now: () => time });
    gateway.listen(0, '127.0.0.1');
    await once(gateway, 'listening');
  };
  await start();
  t.after(async () => {
    await new Promise(resolve => gateway.close(resolve));
    await new Promise(resolve => upstream.close(resolve));
  });
  const browser = () => {
    const jar = new Map();
    let csrf;
    let latestCode;
    async function request(url, options = {}) {
      const response = await fetch(`http://127.0.0.1:${gateway.address().port}${url}`, {
        redirect: 'manual', ...options,
        headers: { cookie: [...jar].map(([name, value]) => `${name}=${value}`).join('; '), ...options.headers },
      });
      for (const item of response.headers.getSetCookie()) {
        const [name, value] = item.split(';')[0].split('=');
        if (value) jar.set(name, value); else jar.delete(name);
      }
      const text = await response.text();
      csrf = /name="csrf" value="([^"]+)"/.exec(text)?.[1] || csrf;
      return { status: response.status, headers: response.headers, text };
    }
    return {
      request, jar,
      async password(value = 'test-password') {
        await request('/login');
        const response = await request('/login', { method: 'POST', body: new URLSearchParams({ username: 'admin', password: value, csrf }) });
        latestCode = emails.at(-1)?.code;
        if (response.status === 303) return request('/login');
        return response;
      },
      otp(code = latestCode || '000000') {
        return request('/login/otp', { method: 'POST', body: new URLSearchParams({ otp: code, csrf }) });
      },
      async resend() {
        const response = await request('/login/resend', { method: 'POST', body: new URLSearchParams({ csrf }) });
        latestCode = emails.at(-1)?.code;
        return response;
      },
    };
  };
  return { browser, advance: milliseconds => { time += milliseconds; }, emails, setMailFailure: value => { mailFailure = value; }, logins: () => upstreamLogins, restart: async () => { await new Promise(resolve => gateway.close(resolve)); await start(); } };
}

test('every login requires password then OTP, protecting HTML and APIs until verified', async t => {
  const f = await fixture(t);
  const browser = f.browser();
  assert.equal((await browser.request('/')).status, 303);
  assert.equal((await browser.request('/api/clusters')).status, 401);
  assert.equal((await browser.password('wrong')).status, 401);
  const setup = await browser.password();
  assert.match(setup.text, /Verify your email/);
  assert.match(setup.text, /ad\*\*\*@example.com/);
  assert.doesNotMatch(setup.text, /QR|authenticator|data:image/i);
  assert.equal(f.emails.length, 1);
  const firstCode = f.emails[0].code;
  assert.match(firstCode, /^[1-9]\d{5}$/);
  assert.equal(browser.jar.has('ajnat_kafka_session'), false);
  assert.equal(f.logins(), 0);
  assert.equal((await browser.request('/api/clusters')).status, 401);
  assert.equal((await browser.otp('000000')).status, 401);
  const accepted = await browser.otp();
  assert.equal(accepted.status, 303);
  assert.equal(f.logins(), 1);
  assert.equal(accepted.headers.get('set-cookie').includes('private-upstream-cookie'), false);
  assert.match(accepted.headers.get('set-cookie'), /HttpOnly; SameSite=Strict/);
  const authenticated = await browser.request('/api/clusters', { headers: { authorization: 'Basic injected', 'x-forwarded-user': 'attacker' } });
  assert.equal(authenticated.status, 200);
  assert.deepEqual(JSON.parse(authenticated.text), { clusters: ['ajnat-local'], authorization: null, forwarded: null });
  const oldSession = browser.jar.get('ajnat_kafka_session');
  await browser.request('/logout');
  assert.equal((await browser.request('/api/clusters', { headers: { cookie: `ajnat_kafka_session=${oldSession}` } })).status, 401);
  const second = await browser.password();
  assert.match(second.text, /Verify your email/);
  assert.equal(f.emails.length, 2);
  assert.equal(second.text.includes('data:image'), false);
  assert.equal((await browser.request('/api/clusters')).status, 401);
  assert.equal((await browser.otp(firstCode)).status, 401, 'previous login OTP cannot be reused');
  assert.equal((await browser.otp()).status, 303);
  assert.equal((await browser.request('/api/clusters')).status, 200);
});

test('direct OTP, forged upstream cookies and cross-site requests cannot bypass login', async t => {
  const f = await fixture(t);
  const browser = f.browser();
  assert.equal((await browser.otp()).status, 403);
  await browser.request('/login');
  assert.equal((await browser.otp()).status, 403);
  assert.equal((await browser.request('/api/clusters', { headers: { cookie: 'SESSION=private-upstream-cookie', authorization: 'Basic YWRtaW4=' } })).status, 401);
  assert.equal((await browser.request('/login', { method: 'POST', body: new URLSearchParams({ username: 'admin', password: 'test-password', csrf: 'forged' }) })).status, 403);
  assert.equal((await browser.request('/login', { headers: { origin: 'https://attacker.example' } })).status, 403);
  assert.equal((await browser.request('/logout', { headers: { 'sec-fetch-site': 'cross-site' } })).status, 403);
  assert.equal(f.logins(), 0);
});

test('OTP attempt limits survive starting another password challenge', async t => {
  const f = await fixture(t);
  for (let challenge = 0; challenge < 2; challenge++) {
    const browser = f.browser();
    await browser.password();
    for (let attempt = 0; attempt < 5; attempt++) assert.equal((await browser.otp('000000')).status, 401);
    assert.equal((await browser.otp('000000')).status, 429);
  }
  const next = f.browser();
  await next.password();
  assert.equal((await next.otp()).status, 429, 'new password challenges cannot reset account OTP limit');
  assert.equal(f.logins(), 0);
});

test('login challenges and idle sessions expire', async t => {
  const f = await fixture(t);
  const browser = f.browser();
  await browser.password();
  f.advance(10 * 60 * 1000 + 1);
  assert.equal((await browser.otp()).status, 403);
  await browser.password();
  assert.equal((await browser.otp()).status, 303);
  f.advance(30 * 60 * 1000 + 1);
  assert.equal((await browser.request('/api/clusters')).status, 401);
});

test('restart invalidates email challenges and authenticated sessions', async t => {
  const f = await fixture(t);
  const browser = f.browser();
  const pending = f.browser();
  await browser.password();
  await browser.otp();
  await pending.password();
  await f.restart();
  assert.equal((await browser.request('/api/clusters')).status, 401);
  assert.equal((await pending.otp()).status, 403);
  await browser.password();
  assert.equal((await browser.otp()).status, 303);
});

test('concurrent OTP submissions create only one authenticated session', async t => {
  const f = await fixture(t);
  const browser = f.browser();
  await browser.password();
  const responses = await Promise.all([browser.otp(), browser.otp()]);
  assert.equal(responses.filter(item => item.status === 303).length, 1);
  assert.equal(responses.filter(item => [403, 409].includes(item.status)).length, 1);
  assert.equal(f.logins(), 1);
});

test('upstream outage fails closed and consumes the submitted email OTP', async t => {
  const f = await fixture(t, { upstreamFailure: true });
  const browser = f.browser();
  await browser.password();
  assert.equal((await browser.otp()).status, 502);
  assert.equal(browser.jar.has('ajnat_kafka_session'), false);
  assert.equal((await browser.otp()).status, 401);
  assert.equal((await browser.request('/api/clusters')).status, 401);
});

test('email codes belong to one browser challenge and resends invalidate the previous code', async t => {
  const f = await fixture(t);
  const first = f.browser();
  const second = f.browser();
  await first.password();
  const oldCode = f.emails.at(-1).code;
  await second.password();
  assert.equal((await second.otp(oldCode)).status, 401);
  assert.equal((await first.resend()).status, 429);
  f.advance(60000);
  assert.equal((await first.resend()).status, 303);
  assert.equal(f.emails.length, 3);
  assert.equal((await first.otp(oldCode)).status, 401);
  assert.equal((await first.otp()).status, 303);
});

test('resending does not reset failed OTP attempts', async t => {
  const f = await fixture(t);
  const browser = f.browser();
  await browser.password();
  for (let attempt = 0; attempt < 4; attempt++) assert.equal((await browser.otp('000000')).status, 401);
  f.advance(60000);
  assert.equal((await browser.resend()).status, 303);
  assert.equal((await browser.otp('000000')).status, 401);
  assert.equal((await browser.otp()).status, 429);
});

test('SMTP failure cannot create a usable code or a session; resend can recover', async t => {
  const f = await fixture(t, { mailFailure: true });
  const browser = f.browser();
  const failure = await browser.password();
  assert.equal(failure.status, 502);
  assert.match(failure.text, /Could not send the OTP email/);
  assert.doesNotMatch(failure.text, /OTP sent/);
  assert.equal(f.emails.length, 0);
  assert.equal((await browser.otp()).status, 401);
  assert.equal((await browser.request('/api/clusters')).status, 401);
  f.setMailFailure(false);
  f.advance(60000);
  assert.equal((await browser.resend()).status, 303);
  assert.equal((await browser.otp()).status, 303);
});

test('only SMTP configuration is copied; sender requires SMTP acceptance for the configured recipient', async () => {
  const config = mailConfigFromBackend({ SMTP_HOST: 'smtp.gmail.com', SMTP_PORT: '587', SMTP_SECURE: 'false', SMTP_USER: 'sender@example.com', SMTP_PASS: 'smtp-password', SMTP_FROM: 'Kafka <sender@example.com>', JWT_SECRET: 'must-not-copy', MONGO_URI: 'must-not-copy' }, 'admin@example.com');
  assert.deepEqual(Object.keys(config).sort(), ['from', 'host', 'password', 'port', 'recipient', 'secure', 'user']);
  let mail;
  const send = createEmailSender(config, { sendMail: async value => { mail = value; return { accepted: [value.to] }; } });
  await send({ to: 'admin@example.com', code: '123456' });
  assert.equal(mail.from, config.from);
  assert.equal(mail.to, config.recipient);
  assert.match(mail.text, /123456/);
  await assert.rejects(send({ to: 'attacker@example.com', code: '123456' }));
  const rejected = createEmailSender(config, { sendMail: async () => ({ accepted: [], rejected: ['admin@example.com'] }) });
  await assert.rejects(rejected({ to: 'admin@example.com', code: '123456' }));
});
