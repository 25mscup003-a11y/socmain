const http = require('node:http');
const crypto = require('node:crypto');
const { createEmailSender, readMailConfig } = require('./mailer');
const { loginPage } = require('./pages');

const FLOW_COOKIE = 'ajnat_kafka_login';
const SESSION_COOKIE = 'ajnat_kafka_session';
const CHALLENGE_MS = 10 * 60 * 1000;
const IDLE_MS = 30 * 60 * 1000;
const MAX_SESSION_MS = 8 * 60 * 60 * 1000;
const LIMIT_WINDOW_MS = 15 * 60 * 1000;
const MAX_ENTRIES = 1000;
const random = () => crypto.randomBytes(32).toString('hex');
const equal = (a, b) => crypto.timingSafeEqual(
  crypto.createHash('sha256').update(String(a || '')).digest(),
  crypto.createHash('sha256').update(String(b || '')).digest(),
);
const hopHeaders = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

function createGateway({ upstream, username, password, recipient, sendOTP, now = Date.now, secureCookies = false }) {
  const target = new URL(upstream);
  if (target.protocol !== 'http:') throw new Error('The private Kafbat upstream must use HTTP');
  if (!username || !password) throw new Error('Kafka UI username and password are required');
  if (!/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(recipient || '') || typeof sendOTP !== 'function') {
    throw new Error('An OTP email recipient and SMTP sender are required');
  }
  const otpKey = crypto.randomBytes(32);
  const hashCode = (flow, code) => crypto.createHmac('sha256', otpKey).update(`${flow.id}:${code}`).digest('hex');
  const flows = new Map();
  const sessions = new Map();
  const limits = new Map();
  function cleanup() {
    for (const [id, flow] of flows) if (flow.expires <= now()) flows.delete(id);
    for (const [id, session] of sessions) if (session.expires <= now() || session.created + MAX_SESSION_MS <= now()) sessions.delete(id);
    for (const [key, limit] of limits) if (limit.expires <= now()) limits.delete(key);
  }
  function rateLimited(key, maximum) {
    let limit = limits.get(key);
    if (!limit || limit.expires <= now()) {
      if (limits.size >= MAX_ENTRIES) return true;
      limit = { count: 0, expires: now() + LIMIT_WINDOW_MS };
      limits.set(key, limit);
    }
    return ++limit.count > maximum;
  }
  function cookie(name, value) {
    return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict${secureCookies ? '; Secure' : ''}${value ? '' : '; Max-Age=0'}`;
  }
  function cookies(req) {
    return Object.fromEntries((req.headers.cookie || '').split(';').map(value => value.trim().split('=')));
  }
  function redirect(res, location, setCookies = []) {
    res.writeHead(303, { location, 'cache-control': 'no-store', 'set-cookie': setCookies });
    res.end();
  }
  function fail(res, status, message) {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ message }));
  }
  function newFlow(stage = 'password') {
    if (flows.size >= MAX_ENTRIES) throw new Error('Too many pending logins');
    const flow = { id: random(), csrf: random(), stage, expires: now() + CHALLENGE_MS, attempts: 0 };
    flows.set(flow.id, flow);
    return flow;
  }
  async function page(res, flow, message = '', status = 200) {
    const html = loginPage({ stage: flow.stage, csrf: flow.csrf, recipient, sent: Boolean(flow.otpHash), message });
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store',
      'set-cookie': cookie(FLOW_COOKIE, flow.id),
      'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      'x-content-type-options': 'nosniff', 'referrer-policy': 'same-origin',
    });
    res.end(html);
  }
  async function sendCode(res, flow) {
    if (flow.busy) return fail(res, 409, 'An OTP request is already in progress');
    if (flow.lastSentAt !== undefined && now() - flow.lastSentAt < 60000) {
      return page(res, flow, 'Please wait 60 seconds between OTP emails.', 429);
    }
    if ((flow.sendCount || 0) >= 3 || rateLimited('email:account', 10)) {
      return page(res, flow, 'Too many OTP emails requested. Try again in 15 minutes.', 429);
    }
    flow.busy = true;
    flow.lastSentAt = now();
    flow.sendCount = (flow.sendCount || 0) + 1;
    flow.otpHash = null;
    const code = crypto.randomInt(100000, 1000000).toString();
    try {
      await sendOTP({ to: recipient, code });
      if (!flows.has(flow.id)) return fail(res, 403, 'Login expired. Please sign in again.');
      flow.otpHash = hashCode(flow, code);
      flow.expires = now() + CHALLENGE_MS;
      return redirect(res, '/login', [cookie(FLOW_COOKIE, flow.id), cookie(SESSION_COOKIE, '')]);
    } catch {
      return page(res, flow, 'Could not send the OTP email. Wait 60 seconds, then choose Resend OTP.', 502);
    } finally {
      flow.busy = false;
    }
  }
  async function form(req) {
    if (!(req.headers['content-type'] || '').startsWith('application/x-www-form-urlencoded')) return null;
    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
      size += chunk.length;
      if (size > 4096) return null;
      chunks.push(chunk);
    }
    return new URLSearchParams(Buffer.concat(chunks).toString());
  }
  async function upstreamLogin() {
    const response = await fetch(new URL('/login', target), {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(15000),
      body: new URLSearchParams({ username, password }),
    });
    const backendCookies = response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
    const location = response.headers.get('location') || '';
    await response.body?.cancel();
    if (![302, 303].includes(response.status) || /[?&]error/.test(location) || !backendCookies) {
      throw new Error('Upstream login rejected');
    }
    return backendCookies;
  }
  function proxy(req, res, session, sessionId) {
    const headers = {};
    const connectionHeaders = String(req.headers.connection || '').toLowerCase().split(',').map(header => header.trim());
    for (const [key, value] of Object.entries(req.headers)) {
      if (!hopHeaders.has(key) && !connectionHeaders.includes(key) && !['host', 'cookie', 'authorization', 'forwarded'].includes(key) && !key.startsWith('x-forwarded-')) headers[key] = value;
    }
    headers.host = target.host;
    headers.cookie = session.backendCookies;
    // The gateway has already checked the browser's origin. Present the
    // corresponding private origin to Kafbat's same-origin request checks.
    if (headers.origin) headers.origin = target.origin;
    if (headers.referer) headers.referer = target.origin + new URL(headers.referer).pathname;
    const upstreamRequest = http.request({ hostname: target.hostname, port: target.port || 80, path: req.url, method: req.method, headers }, upstreamResponse => {
      const responseHeaders = {};
      const responseConnections = String(upstreamResponse.headers.connection || '').toLowerCase().split(',').map(header => header.trim());
      for (const [key, value] of Object.entries(upstreamResponse.headers)) {
        if (!hopHeaders.has(key) && !responseConnections.includes(key) && key !== 'set-cookie') responseHeaders[key] = value;
      }
      // Upstream sessions stay on the server; the browser only receives our
      // opaque session created after both password and OTP verification.
      if (upstreamResponse.headers['set-cookie']) {
        const jar = new Map(session.backendCookies.split('; ').map(item => { const index = item.indexOf('='); return [item.slice(0, index), item.slice(index + 1)]; }));
        for (const item of upstreamResponse.headers['set-cookie']) {
          const first = item.split(';')[0];
          const index = first.indexOf('=');
          jar.set(first.slice(0, index), first.slice(index + 1));
        }
        session.backendCookies = [...jar].map(([key, value]) => `${key}=${value}`).join('; ');
      }
      if (responseHeaders.location) {
        const location = new URL(responseHeaders.location, target);
        responseHeaders.location = location.origin === target.origin ? location.pathname + location.search : '/';
        if (location.pathname === '/login') {
          sessions.delete(sessionId);
          responseHeaders['set-cookie'] = cookie(SESSION_COOKIE, '');
        }
      }
      res.writeHead(upstreamResponse.statusCode, responseHeaders);
      upstreamResponse.pipe(res);
      upstreamResponse.on('error', () => res.destroy());
    });
    upstreamRequest.on('error', () => {
      if (!res.headersSent) fail(res, 502, 'Kafka UI is temporarily unavailable. Please try again.');
      else res.destroy();
    });
    upstreamRequest.setTimeout(120000, () => upstreamRequest.destroy());
    req.on('aborted', () => upstreamRequest.destroy());
    res.on('close', () => upstreamRequest.destroy());
    req.pipe(upstreamRequest);
  }

  const server = http.createServer(async (req, res) => {
    try {
      cleanup();
      // Browser mutations must originate from this UI. Never trust forwarded
      // identity or client-supplied Kafbat cookies.
      if (req.headers['sec-fetch-site'] === 'cross-site' || (req.headers.origin && req.headers.origin !== `${secureCookies ? 'https' : 'http'}://${req.headers.host}`)) {
        return fail(res, 403, 'Cross-site requests are not allowed');
      }
      const pathname = new URL(req.url, 'http://localhost').pathname;
      const jar = cookies(req);
      let flow = flows.get(jar[FLOW_COOKIE]);
      const session = sessions.get(jar[SESSION_COOKIE]);
      if (req.method === 'GET' && pathname === '/actuator/health') {
        const health = await fetch(new URL('/actuator/health', target), { signal: AbortSignal.timeout(5000) });
        await health.body?.cancel();
        res.writeHead(health.ok ? 200 : 503, { 'content-type': 'application/json', 'cache-control': 'no-store' });
        return res.end(JSON.stringify({ status: health.ok ? 'UP' : 'DOWN' }));
      }
      if (['GET', 'POST'].includes(req.method) && pathname === '/logout') {
        sessions.delete(jar[SESSION_COOKIE]);
        flows.delete(jar[FLOW_COOKIE]);
        return redirect(res, '/login', [cookie(SESSION_COOKIE, ''), cookie(FLOW_COOKIE, '')]);
      }
      if (req.method === 'GET' && ['/login', '/login/otp'].includes(pathname)) {
        if (session) return redirect(res, '/');
        flow ||= newFlow();
        return await page(res, flow);
      }
      if (req.method === 'POST' && ['/login', '/login/otp', '/login/resend'].includes(pathname)) {
        const body = await form(req);
        if (!flow || !body || !equal(body.get('csrf'), flow.csrf)) return fail(res, 403, 'Login expired. Reload the login page and try again.');
        if (pathname === '/login') {
          if (flow.stage !== 'password') return fail(res, 403, 'Complete OTP verification first');
          if (rateLimited(`password:${req.socket.remoteAddress}`, 10) || rateLimited('password:all', 50)) {
            return await page(res, flow, 'Too many login attempts. Try again in 15 minutes.', 429);
          }
          if (!equal(body.get('username'), username) || !equal(body.get('password'), password)) {
            return await page(res, flow, 'Invalid username or password.', 401);
          }
          flows.delete(flow.id);
          flow = newFlow('otp');
          return await sendCode(res, flow);
        }
        if (flow.stage !== 'otp') return fail(res, 403, 'Enter your username and password first');
        if (flow.busy) return fail(res, 409, 'Verification is already in progress');
        if (pathname === '/login/resend') {
          if (flow.attempts >= 5) {
            flows.delete(flow.id);
            return fail(res, 429, 'Too many OTP attempts. Please sign in again.');
          }
          return await sendCode(res, flow);
        }
        if (++flow.attempts > 5 || rateLimited('otp:account', 10)) {
          flows.delete(flow.id);
          return fail(res, 429, 'Too many OTP attempts. Sign in again; after repeated failures wait 15 minutes.');
        }
        const code = body.get('otp');
        if (!/^\d{6}$/.test(code || '') || !flow.otpHash || !equal(hashCode(flow, code), flow.otpHash)) {
          return await page(res, flow, 'Invalid or already used OTP. Enter the latest code sent to your email.', 401);
        }
        // Consume the challenge before awaiting Kafbat; simultaneous requests
        // cannot exchange the same email code for multiple sessions.
        flow.otpHash = null;
        flow.busy = true;
        let backendCookies;
        try { backendCookies = await upstreamLogin(); }
        catch {
          flow.busy = false;
          return await page(res, flow, 'Kafka UI is temporarily unavailable. Choose Resend OTP to try again.', 502);
        }
        if (!flows.has(flow.id) || flow.expires <= now()) return fail(res, 403, 'Login expired. Please sign in again.');
        if (sessions.size >= MAX_ENTRIES) return fail(res, 503, 'Too many active sessions. Please try again later.');
        const id = random();
        sessions.set(id, { backendCookies, created: now(), expires: now() + IDLE_MS });
        flows.delete(flow.id);
        limits.delete('otp:account');
        return redirect(res, '/', [cookie(SESSION_COOKIE, id), cookie(FLOW_COOKIE, '')]);
      }
      if (!session) {
        if (pathname.startsWith('/api/') || !['GET', 'HEAD'].includes(req.method)) return fail(res, 401, 'Password and OTP verification are required');
        return redirect(res, '/login');
      }
      session.expires = now() + IDLE_MS;
      proxy(req, res, session, jar[SESSION_COOKIE]);
    } catch {
      // Never include SMTP credentials, OTP codes or upstream cookies in logs.
      if (!res.headersSent) fail(res, 503, 'Login service is temporarily unavailable. Please try again.');
      else res.destroy();
    }
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;
  return server;
}

if (require.main === module) {
  const mailConfig = readMailConfig(process.env.SMTP_CONFIG_FILE || '/run/secrets/ui-mail.json');
  const server = createGateway({
    upstream: process.env.KAFKA_UI_UPSTREAM || 'http://kafka-ui:8080',
    username: process.env.SPRING_SECURITY_USER_NAME,
    password: process.env.SPRING_SECURITY_USER_PASSWORD,
    recipient: mailConfig.recipient,
    sendOTP: createEmailSender(mailConfig),
    secureCookies: process.env.COOKIE_SECURE === 'true',
  });
  server.listen(Number(process.env.PORT || 8080), '0.0.0.0', () => console.log('Kafka UI password + OTP gateway listening'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
}

module.exports = { createGateway };
