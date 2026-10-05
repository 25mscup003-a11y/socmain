const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const System = require('../src/models/System.model');

const {
  REQUEST_AAD,
  RESPONSE_AAD,
  deriveAgentTransportKey,
  encryptPayload,
  decryptPayload,
  encryptJsonPayload,
  decryptJsonPayload,
  agentPayloadEncryption,
} = require('../src/utils/agentPayloadEncryption');

const AGENT_KEY = '0123456789abcdef'.repeat(4);

test('agent API JSON uses authenticated AES-256-GCM envelopes', () => {
  const payload = { agent_key: AGENT_KEY, alerts: [{ severity: 'critical', text: 'नमस्ते' }] };
  const envelope = encryptJsonPayload(payload, AGENT_KEY);

  assert.equal(deriveAgentTransportKey(AGENT_KEY).length, 32);
  assert.equal(envelope.alg, 'A256GCM');
  assert.equal(Buffer.from(envelope.nonce, 'base64').length, 12);
  assert.equal(Buffer.from(envelope.tag, 'base64').length, 16);
  assert.deepEqual(decryptJsonPayload(envelope, AGENT_KEY), payload);
  assert.doesNotMatch(JSON.stringify(envelope), /critical|agent_key|नमस्ते/);
});

test('agent API encryption rejects tampering and separates request/response contexts', () => {
  const request = encryptJsonPayload({ ok: true }, AGENT_KEY);
  request.ciphertext = `${request.ciphertext.slice(0, -2)}AA`;
  assert.throws(() => decryptJsonPayload(request, AGENT_KEY));

  const response = encryptPayload(Buffer.from('{"ok":true}'), AGENT_KEY, RESPONSE_AAD);
  assert.equal(decryptPayload(response, AGENT_KEY, RESPONSE_AAD).toString(), '{"ok":true}');
  assert.throws(() => decryptPayload(response, AGENT_KEY, REQUEST_AAD));
});

test('middleware decrypts agent JSON and encrypts the JSON response', async (t) => {
  const systemId = '64b000000000000000000001';
  const originalFindById = System.findById;
  System.findById = () => ({
    select: async () => ({ _id: systemId, agentKey: AGENT_KEY }),
  });
  t.after(() => { System.findById = originalFindById; });

  const envelope = encryptJsonPayload({ secret: 'agent-only-data' }, AGENT_KEY);
  const headers = new Map();
  let wireBody;
  const req = {
    method: 'POST',
    headers: {
      'x-ajnat-payload-encryption': 'aes-256-gcm-v1',
      'x-agent-system-id': systemId,
      'x-agent-nonce': 'request-one',
    },
    body: envelope,
  };
  const res = {
    statusCode: 200,
    headersSent: false,
    setHeader(name, value) { headers.set(name.toLowerCase(), String(value)); },
    getHeader(name) { return headers.get(name.toLowerCase()); },
    status(code) { this.statusCode = code; return this; },
    send(body) { wireBody = body; this.headersSent = true; return this; },
    json(body) {
      this.setHeader('Content-Type', 'application/json; charset=utf-8');
      return this.send(JSON.stringify(body));
    },
  };
  await new Promise((resolve, reject) => {
    Promise.resolve(agentPayloadEncryption(req, res, resolve)).catch(reject);
  });
  res.json({ accepted: req.body.secret });
  const wireText = Buffer.from(wireBody).toString('utf8');
  assert.equal(headers.get('x-ajnat-payload-encryption'), 'aes-256-gcm-v1');
  const digest = crypto.createHash('sha256').update(wireBody).digest('hex');
  assert.equal(headers.get('x-ajnat-response-sha256'), digest);
  const signature = nonce => crypto.createHmac('sha256', AGENT_KEY).update(`AJNAT-RESPONSE-V1.${nonce}.200.${digest}`).digest('hex');
  assert.equal(headers.get('x-ajnat-response-signature'), signature('request-one'));
  assert.notEqual(headers.get('x-ajnat-response-signature'), signature('request-two'));
  assert.doesNotMatch(wireText, /agent-only-data/);
  assert.deepEqual(
    JSON.parse(decryptPayload(JSON.parse(wireText), AGENT_KEY, RESPONSE_AAD).toString('utf8')),
    { accepted: 'agent-only-data' },
  );
});
