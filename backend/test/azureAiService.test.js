const test = require('node:test');
const assert = require('node:assert/strict');
const axios = require('axios');
const AiAnalysis = require('../src/models/AiAnalysis.model');
const {
  autoAnalysisEnabled, mask, extractJson, fallbackOutput, normalizeConfidence, responseText, callModel,
  shouldAutoAnalyzeAlert,
} = require('../src/services/azureAi.service');

test('AI redaction removes secrets and direct identifiers', () => {
  const result = mask({
    apiKey: 'secret-value',
    authorization: 'Bearer token',
    user: 'analyst@example.com',
    nested: { password: 'password-value' },
  });
  assert.equal(result.apiKey, '[REDACTED]');
  assert.equal(result.authorization, '[REDACTED]');
  assert.equal(result.user, '[REDACTED_EMAIL]');
  assert.equal(result.nested.password, '[REDACTED]');
});

test('AI JSON parser accepts plain and fenced model output', () => {
  assert.deepEqual(extractJson('{"confidence":91}'), { confidence: 91 });
  assert.deepEqual(extractJson('```json\n{"summary":"ok"}\n```'), { summary: 'ok' });
});

test('AI parser removes thinking text and fallback is explicitly low confidence', () => {
  assert.deepEqual(
    extractJson('<think>private reasoning</think>```json\n{"summary":"safe"}\n```'),
    { summary: 'safe' },
  );
  const recovered = fallbackOutput('Unstructured provider response');
  assert.equal(recovered.confidence, 25);
  assert.equal(recovered.outputFormatRecovered, true);
});

test('AI Responses API text is read from convenience and nested output formats', () => {
  assert.equal(responseText({ output_text: '{"summary":"direct"}' }), '{"summary":"direct"}');
  assert.equal(responseText({
    output: [{ content: [{ type: 'output_text', text: '{"summary":"nested"}' }] }],
  }), '{"summary":"nested"}');
});

test('AI Responses API retries without unsupported optional parameters on 400', async () => {
  const originalPost = axios.post;
  const originalUrl = process.env.AZURE_AI_RESPONSES_URL;
  const originalKey = process.env.AZURE_AI_API_KEY;
  const originalModel = process.env.AZURE_AI_MODEL;
  const bodies = [];
  process.env.AZURE_AI_RESPONSES_URL = 'https://example.invalid/responses';
  process.env.AZURE_AI_API_KEY = 'test-key';
  process.env.AZURE_AI_MODEL = 'test-model';
  axios.post = async (_url, body) => {
    bodies.push(body);
    if (bodies.length === 1) {
      const error = new Error('Request failed with status code 400');
      error.response = { status: 400, data: { error: { message: "Unsupported parameter: 'text.format'" } } };
      throw error;
    }
    return { data: { output_text: '{"summary":"ok","confidence":80}' } };
  };
  try {
    const result = await callModel('Return JSON.', { event: 'test' });
    assert.equal(result.summary, 'ok');
    assert.equal(bodies.length, 2);
    assert.deepEqual(bodies[0].text, { format: { type: 'json_object' } });
    assert.equal(bodies[0].model, 'test-model');
    assert.equal(bodies[1].text, undefined);
    assert.deepEqual(bodies[0].input, [
      { type: 'message', role: 'system', content: [{ type: 'input_text', text: 'Return JSON.' }] },
      { type: 'message', role: 'user', content: [{ type: 'input_text', text: '{"event":"test"}' }] },
    ]);
  } finally {
    axios.post = originalPost;
    if (originalUrl === undefined) delete process.env.AZURE_AI_RESPONSES_URL;
    else process.env.AZURE_AI_RESPONSES_URL = originalUrl;
    if (originalKey === undefined) delete process.env.AZURE_AI_API_KEY;
    else process.env.AZURE_AI_API_KEY = originalKey;
    if (originalModel === undefined) delete process.env.AZURE_AI_MODEL;
    else process.env.AZURE_AI_MODEL = originalModel;
  }
});

test('AI confidence accepts fractional and percentage provider formats', () => {
  assert.equal(normalizeConfidence(0.95), 95);
  assert.equal(normalizeConfidence(95), 95);
  assert.equal(normalizeConfidence(120), 100);
});

test('AI analysis schema is tenant scoped, auditable and asynchronous', () => {
  for (const field of [
    'tenantId', 'companyId', 'requestedBy', 'requestedByRole', 'status',
    'cacheKey', 'output', 'confidence', 'reasoning', 'sourceIp',
  ]) {
    assert.ok(AiAnalysis.schema.path(field), `${field} must exist`);
  }
  assert.deepEqual(AiAnalysis.schema.path('status').enumValues, ['queued', 'processing', 'completed', 'failed']);
  assert.ok(AiAnalysis.schema.path('taskType').enumValues.includes('edr_incident_analysis'));
  assert.ok(AiAnalysis.schema.path('resourceType').enumValues.includes('EdrIncident'));
});

test('automatic AI investigation targets relevant high-risk normalized events only', () => {
  const previousMaster = process.env.AZURE_AI_AUTO_ANALYZE_ENABLED;
  const previous = process.env.AZURE_AI_AUTO_ANALYZE_HIGH_RISK;
  process.env.AZURE_AI_AUTO_ANALYZE_ENABLED = 'false';
  assert.equal(autoAnalysisEnabled(), false);
  assert.equal(shouldAutoAnalyzeAlert({ severity: 'critical' }), false);
  process.env.AZURE_AI_AUTO_ANALYZE_ENABLED = 'true';
  assert.equal(autoAnalysisEnabled(), true);
  process.env.AZURE_AI_AUTO_ANALYZE_HIGH_RISK = 'false';
  assert.equal(shouldAutoAnalyzeAlert({ module: 'IDS', severity: 'critical' }), false);
  process.env.AZURE_AI_AUTO_ANALYZE_HIGH_RISK = 'true';
  assert.equal(shouldAutoAnalyzeAlert({ eventCategory: 'malware', severity: 'critical' }), true);
  assert.equal(shouldAutoAnalyzeAlert({ module: 'IDS', eventCategory: 'network', severity: 'high' }), true);
  assert.equal(shouldAutoAnalyzeAlert({ module: 'IPS', eventCategory: 'network', severity: 'low', actionable: true }), true);
  assert.equal(shouldAutoAnalyzeAlert({ eventCategory: 'file', severity: 'high' }), true);
  assert.equal(shouldAutoAnalyzeAlert({ eventCategory: 'system', severity: 'low' }), false);
  assert.equal(shouldAutoAnalyzeAlert({ eventCategory: 'malware', severity: 'critical', isSynthetic: true }), false);
  if (previous === undefined) delete process.env.AZURE_AI_AUTO_ANALYZE_HIGH_RISK;
  else process.env.AZURE_AI_AUTO_ANALYZE_HIGH_RISK = previous;
  if (previousMaster === undefined) delete process.env.AZURE_AI_AUTO_ANALYZE_ENABLED;
  else process.env.AZURE_AI_AUTO_ANALYZE_ENABLED = previousMaster;
});
