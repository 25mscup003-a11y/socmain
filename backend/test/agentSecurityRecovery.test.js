const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('verified agent recovery resolves its active tamper alerts', () => {
  const route = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  const transition = route.slice(
    route.indexOf('async function recordAgentSecurityTransition'),
    route.indexOf('function getAgentLicenseLimit'),
  );

  assert.match(transition, /type: 'AGENT_TAMPER_DETECTED'/);
  assert.match(transition, /status: \{ \$in: \['open', 'investigating', 'under_observation'\] \}/);
  assert.match(transition, /\$set: \{ status: 'resolved', resolvedAt: now \}/);
});
