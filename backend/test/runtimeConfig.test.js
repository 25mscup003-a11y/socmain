'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('backend and generated agent connection use required environment settings', () => {
  const server = fs.readFileSync(path.join(__dirname, '../src/server.js'), 'utf8');
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/agent.routes.js'), 'utf8');
  const tenant = fs.readFileSync(path.join(__dirname, '../src/utils/tenant.js'), 'utf8');

  for (const name of [
    'SERVER_PROTO', 'SERVER_IP', 'SERVER_PORT',
    'APP_PROTO', 'ROOT_DOMAIN', 'MAIN_TENANT_SUBDOMAIN',
  ]) {
    assert.match(server, new RegExp(`['"]${name}['"]`));
  }
  assert.match(server, /const PORT = Number\(process\.env\.SERVER_PORT\)/);
  assert.doesNotMatch(routes, /process\.env\.SERVER_IP\s+\|\|\s+['"]localhost['"]/);
  assert.doesNotMatch(routes, /Number\(process\.env\.SERVER_PORT\)\s+\|\|\s+5000/);
  const runtimeConfig = routes.slice(routes.indexOf('config_update:'), routes.indexOf('config_update:') + 1200);
  assert.doesNotMatch(runtimeConfig, /agent_version:/);
  assert.match(routes, /config_update:\s*\{[\s\S]*server_url:\s*agentServerConnection\(\)\.url/);
  assert.match(tenant, /const ROOT_DOMAIN = process\.env\.ROOT_DOMAIN/);
  assert.match(tenant, /const APP_PROTO = process\.env\.APP_PROTO/);
});
