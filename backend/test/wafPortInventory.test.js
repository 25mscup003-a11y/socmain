const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
require('../src/models/Alert.model');
const router = require('../src/routes/waf.routes');

test('WAF status excludes expired inventory and counts only online open ports', async t => {
  const now = new Date();
  const recentOffline = new Date(Date.now() - 2 * 3600000);
  const expired = new Date(Date.now() - 35 * 86400000);
  const company = 'inventory-test-company';
  const records = {
    waf_agents: [
      { company, systemId: 'live', hostname: 'live-host', online: true, lastSeen: now, ports: [80, 8080], portStatus: [{ port: 80, alive: true }, { port: 8080, alive: false }] },
      { company, systemId: 'offline', online: false, lastSeen: recentOffline, ports: [443] },
      { company, systemId: 'expired-direct', online: false, lastSeen: expired, ports: [5000] },
    ],
    alerts: [
      { companyId: company, systemId: 'expired-waf', ruleId: 'WAF_AGENT_STATUS', createdAt: expired, rawEvent: { detectedPorts: [9000] } },
      { companyId: company, systemId: 'expired-listener', ruleId: 'NET_EXPOSURE_SUMMARY', createdAt: expired, rawEvent: { listeners: [{ local_port: 5355 }] } },
      { companyId: company, systemId: 'live', ruleId: 'NET_EXPOSURE_SUMMARY', createdAt: now, rawEvent: { listeners: [{ local_port: 3000, protocol: 'tcp' }] } },
    ],
    waf_events: [],
  };
  const cursor = values => ({ sort() { return this; }, limit() { return this; }, toArray: async () => values });
  const connection = mongoose.connection;
  const readyDescriptor = Object.getOwnPropertyDescriptor(connection, 'readyState');
  const previousDb = connection.db;
  Object.defineProperty(connection, 'readyState', { configurable: true, value: 1 });
  connection.db = { collection: name => ({
    find: filter => cursor((records[name] || []).filter(row => {
      if (filter.ruleId && row.ruleId !== filter.ruleId) return false;
      if (filter.createdAt?.$gte && row.createdAt < filter.createdAt.$gte) return false;
      if (filter.lastSeen?.$gte && row.lastSeen < filter.lastSeen.$gte) return false;
      return true;
    })),
    findOne: async () => null,
    aggregate: () => cursor([]),
  }) };
  t.after(() => {
    connection.db = previousDb;
    if (readyDescriptor) Object.defineProperty(connection, 'readyState', readyDescriptor);
    else delete connection.readyState;
  });
  const route = router.stack.find(layer => layer.route?.path === '/status').route;
  const response = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  await route.stack.at(-1).handle({ user: { role: 'company_admin', companyId: company }, query: { hours: '24' } }, response);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body.agents.map(agent => agent.systemId), ['live', 'offline']);
  assert.equal(response.body.activeAgents, 1);
  assert.deepEqual(response.body.protectedPorts, [80]);
  assert.deepEqual(response.body.listeningPorts, [80, 3000]);
  assert.equal(response.body.totalPortsProtected, 1);
  assert.equal(response.body.totalListeningPorts, 2);
});
