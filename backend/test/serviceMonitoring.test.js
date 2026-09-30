const test = require('node:test');
const assert = require('node:assert/strict');
const { _private } = require('../src/routes/service-monitoring.routes');

test('canonical service events normalize inventory and lifecycle fields', () => {
  const event = _private.canonicalServiceEvent({
    ruleId: 'SERVICE_STOPPED',
    severity: 'high',
    rawEvent: {
      service_name: 'auditd.service',
      previous_status: 'active',
      current_status: 'inactive',
      service_account: 'root',
      service_binary_path: '/usr/sbin/auditd',
      security_service: true,
      risk_score: 65,
    },
  });
  assert.equal(event.serviceName, 'auditd.service');
  assert.equal(event.servicePreviousStatus, 'RUNNING');
  assert.equal(event.serviceCurrentStatus, 'STOPPED');
  assert.equal(event.serviceAccount, 'root');
  assert.equal(event.serviceSecurityCritical, true);
  assert.equal(event.riskScore, 65);
});

test('service health summary uses real inventory state and security failures', () => {
  const services = [
    { serviceName: 'auditd', serviceCurrentStatus: 'RUNNING', serviceSecurityCritical: true, systemId: 'host-a' },
    { serviceName: 'nginx', serviceCurrentStatus: 'FAILED', systemId: 'host-a' },
  ];
  const events = [
    { serviceName: 'auditd', serviceEventType: 'SERVICE_STOPPED', serviceSecurityCritical: true, severity: 'critical' },
    { serviceName: 'nginx', serviceEventType: 'SERVICE_FAILED', severity: 'high' },
  ];
  const summary = _private.summarize(events, services, [{ isOnline: true }]);
  assert.equal(summary.totalServices, 2);
  assert.equal(summary.running, 1);
  assert.equal(summary.failed, 1);
  assert.equal(summary.criticalAlerts, 1);
  assert.equal(summary.endpointsReporting, 1);
  assert.ok(summary.healthScore < 100);
});
