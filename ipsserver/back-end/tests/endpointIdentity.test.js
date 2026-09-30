const { _test } = require('../src/services/mongoService');

describe('SOC IPS alert endpoint identity', () => {
  test('preserves system, department, agent, hostname, and endpoint IP evidence', () => {
    const alert = _test._socIpsAlert({
      action: 'block',
      company: '507f1f77bcf86cd799439011',
      block: {
        ip: '203.0.113.10',
        systemId: '507f1f77bcf86cd799439012',
        departmentId: '507f1f77bcf86cd799439013',
        agentId: 'agent-123',
        agentName: 'linux2',
        agentHostname: 'CHAUDHARY',
        agentIp: '192.168.10.112',
      },
      threat: { level: 'high', type: 'Threat Intelligence' },
    });

    expect(String(alert.systemId)).toBe('507f1f77bcf86cd799439012');
    expect(String(alert.departmentId)).toBe('507f1f77bcf86cd799439013');
    expect(alert.endpointId).toBe('507f1f77bcf86cd799439012');
    expect(alert.agentId).toBe('agent-123');
    expect(alert.hostname).toBe('CHAUDHARY');
    expect(alert.destip).toBe('192.168.10.112');
    expect(alert.eventFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(alert.eventId).toBe(`ips-${alert.eventFingerprint}`);
  });

  test('creates stable, action-specific fingerprints for IPS events', () => {
    const input = {
      company: '507f1f77bcf86cd799439011',
      block: {
        ip: '203.0.113.10',
        blockKey: 'ip:203.0.113.10:both',
        ts: '2026-08-26T16:19:28.548Z',
      },
    };

    const first = _test._socIpsAlert({ ...input, action: 'block' });
    const retry = _test._socIpsAlert({ ...input, action: 'block' });
    const unblock = _test._socIpsAlert({ ...input, action: 'unblock' });

    expect(first.eventFingerprint).toBe(retry.eventFingerprint);
    expect(first.eventFingerprint).not.toBe(unblock.eventFingerprint);
  });
});
