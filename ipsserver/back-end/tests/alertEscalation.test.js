jest.mock('nodemailer', () => ({ createTransport: jest.fn(() => { throw new Error('Tests must never send email'); }) }));
jest.mock('../src/services/mongoService', () => ({ storeLog: jest.fn().mockResolvedValue(null) }));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));
const engine = require('../src/services/alertEngine');

test('escalation requests isolation without claiming success or scheduling a false recovery', async () => {
  const previousSMTP = process.env.SMTP_USER;
  delete process.env.SMTP_USER;
  jest.useFakeTimers();
  const previousEmitter = global.emitIPSEvent;
  global.emitIPSEvent = jest.fn();
  try {
    const incident = await engine.handleDetection({ companyId: 'tenant-a', srcIp: '203.0.113.1' });
    await jest.advanceTimersByTimeAsync(2 * 60000);
    expect(incident.status).toBe('isolation_requested');
    expect(incident.isolationConfirmed).toBe(false);
    expect(incident.isolatedAt).toBeNull();
    expect(global.emitIPSEvent).toHaveBeenCalledWith('isolation-requested', expect.objectContaining({ enforced: false }));
    await engine.autoRecoveryCheck('tenant-a:203.0.113.1', incident);
    expect(incident.status).toBe('isolation_requested');
    expect(jest.getTimerCount()).toBe(0);
  } finally {
    global.emitIPSEvent = previousEmitter;
    if (previousSMTP === undefined) delete process.env.SMTP_USER;
    else process.env.SMTP_USER = previousSMTP;
    jest.useRealTimers();
  }
});
