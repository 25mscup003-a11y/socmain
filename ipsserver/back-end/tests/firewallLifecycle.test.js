const mockExecFile = jest.fn();
let mockDatabase = null;
jest.mock('child_process', () => ({ execFile: (...args) => mockExecFile(...args) }));
jest.mock('../src/db/mongodb', () => ({ getDB: () => mockDatabase }));
jest.mock('../src/utils/logger', () => Object.fromEntries(['info', 'warn', 'error', 'block'].map(key => [key, jest.fn()])));

let service;
function load(mode = 'endpoint-agent') {
  jest.resetModules();
  process.env.IPS_FIREWALL_MODE = mode;
  service = require('../src/services/firewallService');
  return service;
}
const A = '507f1f77bcf86cd799439011';
const B = '507f1f77bcf86cd799439012';
const target = { ip: '203.0.113.100', company: A };

beforeEach(() => {
  mockDatabase = null;
  jest.useFakeTimers();
  jest.setSystemTime(new Date('2026-10-05T00:00:00Z'));
  mockExecFile.mockReset().mockImplementation((cmd, args, opts, callback) => callback(null, '@blocked_ipv4 @blocked_ipv6', ''));
  load();
});
afterEach(async () => {
  mockDatabase = null;
  await service.clearAllBlocks();
  jest.useRealTimers();
  jest.restoreAllMocks();
});

test('unblock never falls back to another tenant or another port/direction', async () => {
  await service.blockTarget({ ...target, port: 443, direction: 'inbound' });
  await service.unblockTarget({ ...target, company: B });
  await service.unblockTarget(target);
  expect(service.getBlocklist(A)).toHaveLength(1);
  expect(service.getBlocklist(B)).toHaveLength(0);
  expect(mockExecFile).not.toHaveBeenCalled();
});

test('exact unblock deletes only its own database record', async () => {
  await service.blockTarget({ ...target, port: 443 });
  await service.blockTarget({ ...target, port: 80 });
  const deleteOne = jest.fn().mockResolvedValue({ deletedCount: 1 });
  mockDatabase = { collection: () => ({ deleteOne }) };
  await service.unblockTarget({ ...target, port: 443 });
  expect(service.getBlocklist(A).map(entry => entry.port)).toEqual([80]);
  expect(deleteOne).toHaveBeenCalledWith({ company: A, blockKey: 'ip:203.0.113.100|port:443' });
});

test('refresh preserves delegated enforcement state', async () => {
  await service.blockTarget(target);
  expect(await service.blockTarget(target)).toMatchObject({ refreshed: true, method: 'endpoint-agent', delegated: true, enforced: false });
});

test('setting TTL to zero cancels a previous expiry', async () => {
  await service.blockTarget({ ...target, ttlHours: 1 });
  await service.blockTarget({ ...target, ttlHours: 0 });
  await jest.advanceTimersByTimeAsync(2 * 3600000);
  expect(service.getBlocklist(A)).toHaveLength(1);
  expect(service.getBlocklist(A)[0].expiresAt).toBeNull();
});

test('long TTL does not overflow and expires only after the full duration', async () => {
  await service.blockTarget({ ...target, ttlHours: 720 });
  await jest.advanceTimersByTimeAsync(2 ** 31);
  expect(service.getBlocklist(A)).toHaveLength(1);
  await jest.advanceTimersByTimeAsync(720 * 3600000 - 2 ** 31);
  expect(service.getBlocklist(A)).toHaveLength(0);
});

test('expiry preserves port ranges and does not remove another rule', async () => {
  await service.blockTarget({ ...target, port: '80-90', ttlHours: 1 });
  await service.blockTarget({ ...target, port: '80-100', ttlHours: 2 });
  await jest.advanceTimersByTimeAsync(3600000);
  expect(service.getBlocklist(A).map(entry => entry.portEnd)).toEqual([100]);
});

test('concurrent repeated blocks create one record', async () => {
  const results = await Promise.all([service.blockTarget(target), service.blockTarget(target)]);
  expect(service.getBlocklist(A)).toHaveLength(1);
  expect(results[1].refreshed).toBe(true);
});

test('IPv6 equivalent spellings share a single key', async () => {
  await service.blockTarget({ ...target, ip: '2001:0db8:0:0:0:0:0:1' });
  await service.unblockTarget({ ...target, ip: '2001:db8::1' });
  expect(service.getBlocklist(A)).toHaveLength(0);
});

test.each(['1:2:3', '1.2.3.4/99', '2001:db8::/129', ':::', '1.2.3.999', '1.2.3.4/'])('rejects invalid IP/CIDR %s', ip => {
  expect(service.isValidIP(ip)).toBe(false);
});

test('Windows firewall failures are not reported as successful blocks', async () => {
  load('windows-defender');
  mockExecFile.mockImplementation((cmd, args, opts, callback) => callback(new Error('denied'), '', 'Access denied'));
  await expect(service.blockTarget(target)).rejects.toThrow('Access denied');
  expect(service.getBlocklist(A)).toHaveLength(0);
});

test('nftables setup failure is reported before adding a block', async () => {
  load('nftables');
  jest.spyOn(process, 'geteuid').mockReturnValue(0);
  mockExecFile.mockImplementation((cmd, args, opts, callback) => args[0] === '--version'
    ? callback(null, 'nft', '') : callback(new Error('denied'), '', 'Operation not permitted'));
  await expect(service.blockTarget(target)).rejects.toThrow('Operation not permitted');
  expect(service.getBlocklist(A)).toHaveLength(0);
});

test('unsupported host filters are rejected instead of silently blocking all traffic', async () => {
  load('nftables');
  await expect(service.blockTarget({ ...target, port: 443 })).rejects.toThrow('IP-only');
  await expect(service.blockTarget({ ...target, direction: 'outbound' })).rejects.toThrow('both directions');
  expect(mockExecFile).not.toHaveBeenCalled();
});

test('nftables retains another tenant reference until the last unblock', async () => {
  load('nftables');
  jest.spyOn(process, 'geteuid').mockReturnValue(0);
  await service.blockTarget(target);
  await service.blockTarget({ ...target, company: B });
  mockExecFile.mockClear();
  const result = await service.unblockTarget(target);
  expect(result.sharedRuleRetained).toBe(true);
  expect(mockExecFile).not.toHaveBeenCalled();
  await service.unblockTarget({ ...target, company: B });
  expect(mockExecFile.mock.calls.filter(([, args]) => args[0] === 'delete')).toHaveLength(1);
});

test('failed expiry cleanup retains the rule and retries', async () => {
  load('nftables');
  jest.spyOn(process, 'geteuid').mockReturnValue(0);
  await service.blockTarget({ ...target, ttlHours: 1 });
  mockExecFile.mockImplementation((cmd, args, opts, callback) => callback(new Error('denied'), '', 'Access denied'));
  await jest.advanceTimersByTimeAsync(3600000);
  expect(service.getBlocklist(A)).toHaveLength(1);
  mockExecFile.mockImplementation((cmd, args, opts, callback) => callback(null, '', ''));
  await jest.advanceTimersByTimeAsync(5 * 60000);
  expect(service.getBlocklist(A)).toHaveLength(0);
});
