const { describe, it } = require('node:test');
const assert = require('node:assert');
process.env.SOAR_VAULT_SECRET ||= 'unit-test-only-soar-vault-secret';
const { evalCondition, ruleMatches, executeActionHandler } = require('../src/services/soar.service');
const { isSafeUrl, encryptSecret, decryptSecret } = require('../src/services/soarConnector.service');
const { evalSimulatorCondition } = require('../src/services/soarSimulator.service');
const { isShiftActiveAt } = require('../src/services/soarEmailRecipients.service');
const {
  ticketCategoryFor, isIdsIpsFirewallTicket, ticketAssignmentRoles, rankEligibleAnalysts,
} = require('../src/services/socTicketAssignment.service');
const { isTicketAlert } = require('../src/services/socCaseExclusivity.service');

describe('SOAR Engine — Unit Tests', () => {

  it('should evaluate equality and containment conditions correctly', () => {
    const alert = { severity: 'high', srcip: '192.168.1.50', description: 'Suricata Alert Malware' };

    assert.strictEqual(evalCondition(alert, { field: 'severity', operator: 'eq', value: 'high' }), true);
    assert.strictEqual(evalCondition(alert, { field: 'severity', operator: 'neq', value: 'low' }), true);
    assert.strictEqual(evalCondition(alert, { field: 'description', operator: 'contains', value: 'malware' }), true);
    assert.strictEqual(evalCondition(alert, { field: 'severity', operator: 'in', value: ['high', 'critical'] }), true);
    assert.strictEqual(evalCondition(alert, { field: 'severity', operator: 'eq', value: 'low' }), false);
  });

  it('should evaluate rule matching logic correctly', () => {
    const alert = { severity: 'critical', srcip: '10.0.0.5' };
    const rule = {
      conditionLogic: 'AND',
      conditions: [
        { field: 'severity', operator: 'eq', value: 'critical' },
        { field: 'srcip', operator: 'contains', value: '10.0' },
      ],
    };

    assert.strictEqual(ruleMatches(alert, rule), true);
  });

  it('should prevent SSRF against restricted metadata IP targets', () => {
    assert.strictEqual(isSafeUrl('http://169.254.169.254/latest/meta-data'), false);
    assert.strictEqual(isSafeUrl('http://127.0.0.1:8080/admin'), false);
    assert.strictEqual(isSafeUrl('http://localhost:3000/api'), false);
    assert.strictEqual(isSafeUrl('https://api.virustotal.com/v3/ip_addresses'), true);
  });

  it('should encrypt and decrypt secrets in credential vault using AES-256-GCM', () => {
    const secret = 'super-secret-api-token-2026';
    const encrypted = encryptSecret(secret);
    
    assert.ok(encrypted.encryptedValue);
    assert.ok(encrypted.iv);
    assert.ok(encrypted.authTag);

    const decrypted = decryptSecret(encrypted.encryptedValue, encrypted.iv, encrypted.authTag);
    assert.strictEqual(decrypted, secret);
  });

  it('should dry-run simulate rule conditions correctly', () => {
    const event = { description: 'Unauthorized Admin Login', severity: 'high' };
    const cond = { field: 'severity', operator: 'eq', value: 'high' };

    const result = evalSimulatorCondition(event, cond);
    assert.strictEqual(result, true);
  });

  it('should fail closed for actions without a real handler', async () => {
    await assert.rejects(
      executeActionHandler({ _id: 'alert', companyId: 'company' }, { type: 'kill_process', payload: {} }, {}),
      /not implemented/,
    );
  });

  it('should match normal and overnight SOC shifts in their configured timezone', () => {
    const weekdayShift = { timezone: 'UTC', startTime: '09:00', endTime: '17:00', weekdays: [1] };
    assert.strictEqual(isShiftActiveAt(weekdayShift, new Date('2026-08-10T10:00:00Z')), true);
    assert.strictEqual(isShiftActiveAt(weekdayShift, new Date('2026-08-10T18:00:00Z')), false);

    const overnightShift = { timezone: 'UTC', startTime: '22:00', endTime: '06:00', weekdays: [1] };
    assert.strictEqual(isShiftActiveAt(overnightShift, new Date('2026-08-10T23:00:00Z')), true);
    assert.strictEqual(isShiftActiveAt(overnightShift, new Date('2026-08-11T03:00:00Z')), true);
    assert.strictEqual(isShiftActiveAt(overnightShift, new Date('2026-08-11T07:00:00Z')), false);
  });

  it('should classify Threat Intelligence tickets for exclusive L4 routing', () => {
    assert.strictEqual(ticketCategoryFor({ sourceType: 'THREAT_FEED', severity: 'low' }), 'threat_intelligence');
    assert.strictEqual(ticketCategoryFor({ iocMatched: true, severity: 'critical' }), 'threat_intelligence');
    assert.strictEqual(ticketCategoryFor({ sourceType: 'IDS', eventCategory: 'network' }), 'network');
  });

  it('should route IDS, IPS and Firewall tickets only to SOC Manager or L4', () => {
    for (const ticket of [
      { sourceType: 'IDS' },
      { module: 'IPS' },
      { source: 'suricata' },
      { source_type: 'network_firewall' },
    ]) {
      assert.strictEqual(isIdsIpsFirewallTicket(ticket), true);
      assert.deepStrictEqual(ticketAssignmentRoles(ticket), ['soc_manager', 'l4_analyst']);
    }
    assert.deepStrictEqual(ticketAssignmentRoles({ sourceType: 'EDR', severity: 'high' }), ['l2_analyst']);
  });

  it('should identify ticket disposition before incident creation', () => {
    assert.strictEqual(isTicketAlert({ ticketOpenedAt: new Date() }), true);
    assert.strictEqual(isTicketAlert({ ticketSource: 'soar' }), true);
    assert.strictEqual(isTicketAlert({ socCaseType: 'ticket' }), true);
    assert.strictEqual(isTicketAlert({ socCaseType: 'incident' }), false);
  });

  it('should prefer the lowest same-category workload before total workload', () => {
    const analysts = [{ _id: 'b' }, { _id: 'a' }, { _id: 'c' }];
    const category = new Map([['a', 2], ['b', 1], ['c', 1]]);
    const total = new Map([['a', 2], ['b', 5], ['c', 3]]);
    assert.strictEqual(String(rankEligibleAnalysts(analysts, category, total)[0]._id), 'c');
  });

});
