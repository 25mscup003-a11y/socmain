/**
 * Seed Default Fraud Rules
 * Called once from server.js on startup to populate baseline rules
 * if no rules exist yet. Safe to call multiple times (idempotent).
 */
const FraudRule = require('../src/models/FraudRule.model');

const DEFAULT_RULES = [
  {
    name: 'Critical Risk Score — Block',
    description: 'Block any request with a risk score >= 90',
    conditionField: 'riskScore', conditionOperator: 'gte', conditionValue: 90,
    action: 'BLOCK', severity: 'critical', priority: 100, isBuiltIn: true,
  },
  {
    name: 'High Risk Score — Challenge',
    description: 'Challenge logins with risk score >= 70',
    conditionField: 'riskScore', conditionOperator: 'gte', conditionValue: 70,
    action: 'CHALLENGE', severity: 'high', priority: 90, isBuiltIn: true,
  },
  {
    name: 'TOR Network — Block',
    description: 'Block all connections through the Tor anonymity network',
    conditionField: 'isTor', conditionOperator: 'is_true', conditionValue: true,
    action: 'BLOCK', severity: 'critical', priority: 99, isBuiltIn: true,
  },
  {
    name: 'VPN Detected — Challenge',
    description: 'Challenge logins from detected VPN endpoints',
    conditionField: 'isVpn', conditionOperator: 'is_true', conditionValue: true,
    action: 'CHALLENGE', severity: 'medium', priority: 80, isBuiltIn: true,
  },
  {
    name: 'Proxy Detected — Challenge',
    description: 'Challenge requests routed through proxy servers',
    conditionField: 'isProxy', conditionOperator: 'is_true', conditionValue: true,
    action: 'CHALLENGE', severity: 'medium', priority: 80, isBuiltIn: true,
  },
  {
    name: 'Bot Activity — Block',
    description: 'Block automated bot traffic',
    conditionField: 'isBot', conditionOperator: 'is_true', conditionValue: true,
    action: 'BLOCK', severity: 'high', priority: 95, isBuiltIn: true,
  },
  {
    name: 'New Device + New Country — Challenge',
    description: 'Challenge when a login comes from an unrecognized device AND a new country',
    conditionField: 'isNewDevice', conditionOperator: 'is_true', conditionValue: true,
    action: 'CHALLENGE', severity: 'medium', priority: 70, isBuiltIn: true,
  },
  {
    name: 'High Velocity Login — Block',
    description: 'Block when 5+ login attempts occur within 5 minutes from same IP/email',
    conditionField: 'velocity', conditionOperator: 'gte', conditionValue: 5,
    action: 'BLOCK', severity: 'high', priority: 92, isBuiltIn: true,
  },
  {
    name: 'Multiple Accounts — Alert',
    description: 'Alert when the same device fingerprint is used across multiple accounts',
    conditionField: 'multipleAccounts', conditionOperator: 'is_true', conditionValue: true,
    action: 'ALERT', severity: 'high', priority: 75, isBuiltIn: true,
  },
];

async function seedFraudRules() {
  try {
    const existing = await FraudRule.countDocuments({ isBuiltIn: true });
    if (existing >= DEFAULT_RULES.length) {
      console.log(`[FraudRules] ${existing} built-in rules already seeded — skipping`);
      return;
    }

    let seeded = 0;
    for (const rule of DEFAULT_RULES) {
      await FraudRule.findOneAndUpdate(
        { name: rule.name },
        { $setOnInsert: { ...rule, isActive: true } },
        { upsert: true }
      );
      seeded++;
    }
    console.log(`✅ [FraudRules] Seeded ${seeded} default fraud rules`);
  } catch (err) {
    console.error('⚠️  [FraudRules] Seed error:', err.message);
  }
}

module.exports = seedFraudRules;
