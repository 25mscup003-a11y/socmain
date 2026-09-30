const SoarRule = require('../models/SoarRule.model');
const ResponsePlaybook = require('../models/ResponsePlaybook.model');

function evalSimulatorCondition(eventData, condition) {
  const val = eventData[condition.field] !== undefined ? eventData[condition.field] : '';
  const ref = condition.value;
  const strVal = String(val || '').toLowerCase();
  const strRef = String(ref || '').toLowerCase();

  switch (condition.operator) {
    case 'eq':
      return String(val) === String(ref);
    case 'neq':
      return String(val) !== String(ref);
    case 'gt':
      return Number(val) > Number(ref);
    case 'gte':
      return Number(val) >= Number(ref);
    case 'lt':
      return Number(val) < Number(ref);
    case 'lte':
      return Number(val) <= Number(ref);
    case 'contains':
      return strVal.includes(strRef);
    case 'not_contains':
      return !strVal.includes(strRef);
    case 'starts_with':
      return strVal.startsWith(strRef);
    case 'ends_with':
      return strVal.endsWith(strRef);
    case 'in':
      return Array.isArray(ref) && ref.map(String).includes(String(val));
    case 'not_in':
      return Array.isArray(ref) && !ref.map(String).includes(String(val));
    case 'exists':
      return val !== undefined && val !== null && val !== '';
    case 'does_not_exist':
      return val === undefined || val === null || val === '';
    case 'matches_regex':
      try {
        const regex = new RegExp(ref, 'i');
        return regex.test(String(val));
      } catch {
        return false;
      }
    case 'cidr_contains':
      // Simplified CIDR check (or prefix match)
      return strVal.startsWith(strRef.split('/')[0]);
    default:
      return false;
  }
}

/**
 * Dry-run simulation of a rule or playbook against an event payload
 */
async function simulateRuleExecution({ ruleId, playbookId, eventPayload, companyId, rule: suppliedRule, playbook: suppliedPlaybook }) {
  const startTime = Date.now();
  let rule = suppliedRule || null;
  let playbook = suppliedPlaybook || null;

  if (ruleId) {
    rule = await SoarRule.findById(ruleId);
  }
  if (playbookId) {
    playbook = await ResponsePlaybook.findById(playbookId);
  }

  const conditions = (rule?.conditions || playbook?.conditions || []);
  const conditionResults = [];
  let allMatched = true;

  for (const cond of conditions) {
    const matched = evalSimulatorCondition(eventPayload, cond);
    conditionResults.push({
      field: cond.field,
      operator: cond.operator,
      expectedValue: cond.value,
      actualValue: eventPayload[cond.field],
      matched,
    });
    if (!matched) {
      allMatched = false;
    }
  }

  const actions = (rule?.actions || playbook?.steps || []);
  const proposedActions = [];
  const approvalRequirements = [];

  for (const act of actions) {
    const actionType = act.type || act.actionType;
    const requireApproval = act.requireApproval || ['isolate_agent', 'block_ip', 'disable_user', 'kill_process', 'delete_file'].includes(actionType);
    
    proposedActions.push({
      type: actionType,
      payload: act.payload || act.actionParams || {},
      status: allMatched ? (requireApproval ? 'would_pause_for_approval' : 'would_execute') : 'skipped_condition_failed',
      riskLevel: act.riskLevel || (requireApproval ? 'high' : 'low'),
    });

    if (allMatched && requireApproval) {
      approvalRequirements.push({
        actionType,
        requiredRole: act.requiredRole || 'soc_manager',
        reason: `High risk action ${actionType} requires human confirmation.`,
      });
    }
  }

  const durationMs = Date.now() - startTime;

  return {
    ruleName: rule?.name || playbook?.name || 'Simulation Rule',
    overallMatch: allMatched,
    conditionCount: conditions.length,
    matchedConditionsCount: conditionResults.filter(c => c.matched).length,
    conditionResults,
    proposedActions,
    approvalRequirements,
    estimatedDurationMs: Math.max(durationMs, 120),
    transformedVariables: {
      alertDescription: eventPayload.description || 'Simulated Security Event',
      sourceIp: eventPayload.srcip || eventPayload.sourceIp || '192.168.1.100',
      severity: eventPayload.severity || 'high',
    },
    warnings: allMatched && proposedActions.length === 0 ? ['Rule matches but no actions configured'] : [],
  };
}

module.exports = {
  evalSimulatorCondition,
  simulateRuleExecution,
};
