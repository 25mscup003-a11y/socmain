const mongoose = require('mongoose');
require('dotenv').config();

const AutomatedResponse = require('../src/models/AutomatedResponse.model');
const Company = require('../src/models/Company.model');
const SoarAuditLog = require('../src/models/SoarAuditLog.model');
const SoarExecution = require('../src/models/SoarExecution.model');
const SoarLog = require('../src/models/SoarLog.model');
const SoarRule = require('../src/models/SoarRule.model');
const User = require('../src/models/User.model');

const APPLY = process.argv.includes('--apply');
const FINAL_STATUSES = ['completed', 'partially_completed', 'failed', 'cancelled', 'rolled_back'];

async function main() {
  await mongoose.connect(process.env.MONGO_URI || process.env.MONGODB_URI);
  const staleBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const staleFilter = {
    status: 'waiting_approval', approvalStatus: 'pending',
    $or: [{ expiresAt: { $lte: new Date() } }, { expiresAt: null, createdAt: { $lte: staleBefore } }],
  };
  const staleResponses = await AutomatedResponse.find(staleFilter).select('_id companyId actionType correlationId').lean();
  const finalExecutions = await SoarExecution.find({ status: { $in: FINAL_STATUSES } }).lean();
  const finalIds = finalExecutions.map(item => String(item._id));
  const existingAuditIds = new Set((await SoarAuditLog.find({
    correlationId: { $in: finalIds }, action: 'SOAR_EXECUTION_BACKFILLED',
  }).distinct('correlationId')).map(String));
  const missingExecutions = finalExecutions.filter(item => !existingAuditIds.has(String(item._id)));
  const companies = await Company.find({ status: { $in: ['active', 'trial'] } }).select('_id tenantId partnerId').lean();
  const ruleId = 'default-critical-alert-triage-v1';
  const existingRules = await SoarRule.countDocuments({ ruleId, companyId: { $in: companies.map(item => item._id) } });

  const summary = {
    mode: APPLY ? 'apply' : 'dry-run',
    staleEndpointApprovals: staleResponses.length,
    missingExecutionLogs: missingExecutions.length,
    eligibleCompanies: companies.length,
    activeRulesToCreate: Math.max(0, companies.length - existingRules),
  };
  console.log(JSON.stringify(summary, null, 2));
  if (!APPLY) return;

  if (staleResponses.length) {
    const ids = staleResponses.map(item => item._id);
    await AutomatedResponse.updateMany({ _id: { $in: ids } }, {
      $set: { status: 'cancelled', approvalStatus: 'expired', completedAt: new Date(), errorDetail: 'Approval expired before resolution' },
      $push: { auditTrail: { status: 'cancelled', message: 'Approval expired automatically during SOAR repair' } },
    });
    await SoarAuditLog.insertMany(staleResponses.map(item => ({
      companyId: item.companyId, action: 'SOAR_ENDPOINT_APPROVAL_EXPIRED',
      resourceType: 'AutomatedResponse', resourceId: String(item._id),
      correlationId: item.correlationId || String(item._id), result: 'failure',
      message: `${item.actionType} approval expired during backlog repair`,
    })));
  }

  for (const execution of missingExecutions) {
    if (execution.alertId && execution.ruleId) {
      await SoarLog.create({
        companyId: execution.companyId, alertId: execution.alertId, ruleId: execution.ruleId,
        ruleName: execution.ruleName,
        actionsRun: (execution.steps || []).map(step => step.actionType),
        results: (execution.steps || []).map(step => ({
          action: step.actionType, success: step.status === 'completed',
          detail: step.output?.detail || step.errorMessage || step.status,
        })),
        error: execution.errorMessage || '',
      });
    }
    await SoarAuditLog.create({
      tenantId: execution.tenantId || null, partnerId: execution.partnerId || null,
      companyId: execution.companyId, departmentId: execution.departmentId || null,
      action: 'SOAR_EXECUTION_BACKFILLED', resourceType: 'SoarExecution',
      resourceId: String(execution._id), correlationId: String(execution._id),
      result: ['failed', 'cancelled'].includes(execution.status) ? 'failure' : 'success',
      message: `Historical SOAR execution log restored (${execution.status})`,
    });
  }

  for (const company of companies) {
    const owner = await User.findOne({ companyId: company._id, role: { $in: ['company_admin', 'soc_manager'] }, isActive: true }).select('_id').lean();
    await SoarRule.updateOne({ companyId: company._id, ruleId }, { $setOnInsert: {
      tenantId: company.tenantId || null, partnerId: company.partnerId || null,
      companyId: company._id, ruleId,
      name: 'Critical Alert Safe Triage',
      description: 'Safely marks critical alerts as investigating, assigns an analyst, and notifies the SOC manager.',
      category: 'Triage', triggerType: 'new_alert', conditionLogic: 'AND',
      conditions: [{ field: 'severity', operator: 'eq', value: 'critical' }],
      actions: [
        { type: 'set_alert_status', payload: { status: 'investigating' }, riskLevel: 'low' },
        { type: 'assign_alert', payload: {}, riskLevel: 'low' },
        { type: 'notify_soc_manager', payload: {}, riskLevel: 'low' },
      ],
      executionMode: 'automatic', enabled: true, status: 'active', priority: 10,
      stopOnMatch: false, createdBy: owner?._id || null,
      safetyPolicy: { requireApprovalForDestructive: true },
    } }, { upsert: true });
  }
  console.log('SOAR operational repair completed.');
}

main().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => mongoose.disconnect());
