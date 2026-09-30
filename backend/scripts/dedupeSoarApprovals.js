require('dotenv').config();
const mongoose = require('mongoose');
const SoarApproval = require('../src/models/SoarApproval.model');
const SoarExecution = require('../src/models/SoarExecution.model');

async function cancelExecutions(approvalIds, reason) {
  const approvals = await SoarApproval.find({ _id: { $in: approvalIds } }).select('executionId').lean();
  const executionIds = approvals.map(item => item.executionId).filter(Boolean);
  if (!executionIds.length) return 0;
  const result = await SoarExecution.updateMany(
    { _id: { $in: executionIds }, status: 'waiting_for_approval' },
    { $set: { status: 'cancelled', completedAt: new Date(), errorMessage: reason } },
  );
  return result.modifiedCount;
}

async function main() {
  await mongoose.connect(process.env.MONGO_URI);
  const now = new Date();
  const expired = await SoarApproval.find({ status: 'pending', expiresAt: { $lte: now } }).select('_id').lean();
  const expiredIds = expired.map(item => item._id);
  if (expiredIds.length) {
    await SoarApproval.updateMany(
      { _id: { $in: expiredIds } },
      { $set: { status: 'expired', resolvedAt: now, notes: 'Expired automatically during approval queue remediation' } },
    );
  }
  const expiredExecutions = await cancelExecutions(expiredIds, 'Approval expired before resolution');

  const groups = await SoarApproval.aggregate([
    { $match: { status: 'pending' } },
    { $sort: { createdAt: -1 } },
    { $group: {
      _id: { companyId: '$companyId', ruleId: '$ruleId', targetResource: '$targetResource' },
      ids: { $push: '$_id' },
      count: { $sum: 1 },
    } },
    { $match: { count: { $gt: 1 } } },
  ]);
  const duplicateIds = groups.flatMap(group => group.ids.slice(1));
  if (duplicateIds.length) {
    await SoarApproval.updateMany(
      { _id: { $in: duplicateIds } },
      { $set: { status: 'cancelled', resolvedAt: now, notes: 'Cancelled as duplicate pending approval' } },
    );
  }
  const duplicateExecutions = await cancelExecutions(duplicateIds, 'Duplicate approval execution cancelled');
  await SoarApproval.syncIndexes();
  const pending = await SoarApproval.countDocuments({ status: 'pending' });
  console.log(JSON.stringify({
    expiredApprovals: expiredIds.length,
    expiredExecutions,
    duplicateApprovals: duplicateIds.length,
    duplicateExecutions,
    pending,
  }));
  await mongoose.disconnect();
}

main().catch(async error => {
  console.error(error);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
