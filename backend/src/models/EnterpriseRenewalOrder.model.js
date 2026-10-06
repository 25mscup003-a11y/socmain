const mongoose = require('mongoose');
const EnterpriseOrder = require('./EnterpriseOrder.model');

const schema = EnterpriseOrder.schema.clone();
schema.clearIndexes();
schema.add({
  kind: { type: String, enum: ['renewal'], default: 'renewal' },
  renewalBatchId: { type: mongoose.Schema.Types.ObjectId, ref: 'AddSystemSubscription', required: true },
  renewFrom: { type: Date, required: true },
  priceKey: { type: String, required: true },
});
// Concurrent checkouts for the same subscription period share one order.
schema.index({ companyId: 1, renewalBatchId: 1, renewFrom: 1 }, { unique: true });
module.exports = mongoose.model('EnterpriseRenewalOrder', schema);
