const mongoose = require('mongoose');
const EnterpriseOrder = require('./EnterpriseOrder.model');

// Same verified payment lifecycle, with a company-scoped checkout key instead
// of a quote revision: one quote can have several later license additions.
const schema = EnterpriseOrder.schema.clone();
schema.clearIndexes();
schema.index({ companyId: 1, purchaseKey: 1 }, { unique: true });
module.exports = mongoose.model('EnterpriseAdditionOrder', schema);
