const EnterpriseOrder = require('../models/EnterpriseOrder.model');
const EnterpriseAdditionOrder = require('../models/EnterpriseAdditionOrder.model');

module.exports = async function enterprisePaymentIsolation(req, res, next) {
  const id = req.body?.razorpay_order_id;
  if (req.method !== 'POST' || !id) return next();
  if (typeof id !== 'string') return res.status(400).json({ message: 'Invalid payment order.' });
  try {
    if (await EnterpriseOrder.exists({ razorpayOrderId: id }) || await EnterpriseAdditionOrder.exists({ razorpayOrderId: id })) {
      return res.status(400).json({ message: 'Use Enterprise checkout to confirm this payment.' });
    }
    next();
  } catch {
    res.status(503).json({ message: 'Unable to verify the payment order. Please retry.' });
  }
};
