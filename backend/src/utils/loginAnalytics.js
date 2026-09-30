const mongoose = require('mongoose');

function companyLoginScope(companyId) {
  if (!companyId || !mongoose.Types.ObjectId.isValid(companyId)) return null;
  return { companyId: new mongoose.Types.ObjectId(String(companyId)) };
}

function transformLoginActionCounts(rows = []) {
  const counts = {
    login_success: 0,
    login_failed: 0,
    logout: 0,
    otp_verified: 0,
    otp_failed: 0,
  };
  for (const row of rows) {
    if (row?._id) counts[row._id] = Number(row.count || 0);
  }
  return counts;
}

module.exports = { companyLoginScope, transformLoginActionCounts };
