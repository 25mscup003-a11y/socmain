const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');

function isTicketAlert(alert = {}) {
  return alert.socCaseType === 'ticket'
    || Boolean(alert.ticketOpenedAt)
    || alert.ticketSource === 'soar';
}

async function claimAlertForTicket(alertId, companyId) {
  const existingIncident = await EdrIncident.findOne({
    companyId,
    alertIds: alertId,
  }).select('_id').lean();
  if (existingIncident) {
    await Alert.updateOne(
      { _id: alertId, companyId, socCaseType: { $ne: 'ticket' } },
      { $set: { socCaseType: 'incident', socCaseTypeSetAt: new Date() } },
    );
    return { claimed: false, reason: 'incident_exists', incidentId: existingIncident._id };
  }

  const alert = await Alert.findOneAndUpdate(
    {
      _id: alertId,
      companyId,
      $or: [
        { socCaseType: 'ticket' },
        { socCaseType: null },
        { socCaseType: { $exists: false } },
      ],
    },
    { $set: { socCaseType: 'ticket', socCaseTypeSetAt: new Date() } },
    { new: true },
  );
  return alert
    ? { claimed: true, alert }
    : { claimed: false, reason: 'incident_claimed' };
}

async function claimAlertsForIncident(alertIds, companyId) {
  const ids = [...new Set((alertIds || []).filter(Boolean).map(String))];
  if (!ids.length) return { claimedIds: [], rejectedIds: [] };

  await Alert.updateMany(
    {
      _id: { $in: ids },
      companyId,
      ticketOpenedAt: null,
      ticketSource: { $ne: 'soar' },
      $or: [
        { socCaseType: 'incident' },
        { socCaseType: null },
        { socCaseType: { $exists: false } },
      ],
    },
    { $set: { socCaseType: 'incident', socCaseTypeSetAt: new Date() } },
  );

  const claimed = await Alert.find({
    _id: { $in: ids },
    companyId,
    socCaseType: 'incident',
    ticketOpenedAt: null,
    ticketSource: { $ne: 'soar' },
  }).select('_id').lean();
  const claimedSet = new Set(claimed.map(item => String(item._id)));
  return {
    claimedIds: ids.filter(id => claimedSet.has(id)),
    rejectedIds: ids.filter(id => !claimedSet.has(id)),
  };
}

module.exports = {
  isTicketAlert,
  claimAlertForTicket,
  claimAlertsForIncident,
};
