require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const mongoose = require('mongoose');
const Alert = require('../src/models/Alert.model');
const Log = require('../src/models/Log.model');
const CorrelationEvent = require('../src/models/CorrelationEvent.model');
const EdrIncident = require('../src/models/EdrIncident.model');
const System = require('../src/models/System.model');

const args = new Set(process.argv.slice(2));
const valueArg = name => {
  const prefix = `${name}=`;
  const match = process.argv.slice(2).find(arg => arg.startsWith(prefix));
  return match ? match.slice(prefix.length) : '';
};

const confirm = args.has('--confirm');
const allCompanies = args.has('--all-companies');
const resetBaseline = args.has('--reset-baseline');
const companyId = valueArg('--companyId');

function usage() {
  console.log([
    'Usage:',
    '  node scripts/clear-fim-data.js --companyId=<companyId>',
    '  node scripts/clear-fim-data.js --companyId=<companyId> --confirm',
    '  node scripts/clear-fim-data.js --all-companies --confirm',
    '  node scripts/clear-fim-data.js --all-companies --confirm --reset-baseline',
    '',
    'Without --confirm this is a dry-run and only prints counts.',
  ].join('\n'));
}

function scoped(base = {}) {
  if (!companyId) return base;
  if (!mongoose.Types.ObjectId.isValid(companyId)) {
    throw new Error(`Invalid companyId: ${companyId}`);
  }
  return { ...base, companyId: new mongoose.Types.ObjectId(companyId) };
}

async function main() {
  const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://localhost:27017/soc4';
  if (!companyId && !allCompanies) {
    usage();
    throw new Error('Choose --companyId=<id> or --all-companies');
  }

  await mongoose.connect(mongoUri, {
    serverSelectionTimeoutMS: 15000,
    socketTimeoutMS: 45000,
    connectTimeoutMS: 15000,
  });

  const fimAlertQuery = scoped({
    $or: [
      { eventCategory: 'file' },
      { ruleId: /^FILE_/i },
      { source: 'file_watch' },
      { fileAction: { $exists: true, $ne: null } },
    ],
  });
  const fimLogQuery = scoped({
    $or: [
      { logType: 'file' },
      { 'fields.fileAction': { $exists: true } },
      { 'fields.file_action': { $exists: true } },
    ],
  });

  const [fimAlertIds, alertCount, logCount] = await Promise.all([
    Alert.find(fimAlertQuery).select('_id').lean(),
    Alert.countDocuments(fimAlertQuery),
    Log.countDocuments(fimLogQuery),
  ]);
  const alertIds = fimAlertIds.map(a => a._id);
  const alertIdQuery = alertIds.length ? { alertIds: { $in: alertIds } } : { _id: { $exists: false } };
  const correlationQuery = scoped(alertIdQuery);
  const incidentQuery = scoped(alertIdQuery);

  const [correlationCount, incidentCount] = await Promise.all([
    CorrelationEvent.countDocuments(correlationQuery),
    EdrIncident.countDocuments(incidentQuery),
  ]);

  console.log(JSON.stringify({
    mode: confirm ? 'delete' : 'dry-run',
    scope: companyId ? { companyId } : { allCompanies: true },
    resetBaseline,
    counts: {
      fimAlerts: alertCount,
      fileLogs: logCount,
      correlationEventsReferencingFimAlerts: correlationCount,
      incidentsReferencingFimAlerts: incidentCount,
    },
  }, null, 2));

  if (!confirm) return;

  const systemQuery = scoped({ isActive: true });
  const [baseline, correlations, incidents, logs, alerts] = await Promise.all([
    resetBaseline ? System.updateMany(systemQuery, [{ $set: { fimStartAt: { $ifNull: ['$installDate', '$createdAt'] } } }]) : Promise.resolve({ modifiedCount: 0 }),
    CorrelationEvent.deleteMany(correlationQuery),
    EdrIncident.deleteMany(incidentQuery),
    Log.deleteMany(fimLogQuery),
    Alert.deleteMany(fimAlertQuery),
  ]);

  console.log(JSON.stringify({
    resetBaseline: resetBaseline ? 'fimStartAt reset to installDate/createdAt' : null,
    deleted: {
      fimAlerts: alerts.deletedCount || 0,
      fileLogs: logs.deletedCount || 0,
      correlationEvents: correlations.deletedCount || 0,
      incidents: incidents.deletedCount || 0,
    },
    updated: {
      systemsFimStartAt: baseline.modifiedCount || 0,
    },
  }, null, 2));
}

main()
  .catch(err => {
    console.error(err.message);
    process.exitCode = 1;
  })
  .finally(() => mongoose.disconnect());
