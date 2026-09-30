require('dotenv').config();
const mongoose = require('mongoose');
const Alert = require('../src/models/Alert.model');
const CorrelationEvent = require('../src/models/CorrelationEvent.model');
const EdrIncident = require('../src/models/EdrIncident.model');
const { normalizeSecurityEvent, calculateSecurityRisk } = require('../src/utils/securityEventNormalizer');
const { syncIncident } = require('../src/services/correlation.service');

async function run() {
  await mongoose.connect(process.env.MONGO_URI);
  const legacyCategoryResult = await Alert.updateMany(
    { eventCategory: { $in: ['dns', 'web', 'http', 'https', 'ssl', 'tls', 'ids', 'ips', 'zeek'] } },
    [{ $set: { subCategory: { $ifNull: ['$subCategory', '$eventCategory'] }, eventCategory: 'network' } }],
  );
  const cursor = Alert.find({ sourceType: { $exists: false }, rawEvent: { $type: 'object' } }).cursor();
  let updated = 0;
  for await (const alert of cursor) {
    const normalized = normalizeSecurityEvent({ ...alert.rawEvent, severity: alert.severity });
    if (!normalized.sourceType) continue;
    Object.assign(alert, normalized);
    alert.riskScore = alert.riskScore || calculateSecurityRisk(alert);
    await alert.save();
    updated += 1;
  }
  let threatIncidentCount = 0;
  const correlations = CorrelationEvent.find({}).select('_id patternId alertIds relatedAlertIds').cursor();
  for await (const correlation of correlations) {
    const evidenceIds = correlation.relatedAlertIds?.length ? correlation.relatedAlertIds : correlation.alertIds;
    const hasThreatIntelEvidence = ['MALICIOUS_LOGIN', 'ZEEK_IOC_MATCH'].includes(correlation.patternId)
      || await Alert.exists({ _id: { $in: evidenceIds || [] }, $or: [{ iocMatched: true }, { sourceType: 'THREAT_FEED' }] });
    const incidentSource = hasThreatIntelEvidence ? 'threat_intelligence' : 'edr';
    await CorrelationEvent.updateOne({ _id: correlation._id }, { $set: { incidentSource, ...(incidentSource === 'threat_intelligence' ? { riskScore: Math.max(85, Number(correlation.riskScore || 0)) } : {}) } });
    const currentCorrelation = await CorrelationEvent.findById(correlation._id);
    if (currentCorrelation) await syncIncident(currentCorrelation);
    const result = await EdrIncident.updateMany({ correlationId: correlation._id }, { $set: { incidentSource } });
    if (incidentSource === 'threat_intelligence') threatIncidentCount += result.modifiedCount || 0;
  }
  // createIndexes is additive: it never drops an operational index that may
  // have been created outside this application version.
  await Alert.createIndexes();
  console.log(`Normalized ${updated} security alerts, ${legacyCategoryResult.modifiedCount || 0} legacy network categories, and routed ${threatIncidentCount} threat-intelligence incidents; indexes created.`);
  await mongoose.disconnect();
}

run().catch(async err => { console.error(err); await mongoose.disconnect(); process.exitCode = 1; });
