require('dotenv').config();
const mongoose = require('mongoose');
const Alert = require('../src/models/Alert.model');
const CorrelationEvent = require('../src/models/CorrelationEvent.model');
const { syncIncident } = require('../src/services/correlation.service');

async function run() {
  await mongoose.connect(process.env.MONGO_URI);
  const correlations = await CorrelationEvent.find({}).select('_id patternId alertIds relatedAlertIds riskScore').lean();
  let threatIntelligence = 0;
  let edr = 0;
  for (const row of correlations) {
    const evidenceIds = row.relatedAlertIds?.length ? row.relatedAlertIds : row.alertIds;
    const hasTiEvidence = ['MALICIOUS_LOGIN', 'ZEEK_IOC_MATCH'].includes(row.patternId)
      || await Alert.exists({ _id: { $in: evidenceIds || [] }, $or: [{ iocMatched: true }, { sourceType: 'THREAT_FEED' }, { capabilityIds: 29 }, { vtVerdict: { $in: ['malicious', 'suspicious'] } }] });
    const incidentSource = hasTiEvidence ? 'threat_intelligence' : 'edr';
    const correlation = await CorrelationEvent.findByIdAndUpdate(row._id, {
      $set: { incidentSource, ...(hasTiEvidence ? { riskScore: Math.max(85, Number(row.riskScore || 0)) } : {}) },
    }, { new: true });
    await syncIncident(correlation);
    if (hasTiEvidence) threatIntelligence += 1; else edr += 1;
  }
  await mongoose.disconnect();
  console.log(`Routed correlations: threat_intelligence=${threatIntelligence}, edr=${edr}`);
}

run().catch(async error => { console.error(error); await mongoose.disconnect(); process.exitCode = 1; });
