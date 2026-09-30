require('dotenv').config();
const mongoose = require('mongoose');
const Alert = require('../src/models/Alert.model');
const CorrelationEvent = require('../src/models/CorrelationEvent.model');
const {
  isRansomwareImpact,
  isSuspiciousExecution,
  isSuspiciousOutbound,
} = require('../src/services/correlation.service');

function hasValidOrderedChain(alerts) {
  const ordered = alerts.slice().sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const predicates = [isSuspiciousExecution, isRansomwareImpact, isSuspiciousOutbound];
  let after = 0;
  for (const predicate of predicates) {
    const hit = ordered.find(alert => new Date(alert.createdAt).getTime() >= after && predicate(alert));
    if (!hit) return false;
    after = new Date(hit.createdAt).getTime();
  }
  return true;
}

async function main() {
  await mongoose.connect(process.env.MONGO_URI);
  const incidents = await CorrelationEvent.find({
    patternId: 'RANSOMWARE_CHAIN',
    status: { $in: ['open', 'investigating'] },
  }).populate('alertIds');
  let reclassified = 0;
  for (const incident of incidents) {
    if (hasValidOrderedChain(incident.alertIds || [])) continue;
    incident.status = 'false_positive';
    incident.resolvedAt = new Date();
    incident.notes = 'Automatically reclassified: legacy ransomware rule matched routine file/system/network telemetry without verified impact, suspicious execution and high-risk outbound C2 evidence.';
    incident.resolutionHistory.push({
      status: 'false_positive',
      notes: incident.notes,
      changedAt: new Date(),
    });
    await incident.save();
    reclassified += 1;
  }
  console.log(JSON.stringify({ scanned: incidents.length, reclassified }));
  await mongoose.disconnect();
}

main().catch(async error => {
  console.error(error);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
