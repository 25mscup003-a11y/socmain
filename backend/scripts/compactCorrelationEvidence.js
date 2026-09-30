require('dotenv').config();
const mongoose = require('mongoose');
const CorrelationEvent = require('../src/models/CorrelationEvent.model');
const {
  PATTERNS, matchPatternAlerts, matchSignature, alertTimeline, extractIocs,
} = require('../src/services/correlation.service');

async function main() {
  await mongoose.connect(process.env.MONGO_URI);
  const patternMap = new Map(PATTERNS.map(pattern => [pattern.id, pattern]));
  const incidents = await CorrelationEvent.find({}).populate('alertIds');

  let compacted = 0;
  let backfilled = 0;
  let suppressed = 0;
  for (const incident of incidents) {
    const pattern = patternMap.get(incident.patternId);
    if (!pattern) continue;
    const originalAlerts = (incident.alertIds || []).filter(Boolean);
    const exactMatch = matchPatternAlerts(originalAlerts, pattern);
    const retained = exactMatch.length === pattern.requires.length
      ? exactMatch
      : originalAlerts.slice(0, pattern.requires.length);
    const removed = Math.max(0, originalAlerts.length - retained.length);
    if (removed > 0) {
      incident.alertIds = retained.map(alert => alert._id);
      incident.timeline = alertTimeline(retained);
      incident.evidence = retained.map(alert => ({
        alertId: alert._id, ruleId: alert.ruleId, source: alert.source, observedAt: alert.createdAt,
      }));
      incident.iocs = extractIocs(retained);
      incident.eventCount = retained.length;
      incident.suppressedDuplicateCount = Number(incident.suppressedDuplicateCount || 0) + removed;
      incident.resolutionHistory.push({
        status: 'evidence_compacted',
        notes: `Removed ${removed} scheduler-duplicate links; retained the exact ${retained.length}-event evidence chain.`,
        changedAt: new Date(),
      });
      compacted += 1;
      suppressed += removed;
    }
    if (!(incident.relatedAlertIds || []).length) {
      incident.relatedAlertIds = retained.map(alert => alert._id);
      backfilled += 1;
    }
    if (!incident.occurrenceCount || incident.occurrenceCount < 1) incident.occurrenceCount = 1;
    if (!incident.lastMatchSignature && retained.length === pattern.requires.length) {
      incident.lastMatchSignature = matchSignature(pattern, retained);
    }
    await incident.save();
  }

  console.log(JSON.stringify({ scanned: incidents.length, compacted, backfilled, suppressed }));
  await mongoose.disconnect();
}

main().catch(async error => {
  console.error(error);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
