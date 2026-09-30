require('dotenv').config();
const mongoose = require('mongoose');
const CorrelationEvent = require('../src/models/CorrelationEvent.model');
const { PATTERNS, matchPatternAlerts, matchSignature } = require('../src/services/correlation.service');

async function main() {
  await mongoose.connect(process.env.MONGO_URI);
  const patternMap = new Map(PATTERNS.map(pattern => [pattern.id, pattern]));
  const incidents = await CorrelationEvent.find({
    status: { $in: ['open', 'investigating'] },
  }).populate('alertIds');

  let valid = 0;
  let rejected = 0;
  for (const incident of incidents) {
    const pattern = patternMap.get(incident.patternId);
    const alerts = (incident.alertIds || []).filter(Boolean);
    const matched = pattern ? matchPatternAlerts(alerts, pattern) : [];
    if (pattern && matched.length === pattern.requires.length) {
      incident.lastMatchSignature = matchSignature(pattern, matched);
      incident.eventCount = Math.max(incident.eventCount || 0, matched.length);
      await incident.save();
      valid += 1;
      continue;
    }

    const note = 'Automatically rejected during correlation-rule revalidation: stored evidence does not satisfy the current ordered, endpoint-scoped detection requirements.';
    incident.status = 'false_positive';
    incident.resolvedAt = new Date();
    incident.lastActivityAt = incident.windowEnd || incident.createdAt;
    incident.notes = incident.notes ? `${incident.notes}\n${note}`.slice(0, 4000) : note;
    incident.resolutionHistory.push({
      status: 'false_positive',
      notes: note,
      changedAt: new Date(),
    });
    await incident.save();
    rejected += 1;
  }

  // Historical schema defaults must never make an old rejected match look like
  // new attack activity. Anchor it to the last source event (or creation time).
  const historical = await CorrelationEvent.find({ status: 'false_positive' });
  let timestampsNormalized = 0;
  for (const incident of historical) {
    const actualActivity = incident.windowEnd || incident.createdAt;
    if (!actualActivity || Number(incident.lastActivityAt) === Number(actualActivity)) continue;
    incident.lastActivityAt = actualActivity;
    await incident.save();
    timestampsNormalized += 1;
  }

  console.log(JSON.stringify({
    scanned: incidents.length, valid, rejected, timestampsNormalized,
  }));
  await mongoose.disconnect();
}

main().catch(async error => {
  console.error(error);
  await mongoose.disconnect().catch(() => {});
  process.exit(1);
});
