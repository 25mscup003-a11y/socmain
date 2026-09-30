const net = require('net');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const { enrichIp } = require('./ipEnrichmentService');

function coordinates(value) {
  if (!value || value === 'Local') return {};
  const [lat, lon] = String(value).split(',').map(Number);
  return Number.isFinite(lat) && Number.isFinite(lon) ? { geoLat: lat, geoLon: lon } : {};
}

function enrichmentUpdate(result = {}) {
  const privacy = result.privacy || {};
  return {
    geoCountry: result.country || result.countryCode || undefined,
    geoCountryCode: result.countryCode || undefined,
    geoContinent: result.continent || undefined,
    geoContinentCode: result.continentCode || undefined,
    geoCity: result.city || undefined,
    geoRegion: result.region || undefined,
    geoPostal: result.postal || undefined,
    geoTimezone: result.timezone || undefined,
    geoLoc: result.loc || undefined,
    geoISP: result.organization || undefined,
    asn: result.asn || undefined,
    asnOrg: result.organization || undefined,
    asnDomain: result.domain || undefined,
    geoVpn: privacy.vpn === true,
    geoProxy: privacy.proxy === true,
    geoTor: privacy.tor === true,
    geoRelay: privacy.relay === true,
    geoHosting: privacy.hosting === true,
    geoAnycast: result.anycast === true,
    geoHostname: result.hostname || undefined,
    geoStatus: result.error ? 'failed' : 'enriched',
    ...coordinates(result.loc),
  };
}

function isGeolocationEvidence(alert = {}) {
  return Number(alert.capabilityId) === 23
    || /^(?:GEO_|GPS_LOCATION_TELEMETRY$)/i.test(String(alert.ruleId || alert.type || ''))
    || String(alert.eventCategory || alert.category || '').toLowerCase() === 'geolocation';
}

function hasCapability(alert = {}, capabilityId) {
  return Number(alert.capabilityId) === capabilityId
    || (Array.isArray(alert.capabilityIds) && alert.capabilityIds.map(Number).includes(capabilityId));
}

function currentGpsState(alert = {}) {
  const ruleId = String(alert.ruleId || alert.rule_id || alert.type || '').toUpperCase();
  const source = String(alert.source || '').toLowerCase();
  if (!['GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS'].includes(ruleId) && source !== 'gps-location') return null;

  const systemId = alert.systemId?._id || alert.systemId;
  const companyId = alert.companyId?._id || alert.companyId;
  if (!systemId || !companyId) return null;
  const status = String(alert.gpsStatus || alert.rawEvent?.gpsStatus || '').toLowerCase();
  if (!status) return null;
  const observedValue = alert.gpsObservedAt || alert.rawEvent?.gpsObservedAt || alert.timestamp || alert.createdAt;
  const numericObserved = Number(observedValue);
  const observedAt = observedValue instanceof Date
    ? observedValue
    : new Date(Number.isFinite(numericObserved)
      ? (numericObserved < 100000000000 ? numericObserved * 1000 : numericObserved)
      : observedValue);
  if (Number.isNaN(observedAt.getTime())) return null;

  const latitude = Number(alert.gpsLat ?? alert.rawEvent?.gpsLat);
  const longitude = Number(alert.gpsLon ?? alert.rawEvent?.gpsLon);
  const accuracy = Number(alert.gpsAccuracyMeters ?? alert.rawEvent?.gpsAccuracyMeters);
  const altitude = Number(alert.gpsAltitudeMeters ?? alert.rawEvent?.gpsAltitudeMeters);
  const coordinatesValid = Number.isFinite(latitude) && latitude >= -90 && latitude <= 90
    && Number.isFinite(longitude) && longitude >= -180 && longitude <= 180
    && Number.isFinite(accuracy) && accuracy >= 0;
  const displayable = ['available', 'inaccurate'].includes(status) && coordinatesValid;

  return {
    systemId,
    companyId,
    observedAt,
    update: {
      gpsStatus: status,
      gpsProvider: String(alert.gpsProvider || alert.rawEvent?.gpsProvider || ''),
      gpsReason: String(alert.gpsReason || alert.rawEvent?.gpsReason || '').slice(0, 500),
      gpsObservedAt: observedAt,
      gpsLat: displayable ? latitude : null,
      gpsLon: displayable ? longitude : null,
      gpsAccuracyMeters: Number.isFinite(accuracy) && accuracy >= 0 ? accuracy : null,
      gpsAltitudeMeters: displayable && Number.isFinite(altitude) ? altitude : null,
    },
  };
}

async function persistCurrentGpsState(alert = {}) {
  const state = currentGpsState(alert);
  if (!state) return false;
  const result = await System.updateOne({
    _id: state.systemId,
    companyId: state.companyId,
    $or: [
      { gpsObservedAt: null },
      { gpsObservedAt: { $exists: false } },
      { gpsObservedAt: { $lte: state.observedAt } },
    ],
  }, { $set: state.update });
  return result.matchedCount > 0;
}

async function enrichGeolocationAlert(alert, io) {
  const id = alert?._id;
  const ip = alert?.srcip || alert?.sourceIp;
  if (!id || !ip || !net.isIP(String(ip))) return null;

  const alreadyEnriched = Boolean(alert.geoCountry || alert.geoCountryCode);
  const result = alreadyEnriched ? null : await enrichIp(String(ip));
  const update = alreadyEnriched ? { geoStatus: 'enriched' } : enrichmentUpdate(result);
  if (!update.geoCountry && !alreadyEnriched) {
    await Alert.updateOne({ _id: id }, { $set: { geoStatus: 'failed' } });
    return null;
  }

  const saved = await Alert.findByIdAndUpdate(id, { $set: update }, { new: true }).lean();
  if (!saved) return null;

  // Push the enriched record back to live dashboards. Authentication events
  // arrive before the asynchronous Geo-IP lookup finishes, so capability 4
  // needs this update to display the real location without waiting for polling.
  io?.to(`company:${saved.companyId}`).emit('alert:updated', saved);
  if (hasCapability(saved, 4)) {
    io?.to(`company:${saved.companyId}`).emit('auth:event', saved);
  }

  if (isGeolocationEvidence(saved)) {
    io?.to(`company:${saved.companyId}`).emit('geo:event', saved);
  }
  if (/^GEO_/i.test(String(saved.ruleId || ''))) {
    io?.to(`company:${saved.companyId}`).emit('geo:anomaly', saved);
  }
  return saved;
}

function scheduleGeolocationEnrichment(alert, io) {
  setImmediate(() => enrichGeolocationAlert(alert, io)
    .catch(error => console.error('[geolocation enrichment]', error.message)));
}

module.exports = {
  coordinates,
  enrichmentUpdate,
  enrichGeolocationAlert,
  isGeolocationEvidence,
  currentGpsState,
  persistCurrentGpsState,
  scheduleGeolocationEnrichment,
};
