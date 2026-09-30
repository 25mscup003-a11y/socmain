const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const workspace = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(workspace, relative), 'utf8');
const { coordinates, enrichmentUpdate, currentGpsState } = require('../src/services/geolocation.service');

test('geolocation enrichment normalizes coordinates and privacy metadata', () => {
  assert.deepEqual(coordinates('28.6139,77.2090'), { geoLat: 28.6139, geoLon: 77.209 });
  const result = enrichmentUpdate({
    country: 'India', countryCode: 'IN', city: 'Delhi', region: 'Delhi', loc: '28.6139,77.2090',
    asn: 'AS64500', organization: 'Example ISP', privacy: { vpn: true, proxy: false, tor: false, hosting: true },
  });
  assert.equal(result.geoCountry, 'India');
  assert.equal(result.geoCountryCode, 'IN');
  assert.equal(result.geoVpn, true);
  assert.equal(result.geoHosting, true);
  assert.equal(result.geoStatus, 'enriched');
});

test('native GPS telemetry materializes current agent state with millisecond timestamps', () => {
  const state = currentGpsState({
    companyId: 'company-a', systemId: 'system-a', ruleId: 'GPS_LOCATION_TELEMETRY',
    gpsStatus: 'available', gpsProvider: 'android-gps', gpsLat: 28.6139,
    gpsLon: 77.209, gpsAccuracyMeters: 12, gpsObservedAt: 1788777000000,
  });
  assert.equal(state.systemId, 'system-a');
  assert.equal(state.update.gpsLat, 28.6139);
  assert.equal(state.update.gpsLon, 77.209);
  assert.equal(state.update.gpsObservedAt.toISOString(), '2026-09-07T10:30:00.000Z');
});

test('unavailable GPS state clears coordinates instead of displaying a stale map point', () => {
  const state = currentGpsState({
    companyId: 'company-a', systemId: 'system-a', ruleId: 'GEO_GPS_STATUS',
    gpsStatus: 'permission_denied', gpsLat: 28.6139, gpsLon: 77.209,
    gpsAccuracyMeters: 12, gpsObservedAt: '2026-09-08T00:00:00Z',
  });
  assert.equal(state.update.gpsLat, null);
  assert.equal(state.update.gpsLon, null);
});

test('inaccurate GPS state keeps explicitly approximate coordinates for map display', () => {
  const state = currentGpsState({
    companyId: 'company-a', systemId: 'system-a', ruleId: 'GEO_GPS_STATUS',
    gpsStatus: 'inaccurate', gpsProvider: 'geoclue', gpsLat: 26.8393,
    gpsLon: 80.9231, gpsAccuracyMeters: 25000, gpsObservedAt: '2026-09-08T00:00:00Z',
  });
  assert.equal(state.update.gpsLat, 26.8393);
  assert.equal(state.update.gpsLon, 80.9231);
  assert.equal(state.update.gpsAccuracyMeters, 25000);
});

test('geolocation API exposes tenant-scoped live analytics and policy routes', () => {
  const route = read('backend/src/routes/geolocation.routes.js');
  assert.match(route, /router\.get\('\/overview', requireAnalyst/);
  assert.match(route, /router\.get\(\['\/events', '\/alerts'\], requireAnalyst/);
  assert.match(route, /router\.get\('\/statistics', requireAnalyst/);
  assert.match(route, /router\.get\('\/heatmap', requireAnalyst/);
  assert.match(route, /router\.get\('\/timeline', requireAnalyst/);
  assert.match(route, /req\.user\.role !== 'superadmin'.*assertCompanyScope/);
  assert.match(route, /geolocationEvidenceFilter\(\)/);
  assert.match(route, /Agent Allowed Location & Radius/);
  assert.match(route, /AJNAT Device GPS Tracking/);
  assert.match(route, /loadGeoEvents\(companyScope, since, until/);
  assert.match(route, /Select an AJNAT system, valid latitude\/longitude and allowed radius/);
  assert.match(route, /gpsTracking: true/);
  assert.match(route, /event\.gpsLat \?\? event\.geoLat/);
  assert.match(route, /validatePolicyTargets/);
  assert.match(route, /const actorId = req\.user\._id \|\| req\.user\.id/);
  assert.match(route, /Selected AJNAT agent does not belong to this company or is inactive/);
  assert.match(route, /const ONLINE_THRESHOLD_MS = 10 \* 60 \* 1000/);
  assert.match(route, /systems: systems\.map\(system => withLiveSystemStatus\(system\)\)/);
  assert.match(route, /gpsObservedAt/);
  assert.match(route, /router\.post\('\/respond', requireManager/);
  assert.match(route, /AutomatedResponse\.findOne\(\{ alertId: event\._id, companyId: event\.companyId \}\)/);
  assert.match(route, /responseAction: responseAction \|\| null/);
  assert.match(route, /buildLiveForensics/);
  assert.match(route, /AJNAT agent live telemetry/);
  assert.match(route, /liveForensics/);
  assert.match(route, /agentVersion gpsLat gpsLon gpsAccuracyMeters gpsAltitudeMeters gpsProvider gpsStatus gpsReason gpsObservedAt/);
  assert.match(route, /IDENTITY_RESPONSE_ACTIONS = new Set\(\['lock_account', 'force_logoff', 'isolate'\]\)/);
  assert.match(route, /trackIdentityProtectionResponse/);
  assert.match(route, /SocAuditEvent\.create/);
  const alertRoute = read('backend/src/routes/alert.routes.js');
  const alertModel = read('backend/src/models/Alert.model.js');
  const worker = read('backend/src/workers/alertIngestion.worker.js');
  assert.match(alertRoute, /processGeolocationProtectionAlert/);
  assert.match(worker, /processGeolocationProtectionAlert/);
  assert.match(alertModel, /'logged_out', 'logout_failed'/);
});

test('capability 23 dashboard uses the dedicated overview and geolocation sockets', () => {
  const details = read('company/src/pages/EDRDashboardDetails.jsx');
  const geo = read('company/src/pages/edrdashbordpage/Geolocation Anomaly Detection.jsx');
  assert.match(details, /api\.get\('\/geolocation\/overview'/);
  assert.match(details, /api\.get\('\/dashboard\/alerts\/edr'/);
  assert.match(details, /capabilityId: 23, page: 1, limit: 1000/);
  assert.match(details, /socket\.on\('geo:event', liveAlertBuffer\.add\)/);
  assert.match(details, /socket\.on\('geo:anomaly', liveAlertBuffer\.add\)/);
  assert.match(geo, /api\.get\('\/geolocation\/overview'/);
  assert.match(geo, /loadPanelGpsFallback/);
  assert.match(geo, /const incomingRows = panelGpsRows\.length \? panelGpsRows : alerts/);
  assert.match(geo, /currentGpsRowFromSystem/);
  assert.match(geo, /<GpsLiveMap rows=\{gpsRows\}/);
  assert.match(geo, /<GeoOverviewDashboard metrics=\{gpsMetrics\}/);
  assert.match(geo, /GPS Events \(24H\)/);
  assert.match(geo, /Reporting Agents/);
  assert.match(geo, /Average Accuracy/);
  assert.match(geo, /AJNAT Native GPS Agent Monitoring/);
  assert.match(geo, /RECENT AJNAT GPS STATES/);
  assert.match(geo, /GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS/);
  assert.doesNotMatch(geo, /maps\.googleapis\.com/);
  assert.match(geo, /google\.com\/vt\/lyrs=m/);
  assert.match(geo, /new ResizeObserver\(invalidate\)/);
  assert.match(geo, /map\.invalidateSize/);
  assert.match(geo, /threat-countries-map\.png/);
  assert.match(geo, /const agentGpsPosition = row/);
  assert.doesNotMatch(geo, /row\.gpsLat \?\? row\.rawEvent\?\.gpsLat \?\? row\.browserLocation/);
  assert.match(geo, /selectedEventId=\{selectedEventId\}/);
  assert.match(geo, /AJNAT GPS:/);
  assert.match(geo, /AJNAT GPS Telemetry SIEM Logs/);
  assert.match(geo, /PRECISE COORDINATE NOT SENT/);
  assert.match(geo, /GPS\/GNSS hardware fix is not available on this device/);
  assert.match(geo, /Not a GPS observation/);
  assert.match(geo, /AJNAT APPROXIMATE:/);
  assert.match(geo, /metrics\.displayableLatestRows/);
  assert.match(geo, /APPROXIMATE/);
  assert.match(geo, /Reason: \{diagnosis\.detail\}/);
  assert.match(geo, /<GeoAnomalyLogMonitor alerts=\{rows\} companyId=\{companyId\}/);
  assert.doesNotMatch(geo, /GPS DELIVERY DIAGNOSIS/);
  assert.match(geo, /if \(!isGpsTelemetry\) return false/);
  assert.match(geo, /if \(!ajnatSystemId\) return false/);
  assert.doesNotMatch(geo, /<span>Source IP & Geography<\/span>/);
  assert.doesNotMatch(geo, /socket\.on\('geo:login', buf\.add\)/);
  assert.match(geo, /initialPolicy=\{editingPolicy\}/);
  assert.match(geo, /api\.put\(`\/geolocation\/policies\/\$\{editingPolicy\._id\}`/);
  assert.match(geo, /Native device GPS tracking/);
  assert.match(geo, /Required Accuracy \(5–50 metres\)/);
  assert.match(geo, /Policy rule create nahi hui/);
  assert.match(geo, /gpsRowsByAgent/);
  assert.match(geo, /WITHIN 50M/);
  assert.match(geo, /Waiting for AJNAT precise or approximate location/);
  assert.match(geo, /row\.gpsLat \?\?/);
  assert.match(geo, /CapabilityReportsPanel capabilityId=\{23\}/);
  assert.match(details, /api\.post\('\/geolocation\/respond'/);
  assert.match(geo, /'lock_account'/);
  assert.match(geo, /'force_logoff'/);
  assert.match(geo, /'isolate'/);
  assert.match(geo, /api\.get\(`\/geolocation\/events\/\$\{eventId\}`/);
  assert.match(geo, /setInterval\(loadLiveEvent, 5000\)/);
  assert.match(geo, /GPS Observed At/);
  assert.match(geo, /systemId\.gpsObservedAt/);
  assert.match(geo, /Policy Action Status/);
  assert.match(geo, /responseAction\.status/);
  assert.match(geo, /companyId=\{companyId\} onClose/);
  assert.match(geo, /const refreshed = alerts\.find/);
  assert.match(geo, /Apply Rule To AJNAT Agent/);
  assert.match(geo, /AJNAT Agent Scope/);
  assert.match(geo, /Rule sirf selected agent par apply hoga/);
  assert.doesNotMatch(geo, /john\.doe@company\.com|ramesh\.k@company\.com|12,842|8,732/);
});

test('geolocation overview returns AJNAT GPS and policy-category detector telemetry', () => {
  const route = read('backend/src/routes/geolocation.routes.js');
  const filter = read('backend/src/utils/capabilityOverview.js');
  assert.doesNotMatch(route, /LoginActivity/);
  assert.doesNotMatch(route, /loginActivityAsGeoEvent|loadLoginGeoEvents|loginTotal/);
  assert.match(filter, /systemId: \{ \$exists: true, \$ne: null \}/);
  assert.match(filter, /ruleId: \/\^GEO_\/i/);
  assert.match(filter, /policyTriggered: true/);
  assert.match(filter, /policyCategory:/);
  assert.match(filter, /GEO_GPS_STATUS\|GPS_LOCATION_TELEMETRY/);
  assert.match(filter, /source: \/\^gps-location\$\/i/);
  assert.match(route, /summary: summarize\(events, total\)/);
});

test('policy category and action engine choices are validated end to end', () => {
  const route = read('backend/src/routes/geolocation.routes.js');
  const agentRoutes = read('backend/src/routes/agent.routes.js');
  const agentDetector = read('backend/soc-agent/core/geo_enrichment.py');
  const agentSender = read('backend/soc-agent/core/sender.py');
  const dashboard = read('company/src/pages/edrdashbordpage/Geolocation Anomaly Detection.jsx');
  assert.match(route, /GEO_POLICY_CATEGORIES/);
  assert.match(route, /actionsForCategory\(policy\.category\)/);
  assert.match(route, /Select at least one ISO country code/);
  assert.match(agentRoutes, /geolocation_policies: geolocationPolicies\.map/);
  assert.match(agentDetector, /def _finalize_findings/);
  assert.match(agentDetector, /'policyActionStatus': 'triggered'/);
  assert.match(agentSender, /finding\['policyActionStatus'\] = 'enforced'/);
  assert.match(agentSender, /finding\['policyActionStatus'\] = 'failed'/);
  assert.match(dashboard, /categoryStats\.map/);
  assert.match(dashboard, /LIVE EVENTS/);
  assert.match(dashboard, /BLOCKED/);
});

test('geo-IP enrichment does not retag generic web or network alerts as geolocation telemetry', () => {
  const service = read('backend/src/services/geolocation.service.js');
  assert.doesNotMatch(service, /\$addToSet:\s*\{\s*capabilityIds:\s*23/);
  assert.match(service, /isGeolocationEvidence\(saved\)/);
});

test('agent heartbeat and alert ingestion enforce policy-gated GPS telemetry', () => {
  const agentRoutes = read('backend/src/routes/agent.routes.js');
  const alertRoutes = read('backend/src/routes/alert.routes.js');
  const alertModel = read('backend/src/models/Alert.model.js');
  assert.match(agentRoutes, /gps_tracking_enabled: Boolean\(gpsTrackingPolicy/);
  assert.match(agentRoutes, /geolocation_forensics_enabled: Boolean\(gpsTrackingPolicy\)/);
  assert.match(agentRoutes, /manualVersionUpdateConfirmed = reachedRecordedUpdateTarget && pendingUpdateCommand\?\.force !== true/);
  assert.match(agentRoutes, /\['Device GPS Tracking', 'Location-Based'\]/);
  assert.match(agentRoutes, /gps_required_accuracy_meters/);
  assert.match(alertRoutes, /activeGpsPolicyAccuracyLimit/);
  assert.match(alertRoutes, /GPS accuracy must be within/);
  assert.match(agentRoutes, /Math\.min\(50, Math\.max\(5,/);
  assert.match(alertRoutes, /gpsAccuracyMeters: numberOrUndefined/);
  assert.match(alertModel, /gpsObservedAt: \{ type: Date \}/);
  const systemModel = read('backend/src/models/System.model.js');
  const desktopGps = read('backend/soc-agent/core/gps_location.py');
  const androidGps = read('backend/android-agent/app/src/main/java/com/soc/agent/GpsLocationCollector.java');
  const dashboard = read('company/src/pages/edrdashbordpage/Geolocation Anomaly Detection.jsx');
  assert.match(systemModel, /gpsObservedAt:\s+\{ type: Date/);
  assert.match(desktopGps, /gps_location_state/);
  assert.match(desktopGps, /geoForensics/);
  assert.match(dashboard, /agentField\('authentication'/);
  assert.match(dashboard, /agentField\('data'/);
  assert.match(androidGps, /MIN_MOVEMENT_METERS/);
  assert.match(androidGps, /Math\.min\(50\.0,/);
});

test('system setup and capability 23 share the same agent-scoped policy data', () => {
  const systemsPage = read('company/src/pages/EDRSystemSystemsPage.jsx');
  const geoDashboard = read('company/src/pages/edrdashbordpage/Geolocation Anomaly Detection.jsx');
  assert.match(systemsPage, /capabilityId=23&capability=geolocation-anomaly-detection&view=policy/);
  assert.match(systemsPage, /<GeoPolicyEngine \/>/);
  assert.doesNotMatch(systemsPage, /label: '💻 Systems'/);
  assert.match(systemsPage, /Manual System Lock Controls/);
  assert.match(systemsPage, /api\.post\(`\/system\/\$\{system\._id\}\/isolate`/);
  assert.match(systemsPage, /api\.delete\(`\/system\/\$\{system\._id\}\/isolate`/);
  assert.match(geoDashboard, /api\.get\('\/geolocation\/policies'/);
  assert.match(geoDashboard, /api\.post\('\/geolocation\/policies'/);
  assert.match(geoDashboard, /api\.put\(`\/geolocation\/policies\/\$\{editingPolicy\._id\}`/);
  assert.match(geoDashboard, /requestedView === 'policy'/);
});

test('single and batch alert ingestion publish tenant-scoped geo events', () => {
  const alerts = read('backend/src/routes/alert.routes.js');
  assert.ok((alerts.match(/emit\('geo:event',/g) || []).length >= 2);
  assert.ok((alerts.match(/emit\('geo:anomaly',/g) || []).length >= 2);
});
