/**
 * Master Single Source of Truth for Enterprise EDR & SOC Monitoring Capabilities
 * Maps Card ID, Capability ID, Backend Database ID, Titles, Routes, and Icons.
 */

export const CAPABILITY_CONFIG = [
  { id: 1,  capabilityId: 1,  backendId: 1,  title: 'Process Activity Monitoring',            dashboardRoute: '/company-admin/edr?capabilityId=1',  publicRoute: '/company-admin/edr?capabilityId=1',  icon: '⚡', kind: 'process' },
  { id: 2,  capabilityId: 2,  backendId: 2,  title: 'File Activity Monitoring (FIM)',         dashboardRoute: '/company-admin/edr?capabilityId=2',  publicRoute: '/company-admin/edr?capabilityId=2',  icon: '📄', kind: 'file' },
  { id: 3,  capabilityId: 3,  backendId: 3,  title: 'Network Activity Monitoring',            dashboardRoute: '/company-admin/edr?capabilityId=3',  publicRoute: '/company-admin/edr?capabilityId=3',  icon: '🌐', kind: 'network' },
  { id: 4,  capabilityId: 4,  backendId: 4,  title: 'User & Authentication Monitoring',        dashboardRoute: '/company-admin/edr?capabilityId=4',  publicRoute: '/company-admin/edr?capabilityId=4',  icon: '👤', kind: 'auth' },
  { id: 5,  capabilityId: 5,  backendId: 5,  title: 'Memory Activity Monitoring',             dashboardRoute: '/company-admin/edr?capabilityId=5',  publicRoute: '/company-admin/edr?capabilityId=5',  icon: '🧠', kind: 'memory' },
  { id: 6,  capabilityId: 6,  backendId: 6,  title: 'Registry Monitoring',                    dashboardRoute: '/company-admin/edr?capabilityId=6',  publicRoute: '/company-admin/edr?capabilityId=6',  icon: '⚙️', kind: 'registry' },
  { id: 7,  capabilityId: 7,  backendId: 7,  title: 'System Changes Monitoring',              dashboardRoute: '/company-admin/edr?capabilityId=7',  publicRoute: '/company-admin/edr?capabilityId=7',  icon: '🔧', kind: 'systemchanges' },
  { id: 8,  capabilityId: 8,  backendId: 8,  title: 'Persistence Mechanism Detection',        dashboardRoute: '/company-admin/edr?capabilityId=8',  publicRoute: '/company-admin/edr?capabilityId=8',  icon: '🔒', kind: 'persistence' },
  { id: 9,  capabilityId: 9,  backendId: 9,  title: 'Web & DNS Monitoring',                   dashboardRoute: '/company-admin/edr?capabilityId=9',  publicRoute: '/company-admin/edr?capabilityId=9',  icon: '🌐', kind: 'webdns' },
  { id: 10, capabilityId: 10, backendId: 10, title: 'Device Control (USB) Monitoring',        dashboardRoute: '/company-admin/edr?capabilityId=10', publicRoute: '/company-admin/edr?capabilityId=10', icon: '🔌', kind: 'usb' },
  { id: 11, capabilityId: 11, backendId: 11, title: 'Behavioral Analytics (UEBA)',            dashboardRoute: '/company-admin/edr?capabilityId=11', publicRoute: '/company-admin/edr?capabilityId=11', icon: '📈', kind: 'ueba' },
  { id: 12, capabilityId: 12, backendId: 12, title: 'Data Security Monitoring',               dashboardRoute: '/company-admin/edr?capabilityId=12', publicRoute: '/company-admin/edr?capabilityId=12', icon: '🛡️', kind: 'datasecurity' },
  { id: 13, capabilityId: 13, backendId: 13, title: 'Credential Security Monitoring',         dashboardRoute: '/company-admin/edr?capabilityId=13', publicRoute: '/company-admin/edr?capabilityId=13', icon: '🔑', kind: 'credentialsecurity' },
  { id: 14, capabilityId: 14, backendId: 14, title: 'Lateral Movement Detection',             dashboardRoute: '/company-admin/edr?capabilityId=14', publicRoute: '/company-admin/edr?capabilityId=14', icon: '↔️', kind: 'lateralmovement' },
  { id: 15, capabilityId: 15, backendId: 15, title: 'Email Threat Monitoring',                dashboardRoute: '/company-admin/edr?capabilityId=15', publicRoute: '/company-admin/edr?capabilityId=15', icon: '📧', kind: 'emailthreat' },
  { id: 16, capabilityId: 16, backendId: 16, title: 'Insider Threat Detection',               dashboardRoute: '/company-admin/edr?capabilityId=16', publicRoute: '/company-admin/edr?capabilityId=16', icon: '🕵️', kind: 'insiderthreat' },
  { id: 17, capabilityId: 17, backendId: 17, title: 'Patch & Vulnerability Monitoring',       dashboardRoute: '/company-admin/edr?capabilityId=17', publicRoute: '/company-admin/edr?capabilityId=17', icon: '🩹', kind: 'patchvulnerability' },
  { id: 18, capabilityId: 18, backendId: 18, title: 'Sandbox Analysis',                       dashboardRoute: '/company-admin/edr?capabilityId=18', publicRoute: '/company-admin/edr?capabilityId=18', icon: '🧪', kind: 'sandboxanalysis' },
  { id: 19, capabilityId: 19, backendId: 19, title: 'Kernel-Level Monitoring',                dashboardRoute: '/company-admin/edr?capabilityId=19', publicRoute: '/company-admin/edr?capabilityId=19', icon: '🖥️', kind: 'kernelmonitoring' },
  { id: 20, capabilityId: 20, backendId: 20, title: 'API Call Monitoring',                    dashboardRoute: '/company-admin/edr?capabilityId=20', publicRoute: '/company-admin/edr?capabilityId=20', icon: '📡', kind: 'apicallmonitoring' },
  { id: 21, capabilityId: 21, backendId: 21, title: 'Script Execution Monitoring',            dashboardRoute: '/company-admin/edr?capabilityId=21', publicRoute: '/company-admin/edr?capabilityId=21', icon: '📜', kind: 'scriptmonitoring' },
  { id: 22, capabilityId: 22, backendId: 22, title: 'Time-Based Anomaly Detection',           dashboardRoute: '/company-admin/edr?capabilityId=22', publicRoute: '/company-admin/edr?capabilityId=22', icon: '🕒', kind: 'timeanomaly' },
  { id: 23, capabilityId: 23, backendId: 23, title: 'Geolocation Anomaly Detection',          dashboardRoute: '/company-admin/edr?capabilityId=23', publicRoute: '/company-admin/edr?capabilityId=23', icon: '📍', kind: 'geoanomaly' },
  { id: 24, capabilityId: 24, backendId: 24, title: 'Service Monitoring',                     dashboardRoute: '/company-admin/edr?capabilityId=24', publicRoute: '/company-admin/edr?capabilityId=24', icon: '⚙️', kind: 'servicemonitoring' },
  { id: 25, capabilityId: 25, backendId: 25, title: 'Hash/Signature Analysis',                dashboardRoute: '/company-admin/edr?capabilityId=25', publicRoute: '/company-admin/edr?capabilityId=25', icon: '🔍', kind: 'hashsignature' },
  { id: 26, capabilityId: 26, backendId: 26, title: 'Beaconing Detection',                    dashboardRoute: '/company-admin/edr?capabilityId=26', publicRoute: '/company-admin/edr?capabilityId=26', icon: '📡', kind: 'beaconing' },
  { id: 27, capabilityId: 27, backendId: 27, title: 'Encryption / Ransomware Detection',      dashboardRoute: '/company-admin/edr?capabilityId=27', publicRoute: '/company-admin/edr?capabilityId=27', icon: '🔐', kind: 'ransomware' },
  { id: 28, capabilityId: 28, backendId: 28, title: 'Living-off-the-Land (LOLBins) Detection', dashboardRoute: '/company-admin/edr?capabilityId=28', publicRoute: '/company-admin/edr?capabilityId=28', icon: '🧰', kind: 'lolbins' },
  { id: 29, capabilityId: 29, backendId: 29, title: 'Memory Overflow Detection',              dashboardRoute: '/company-admin/edr?capabilityId=29', publicRoute: '/company-admin/edr?capabilityId=29', icon: '💾', kind: 'memoryoverflow' },
  { id: 30, capabilityId: 30, backendId: 30, title: 'DNS Cache Poisoning Detection',          dashboardRoute: '/company-admin/edr?capabilityId=30', publicRoute: '/company-admin/edr?capabilityId=30', icon: '☠️', kind: 'dnscachepoisoning' },
  { id: 31, capabilityId: 31, backendId: 31, title: 'DNS Sinkhole',                           dashboardRoute: '/company-admin/edr?capabilityId=31', publicRoute: '/company-admin/edr?capabilityId=31', icon: '🕳️', kind: 'dnssinkhole' },
];

const CARD_ID_MAP = new Map();
const BACKEND_ID_MAP = new Map();

CAPABILITY_CONFIG.forEach(c => {
  CARD_ID_MAP.set(c.id, c);
  CARD_ID_MAP.set(c.capabilityId, c);
  BACKEND_ID_MAP.set(c.backendId, c);
});

/**
 * Get capability strictly by Card ID (1..31)
 */
export function getCapabilityByCardId(cardId) {
  if (cardId == null) return null;
  const num = Number(cardId);
  if (isNaN(num)) return null;
  return CARD_ID_MAP.get(num) || null;
}

/**
 * Get capability strictly by Backend DB ID (1..38)
 */
export function getCapabilityByBackendId(backendId) {
  if (backendId == null) return null;
  const num = Number(backendId);
  if (isNaN(num)) return null;
  return BACKEND_ID_MAP.get(num) || null;
}

/**
 * Get single source of truth capability object by Card ID or Backend ID
 */
export function getCapability(id) {
  if (id == null) return null;
  const num = Number(id);
  if (isNaN(num)) return null;
  return CARD_ID_MAP.get(num) || BACKEND_ID_MAP.get(num) || null;
}

/**
 * Get title for capability ID
 */
export function getCapabilityTitle(id, fallback = 'Monitoring Capability') {
  const cap = getCapabilityByCardId(id) || getCapability(id);
  return cap ? cap.title : fallback;
}

/**
 * Verify if capability ID is valid
 */
export function isValidCapabilityId(id) {
  return getCapability(id) !== null;
}

/**
 * Get route for capability ID
 */
export function getCapabilityRoute(id) {
  const cap = getCapabilityByCardId(id) || getCapability(id);
  return cap ? cap.publicRoute : `/company-admin/edr?capabilityId=${id}`;
}

export default CAPABILITY_CONFIG;
