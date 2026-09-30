const mongoose = require('mongoose');
const { normalizeThreatLabels } = require('../utils/threatIntelLabels');
const { normalizeEventCategory } = require('../utils/securityEventNormalizer');

const AlertSchema = new mongoose.Schema({
  tenantId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company',    required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', index: true },
  systemId:     { type: mongoose.Schema.Types.ObjectId, ref: 'System' },
  eventId:      { type: String },
  eventFingerprint: { type: String },
  schemaVersion:{ type: Number, default: 1 },
  sourceType:   { type: String, enum: ['IAM', 'IDS', 'IPS', 'ZEEK', 'THREAT_FEED'], index: true },
  sourceVendor: { type: String, maxlength: 128 },
  normalizedEventType: { type: String, maxlength: 128, index: true },
  eventName:    { type: String, maxlength: 500 },
  eventTimestamp: { type: Date, index: true },
  receivedAt:   { type: Date, default: Date.now },
  sensor:       { type: String, maxlength: 128, index: true },
  sensorEventType: { type: String, maxlength: 32, index: true },
  communityId:  { type: String, maxlength: 128, index: true },
  signatureId:  { type: String, maxlength: 128 },
  cve:          { type: String, maxlength: 32 },
  hostnameObserved: { type: String, maxlength: 253 },
  actionable:   { type: Boolean, default: false, index: true },
  expiresAt:    { type: Date, default: null },
  archivedAt:   { type: Date, default: null },
  archiveKey:   { type: String, default: '' },

  // Agent identity
  agentId:   { type: String },
  agentName: { type: String },
  endpointId:   { type: String, index: true },
  hostname:     { type: String },
  osType:       { type: String },
  agentVersion: { type: String },

  // Detection rule — ruleId is the STRING rule name (e.g. 'YARA_MATCH', 'USB_DEVICE_EVENT')
  ruleId:      { type: String },   // e.g. 'YARA_MATCH', 'NET_SUSPICIOUS_CONNECTION'
  detectionRuleId: { type: String, index: true },
  ruleLevel:   { type: Number },   // numeric detection-rule level (optional)
  description: { type: String },
  full_log:    { type: String },
  srcip:       { type: String },
  sourcePort:  { type: Number },

  // Event classification
  source: { type: String }, // syslog, network, process, yara, usb, anomaly
  type:   { type: String }, // rule_id string stored here for legacy compat
  module: { type: String, index: true }, // IDS / IPS
  source_type: { type: String, index: true }, // ids / ips
  event_category: { type: String, index: true }, // ids_alert / ips_block / blacklist_event
  attackType: { type: String, index: true },
  signatureName: { type: String },
  packetCount: { type: Number },
  capabilityId: { type: Number, index: true },
  capabilityIds: [{ type: Number }],
  isSynthetic: { type: Boolean, default: false, index: true },
  dataOrigin: { type: String, enum: ['agent', 'integration', 'manual', 'synthetic'], default: 'agent' },
  fimModule:    { type: String, index: true },
  category:     { type: String },
  subCategory:  { type: String },
  eventType:    { type: String },
  riskScore:    { type: Number },
  behaviorCategory: { type: String, trim: true, maxlength: 120 },
  entityType: { type: String, trim: true, maxlength: 40 },
  entityId: { type: String, trim: true, maxlength: 512 },
  behaviorScore: { type: Number, min: 0, max: 100 },
  baselineScore: { type: Number, min: 0, max: 100 },
  peerDeviationScore: { type: Number, min: 0, max: 100 },
  uebaConfidence: { type: Number, min: 0, max: 100 },
  uebaRiskFactors: [{ type: String, maxlength: 160 }],
  baselineWindowDays: { type: Number, min: 1, max: 365 },
  inputMonitoringAvailable: { type: Boolean },
  inputPrivacyMode: { type: String, trim: true, maxlength: 64 },
  inputKeyboardEvents: { type: Number, min: 0 },
  inputMouseEvents: { type: Number, min: 0 },
  inputClickCount: { type: Number, min: 0 },
  inputScrollCount: { type: Number, min: 0 },
  inputKeyboardRate: { type: Number, min: 0 },
  inputMouseRate: { type: Number, min: 0 },
  inputActivityPercent: { type: Number, min: 0, max: 100 },
  inputProfileStatus: { type: String, enum: ['learning', 'verification_active'] },
  inputBaselineDays: { type: Number, min: 0, max: 30 },
  inputIdentityConfidence: { type: Number, min: 0, max: 100 },
  inputProfileMismatch: { type: Boolean },
  inputProfileMismatchFeatures: [{ type: String, maxlength: 64 }],
  inputProfileDeviation: { type: mongoose.Schema.Types.Mixed, default: {} },
  inputUserSource: { type: String, trim: true, maxlength: 64 },
  inputUserVerified: { type: Boolean },
  inputSessionCount: { type: Number, min: 0, max: 100 },
  insiderSignalType: { type: String, trim: true, maxlength: 80 },
  emailSender: { type: String, trim: true, maxlength: 320, index: true },
  emailRecipient: { type: String, trim: true, maxlength: 320, index: true },
  emailSubject: { type: String, trim: true, maxlength: 1000 },
  emailDirection: { type: String, enum: ['incoming', 'outgoing', 'internal', 'unknown'], default: 'unknown', index: true },
  emailMessageId: { type: String, trim: true, maxlength: 512 },
  emailAuth: {
    spf: { type: String, trim: true, maxlength: 32 },
    dkim: { type: String, trim: true, maxlength: 32 },
    dmarc: { type: String, trim: true, maxlength: 32 },
  },
  mailboxEventType: { type: String, trim: true, maxlength: 80, index: true },
  attachmentMimeType: { type: String, trim: true, maxlength: 255 },
  attachmentSize: { type: Number, min: 0 },
  lateralVector: { type: String, trim: true, maxlength: 160 },
  sourceHost: { type: String, trim: true, maxlength: 255 },
  destinationHost: { type: String, trim: true, maxlength: 255 },
  authProtocol: { type: String, trim: true, maxlength: 80 },
  shareName: { type: String, trim: true, maxlength: 512 },
  sessionState: { type: String, trim: true, maxlength: 64 },
  windowsEventId: { type: Number },
  attackPathId: { type: String, trim: true, maxlength: 128 },
  relatedEventIds: [{ type: String, maxlength: 128 }],
  credentialEventType: { type: String, trim: true, maxlength: 120 },
  authResult: { type: String, trim: true, maxlength: 32 },
  failureReason: { type: String, trim: true, maxlength: 1000 },
  sessionId: { type: String, trim: true, maxlength: 256 },
  deviceId: { type: String, trim: true, maxlength: 256 },
  mfaStatus: { type: String, trim: true, maxlength: 64 },
  identityProvider: { type: String, trim: true, maxlength: 120 },
  privilegeLevel: { type: String, trim: true, maxlength: 120 },
  logonType: { type: String, trim: true, maxlength: 64 },
  groupName: { type: String, trim: true, maxlength: 256 },
  targetUser: { type: String, trim: true, maxlength: 256 },
  endpointType: { type: String, trim: true, maxlength: 64 },
  credentialTarget: { type: String, trim: true, maxlength: 512 },
  tokenType: { type: String, trim: true, maxlength: 120 },
  // Data Security / DLP metadata. Never store matched sensitive values or
  // file/clipboard/email bodies in these normalized fields.
  dataEventType: { type: String, trim: true, maxlength: 120 },
  dataClassification: {
    type: String,
    enum: ['Public', 'Internal', 'Confidential', 'Restricted', 'Secret', 'Unknown'],
    default: 'Unknown',
  },
  dlpPattern: { type: String, trim: true, maxlength: 120 },
  dlpMatchCount: { type: Number, min: 0, default: 0 },
  transferChannel: { type: String, trim: true, maxlength: 120 },
  destinationDomain: { type: String, lowercase: true, trim: true, maxlength: 253 },
  transferProtocol: { type: String, trim: true, maxlength: 64 },
  recommendedAction: { type: String },
  aiInvestigation: {
    status: { type: String, enum: ['not_required', 'queued', 'processing', 'completed', 'failed'], default: 'not_required', index: true },
    jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'AiAnalysis', default: null },
    summary: { type: String, default: '', maxlength: 4000 },
    rootCause: { type: String, default: '', maxlength: 4000 },
    confidence: { type: Number, min: 0, max: 100, default: 0 },
    reasoning: { type: String, default: '', maxlength: 8000 },
    recommendedSteps: [{ type: String }],
    completedAt: { type: Date, default: null },
  },
  eventCategory: {
    type: String,
    enum: ['malware','network','file','system','registry','memory','systemchanges','persistence','edr','usb','isolation','other'],
    index: true,
  },

  severity: {
    type: String,
    enum: ['low','medium','high','critical'],
    default: 'low',
  },
  status: {
    type: String,
    enum: ['open','investigating','resolved','false_positive','under_observation'],
    default: 'open',
  },

  // ── Rule 2 / Rule 9: Fail-safe observation state ──────────────────────────
  underObservation: { type: Boolean, default: false }, // true = low confidence, awaiting VT
  vtIntelMissing:   { type: Boolean, default: false }, // true = VT not available / not_found

  // ── Malware specific ──────────────────────────────────────────
  malwareType:  { type: String }, // Trojan, Ransomware, Worm, Backdoor, Miner, Generic
  filePath:     { type: String },
  fileHash:     { type: String }, // SHA256
  fileHashMd5:  { type: String }, // MD5 (from YARA scanner)
  fileName:     { type: String },
  fileAction:   { type: String }, // created, modified, deleted
  fileUser:     { type: String },
  entropy:      { type: Number },
  affectedFiles:{ type: Number },
  affectedDirectory: { type: String },
  extension:    { type: String },
  encryptionSpeed: { type: Number },
  modifiedFilesPerSecond: { type: Number },
  deletedFilesPerSecond: { type: Number },
  renamedFilesPerSecond: { type: Number },
  quarantined:  { type: Boolean, default: false },
  yaraRules:    [{ type: String }], // matched YARA rule names

  // Action the agent/security tool took on the threat
  actionTaken: {
    type: String,
    enum: ['Blocked', 'Allowed', 'Quarantined', 'Deleted', 'Logged Out', 'Isolated', 'None', null],
    default: null,
  },
  // Containment / response status (more granular than actionTaken)
  containmentStatus: {
    type: String,
    enum: ['none', 'blocked', 'block_failed', 'quarantined', 'isolated', 'isolation_failed', 'logged_out', 'logout_failed', 'allowed'],
    default: 'none',
  },
  // Which security tool detected this threat
  detectionSource: { type: String }, // 'YARA', 'ClamAV', 'Suricata', 'Heuristic', 'Manual', etc.
  // When was this threat first and last observed
  firstSeen: { type: Date },
  lastSeen:  { type: Date },
  occurrenceCount: { type: Number, default: 1, min: 1 },

  // ── VirusTotal scan result ────────────────────────────────
  vtScore:          { type: Number },   // 0-100 threat score
  vtDetections:     { type: Number },   // e.g. 12
  vtTotal:          { type: Number },   // e.g. 70
  vtDetectionRatio: { type: String },   // e.g. '12/70'
  vtVerdict:        { type: String },   // malicious / suspicious / clean / not_found
  vtEngines:        [{ type: mongoose.Schema.Types.Mixed }], // [{name, result}] or [string]
  vtScannedAt:      { type: Date },

  // ── Network specific ───────────────────────────────────────
  destip:    { type: String },
  destinationIps: [{ type: String }],
  url:       { type: String },
  domain:    { type: String },
  normalizedDomain: { type: String, lowercase: true, trim: true },
  httpMethod: { type: String },
  requestPath: { type: String },
  statusCode: { type: Number },
  apiVersion: { type: String },
  responseTime: { type: Number },
  requestSize: { type: Number },
  responseSize: { type: Number },
  authType: { type: String },
  wafProvider: { type: String },
  wafRuleId: { type: String },
  wafRuleName: { type: String },
  matchedSignature: { type: String },
  backendService: { type: String },
  backendError: { type: String },
  requestHeaders: { type: mongoose.Schema.Types.Mixed },
  requestPayload: { type: mongoose.Schema.Types.Mixed },
  responseHeaders: { type: mongoose.Schema.Types.Mixed },
  responsePayload: { type: mongoose.Schema.Types.Mixed },
  browser: { type: String },
  userAgent: { type: String },
  referrer: { type: String },
  tlsVersion: { type: String },
  certificateInfo: { type: mongoose.Schema.Types.Mixed },
  resolver: { type: String },
  queryTime: { type: Number },
  queryType: { type: String },
  responseCode: { type: String },
  responseType: { type: String },
  responseIp: { type: String },
  expectedIp: { type: String },
  detectionType: { type: String, index: true },
  sinkholeIp: { type: String },
  threatCategory: { type: String },
  country: { type: String },
  geoCountry: { type: String },
  dnsTelemetryStatus: {
    type: String,
    enum: ['enabled', 'disabled', 'unsupported', 'permission_denied', 'no_recent_data', 'agent_offline'],
  },
  detectionRuleName: { type: String },
  detectionEvidence: { type: mongoose.Schema.Types.Mixed },
  detectionReason: { type: String },
  reputationScore: { type: Number },
  confidenceScore: { type: Number },
  ttl:       { type: Number },
  previousTtl: { type: Number },
  destPort:  { type: Number },
  port:      { type: Number },   // alias for destPort (agent sends 'port')
  srcPort:   { type: Number },
  protocol:  { type: String },
  connectionId: { type: String, index: true },
  connectionState: { type: String, index: true },
  connectionStartTime: { type: Date },
  connectionEndTime: { type: Date },
  connectionDuration: { type: Number },
  networkInterface: { type: String },
  networkAdapter: { type: String },
  ipVersion: { type: Number },
  connectionCount: { type: Number },
  retryCount: { type: Number },
  averageInterval: { type: Number },
  medianInterval: { type: Number },
  jitterSeconds: { type: Number },
  intervalConsistency: { type: Number },
  periodicityScore: { type: Number },
  observationSeconds: { type: Number },
  bytesSent: { type: Number },
  bytesReceived: { type: Number },
  direction: { type: String },   // inbound / outbound
  inbound:   { type: Boolean },  // true=inbound, false=outbound
  blocked:   { type: Boolean, default: false },
  action:    { type: String, enum: ['detected', 'allowed', 'blocked', 'dropped', 'rejected', 'quarantined'], default: 'detected', index: true },
  geoCountry:{ type: String },
  geoStatus: { type: String, enum: ['pending', 'enriched', 'failed'] },
  geoCountryCode: { type: String },
  geoContinent: { type: String },
  geoContinentCode: { type: String },
  geoCity:   { type: String },
  geoRegion: { type: String },
  geoPostal: { type: String },
  geoTimezone: { type: String },
  geoLoc:    { type: String },
  geoISP:    { type: String },
  geoLat:    { type: Number },
  geoLon:    { type: Number },
  gpsLat:    { type: Number },
  gpsLon:    { type: Number },
  gpsAccuracyMeters: { type: Number },
  gpsAltitudeMeters: { type: Number },
  gpsProvider: { type: String },
  gpsStatus: { type: String },
  gpsReason: { type: String },
  gpsObservedAt: { type: Date },
  geoProxy:  { type: Boolean, default: false },
  geoHosting:{ type: Boolean, default: false },
  geoVpn:    { type: Boolean, default: false },
  geoTor:    { type: Boolean, default: false },
  geoRelay:  { type: Boolean, default: false },
  geoAnycast:{ type: Boolean, default: false },
  geoHostname: { type: String },
  geoAbuseEmail: { type: String },
  geoAbusePhone: { type: String },
  geoAbuseAddress: { type: String },
  geoAbuseNetwork: { type: String },
  geoDomainsCount: { type: Number, default: 0 },
  geoAsnRoute: { type: String },
  highRiskCountry: { type: Boolean, default: false },
  asn:       { type: String },
  asnOrg:    { type: String },
  asnDomain: { type: String },
  destAsn:       { type: String },
  destAsnOrg:    { type: String },
  destAsnDomain: { type: String },
  destGeoCountry: { type: String },
  destGeoCountryCode: { type: String },
  destGeoContinent: { type: String },
  destGeoContinentCode: { type: String },
  destGeoCity: { type: String },
  destGeoRegion: { type: String },
  destGeoPostal: { type: String },
  destGeoTimezone: { type: String },
  destGeoLoc:  { type: String },
  destGeoProxy:  { type: Boolean, default: false },
  destGeoHosting:{ type: Boolean, default: false },
  destGeoVpn:    { type: Boolean, default: false },
  destGeoTor:    { type: Boolean, default: false },
  destGeoRelay:  { type: Boolean, default: false },
  destGeoAnycast:{ type: Boolean, default: false },
  destGeoHostname: { type: String },
  destGeoAbuseEmail: { type: String },
  destGeoAbusePhone: { type: String },
  destGeoAbuseAddress: { type: String },
  destGeoAbuseNetwork: { type: String },
  destGeoDomainsCount: { type: Number, default: 0 },
  destGeoAsnRoute: { type: String },

  // ── USB specific ───────────────────────────────────────────
  device:     { type: String },  // device name/id
  usbBlocked: { type: Boolean, default: false },
  deviceVendor: { type: String },
  serialNumber: { type: String },
  usbVendorId: { type: String },
  usbProductId: { type: String },
  deviceType: { type: String },
  mountPath: { type: String },
  fileSize: { type: Number },
  bytesTransferred: { type: Number },
  policyName: { type: String },
  policyId: { type: String, index: true },
  policyCategory: { type: String, index: true },
  policyAction: { type: String },
  policyTriggered: { type: Boolean, default: false, index: true },
  policyActionStatus: { type: String },
  usbPolicyId: { type: String },
  usbPolicyRuleType: { type: String },
  usbDriver: { type: String },
  sensitivityType: { type: String },
  usbEnforcementStatus: { type: String, enum: ['audit', 'enforced', 'failed', 'not_applicable'] },
  usbEnforcementError: { type: String, maxlength: 500 },

  // ── Process / EDR specific ─────────────────────────────────
  processName: { type: String },
  pid:         { type: Number },
  parentPid:   { type: Number },
  parentProcessName: { type: String },
  parentCommandLine: { type: String },
  parentUsername: { type: String },
  userDomain: { type: String },
  processCmdline: { type: String },
  processExe:  { type: String },
  processStatus: { type: String },
  processCpuPercent: { type: Number },
  processMemoryPercent: { type: Number },
  processMemoryMb: { type: Number },
  memoryMetricType: { type: String, enum: ['host', 'process'], index: true },
  memoryTotalBytes: { type: Number },
  memoryUsedBytes: { type: Number },
  memoryAvailableBytes: { type: Number },
  commitChargeBytes: { type: Number },
  memoryPressure: { type: Number },
  swapTotalBytes: { type: Number },
  swapUsedBytes: { type: Number },
  swapPercent: { type: Number },
  pageFaults: { type: Number },
  majorPageFaults: { type: Number },
  pagingRate: { type: Number },
  oomEvents: { type: Number },
  containerMemoryBytes: { type: Number },
  containerMemoryLimitBytes: { type: Number },
  containerOomEvents: { type: Number },
  processRssBytes: { type: Number },
  virtualMemoryBytes: { type: Number },
  privateWorkingSetBytes: { type: Number },
  sharedMemoryBytes: { type: Number },
  peakMemoryBytes: { type: Number },
  memoryGrowthBytes: { type: Number },
  memoryGrowthPercent: { type: Number },
  memoryAllocationRate: { type: Number },
  threadCount: { type: Number },
  handleCount: { type: Number },
  crashCount: { type: Number },
  restartCount: { type: Number },
  executableRegionCount: { type: Number },
  rwxRegionCount: { type: Number },
  isSimulated: { type: Boolean, default: false, index: true },
  processDiskReadBytes: { type: Number },
  processDiskWriteBytes: { type: Number },
  processDiskReadBytesPerSecond: { type: Number },
  processDiskWriteBytesPerSecond: { type: Number },
  processNetworkConnectionCount: { type: Number },
  processExternalConnectionCount: { type: Number },
  processRemoteAddresses: [{ type: String }],
  processUniqueRemoteIpCount: { type: Number },
  processUniqueRemotePortCount: { type: Number },
  processPrivateRemoteIpCount: { type: Number },
  processClassifications: [{ type: String }],
  processExecutableSha256: { type: String },
  processSignatureStatus: { type: String },
  processTrustStatus: { type: String },
  processPublisher: { type: String },
  processPackageOwner: { type: String },
  processPackageVerificationStatus: { type: String },
  processCreateTime: { type: Date },
  processEndTime: { type: Date },
  processExitCode: { type: Number },
  processIntegrityLevel: { type: String },
  processFileCompany: { type: String },
  processFileVersion: { type: String },
  processExecutableMd5: { type: String },
  processCount: { type: Number },

  // ── Script Execution Monitoring (capability 21) ───────────────────────
  scriptName: { type: String },
  scriptPath: { type: String },
  scriptHash: { type: String, lowercase: true },
  scriptSha1: { type: String, lowercase: true },
  scriptMd5: { type: String, lowercase: true },
  interpreter: { type: String, index: true },
  commandLine: { type: String },
  executionSource: { type: String },
  obfuscationScore: { type: Number, min: 0, max: 100 },
  detectionReasons: [{ type: String }],
  processTree: [{ type: mongoose.Schema.Types.Mixed }],
  childProcesses: [{ type: mongoose.Schema.Types.Mixed }],
  networkConnections: [{ type: mongoose.Schema.Types.Mixed }],
  filesCreated: [{ type: String }],
  filesModified: [{ type: String }],
  filesDeleted: [{ type: String }],

  // ── Kernel-Level Monitoring (capability 19) ────────────────────────
  kernelEventType: { type: String },
  kernelCategory: { type: String },
  kernelVersion: { type: String },
  driverName: { type: String },
  driverPath: { type: String },
  driverVersion: { type: String },
  driverState: { type: String },
  driverStartMode: { type: String },
  moduleName: { type: String },
  modulePath: { type: String },
  moduleSignature: { type: String },
  moduleTaint: { type: String },
  vulnerableDriver: { type: Boolean, default: false },
  syscallName: { type: String },
  syscallCount: { type: Number },
  callbackType: { type: String },
  memoryProtection: { type: String },
  secureBootStatus: { type: String },
  codeIntegrityStatus: { type: String },
  patchGuardStatus: { type: String },
  kernelPosture: { type: mongoose.Schema.Types.Mixed },

  // ── Hash / Signature Analysis (capability 25) ──────────────────────────
  sha256: { type: String, lowercase: true, match: /^[a-f0-9]{64}$/ },
  sha1: { type: String, lowercase: true, match: /^[a-f0-9]{40}$/ },
  md5: { type: String, lowercase: true, match: /^[a-f0-9]{32}$/ },
  signatureStatus: { type: String },
  publisher: { type: String },
  certificateSubject: { type: String },
  certificateIssuer: { type: String },
  certificateSerial: { type: String },
  certificateThumbprint: { type: String },
  certificateValidFrom: { type: Date },
  certificateValidUntil: { type: Date },
  certificateRevocationStatus: { type: String },
  trustStatus: { type: String },
  packageOwner: { type: String },
  packageVerificationStatus: { type: String },
  baselineHash: { type: String, lowercase: true },
  currentHash: { type: String, lowercase: true },
  hashMismatch: { type: Boolean, default: false },
  hashSignatureRule: { type: String },
  hashSignatureRiskScore: { type: Number, min: 0, max: 100 },
  hashSignatureSeverity: { type: String, enum: ['low', 'medium', 'high', 'critical'] },
  hashSignatureMonitoringEnabled: { type: Boolean },
  hashSignatureThreatIntelEnabled: { type: Boolean },
  hashSignaturePolicyThreshold: { type: Number, min: 0, max: 100 },
  hashSignatureAlertEligible: { type: Boolean, default: false },
  riskReasons: [{ type: String }],
  threatIntelMatch: { type: Boolean, default: false },
  threatIntelSource: { type: String },
  reputation: { type: String },
  malwareFamily: { type: String },
  allowlisted: { type: Boolean, default: false },
  telemetryProvider: { type: String, index: true },
  providerChannel: { type: String },
  providerEventId: { type: Number },
  providerRecordId: { type: Number },
  evidenceType: { type: String, index: true },
  coverageStatus: { type: String },
  sensorStatus: { type: mongoose.Schema.Types.Mixed },
  sourceProcessName: { type: String },
  sourcePid: { type: Number },
  targetProcessName: { type: String },
  targetPid: { type: Number },
  imageLoaded: { type: String },
  grantedAccess: { type: String },
  callTrace: { type: String },
  attributionConfidence: { type: String },
  inventoryType: { type: String, index: true },
  inventoryName: { type: String },
  inventoryCount: { type: Number },
  inventorySnapshotId: { type: String },
  inventoryBatchIndex: { type: Number },
  inventoryBatchCount: { type: Number },
  inventoryItems: { type: mongoose.Schema.Types.Mixed },
  inventoryItem: { type: mongoose.Schema.Types.Mixed },
  oldInventoryItem: { type: mongoose.Schema.Types.Mixed },
  changeType: { type: String },
  // Persistence Mechanism Detection (capability 8). The detailed native
  // object remains in inventoryItem/rawEvent; these indexed scalar fields
  // support fast tenant-scoped hunting and reporting.
  persistenceType: { type: String, index: true },
  persistenceLocation: { type: String },
  persistenceKey: { type: String },
  persistenceValue: { type: mongoose.Schema.Types.Mixed },
  persistenceTrigger: { type: String },
  persistenceAction: { type: String },
  // System Changes Monitoring (capability 7). Alerts remain the canonical
  // event store; these normalized fields make tenant-scoped filtering and
  // reporting independent of collector-specific raw payload shapes.
  systemChangeCategory: { type: String, index: true },
  systemChangeType: { type: String, index: true },
  systemChangeTarget: { type: String },
  previousState: { type: mongoose.Schema.Types.Mixed },
  newState: { type: mongoose.Schema.Types.Mixed },
  baselineStatus: { type: String, index: true },
  changeSource: { type: String },
  changeTicket: { type: String },
  maintenanceApproved: { type: Boolean, default: false },
  systemChangeIndicators: [{ type: String }],
  // ── Registry & System Configuration Monitoring (capability 6) ────────
  configurationCategory: { type: String, index: true },
  configurationOperation: { type: String, index: true },
  configurationObject: { type: String },
  configurationPlatform: { type: String, index: true },
  configurationBaselineStatus: { type: String, index: true },
  configurationPolicyId: { type: String },
  configurationPolicyViolation: { type: Boolean, default: false, index: true },
  configurationRiskFactors: [{ type: String }],
  registryHive: { type: String },
  registryValueName: { type: String },
  registryValueType: { type: String },
  processAttribution: { type: String },
  // ── Service Monitoring (capability 24) ────────────────────────────────
  serviceName: { type: String },
  serviceDisplayName: { type: String },
  serviceEventType: { type: String },
  servicePreviousStatus: { type: String },
  serviceCurrentStatus: { type: String },
  serviceStartupType: { type: String },
  serviceAccount: { type: String },
  serviceBinaryPath: { type: String },
  serviceBinarySha256: { type: String, lowercase: true },
  serviceBinarySha1: { type: String, lowercase: true },
  serviceBinaryMd5: { type: String, lowercase: true },
  serviceSignatureStatus: { type: String },
  servicePublisher: { type: String },
  servicePackageOwner: { type: String },
  servicePackageVerificationStatus: { type: String },
  serviceDependencies: [{ type: String }],
  servicePid: { type: Number },
  serviceRestartCount: { type: Number },
  serviceUnitPath: { type: String },
  serviceSecurityCritical: { type: Boolean, default: false },
  suspiciousServicePath: { type: Boolean, default: false },
  workloadType: { type: String, index: true },
  workloadCounts: { type: mongoose.Schema.Types.Mixed },
  listenerPorts: [{ type: Number }],
  runtimeType: { type: String, index: true },
  containerId: { type: String },
  podName: { type: String },
  namespace: { type: String },
  containerRisks: [{ type: String }],
  username:    { type: String },
  userAction:  { type: String }, // login, logout, suspicious_cmd, privilege_escalation
  sourcePath:  { type: String },
  keyPath:     { type: String },
  registryKey: { type: String },
  oldValue:    { type: mongoose.Schema.Types.Mixed },
  newValue:    { type: mongoose.Schema.Types.Mixed },
  oldHash:     { type: String },
  newHash:     { type: String },
  hashAlgorithm: { type: String },
  hash:        { type: String },
  mitreId:     { type: String },
  technique:   { type: String },
  mitreTactic: { type: String },
  mitreTechnique: { type: String, index: true },
  mitreTechniques: [{ type: String }],

  // ── LOLBins detection fields ────────────────────────────────
  processName:        { type: String },
  processExe:         { type: String },
  processCmdline:     { type: String },
  pid:                { type: Number },
  parentPid:          { type: Number },
  parentProcessName:  { type: String },
  riskScore:          { type: Number, default: 0 },
  matchedPatterns:    [{ type: String }],
  isNetwork:          { type: Boolean },
  isPersistence:      { type: Boolean },

  // ── Ransomware/encryption detection fields ──────────────────
  source:             { type: String },   // 'lolbins' | 'ransomware' | 'auto_response' | etc.

  // ── Isolation tracking ─────────────────────────────────────
  isolated:        { type: Boolean, default: false },
  isolatedAt:      { type: Date },
  isolationReason: { type: String },
  isolationStatus: { type: String }, // isolated / reconnected

  // ── Assignment & notes ─────────────────────────────────────
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  incidentId: { type: mongoose.Schema.Types.ObjectId, ref: 'EdrIncident', default: null, index: true },
  ticketOpenedAt: { type: Date, default: null, index: true },
  ticketOpenedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  ticketQueuedAt: { type: Date, default: null, index: true },
  ticketRoutedAt: { type: Date, default: null, index: true },
  ticketSource: { type: String, enum: ['soar', 'manager', 'analyst', 'system', 'legacy', null], default: null, index: true },
  ticketCategory: { type: String, default: 'general', trim: true, maxlength: 80, index: true },
  ticketAssignmentMode: { type: String, enum: ['auto', 'manual', 'self', null], default: null },
  // An alert may become a ticket or incident, never both. This discriminator
  // is claimed atomically before either record type is created.
  socCaseType: { type: String, enum: ['ticket', 'incident', null], default: null, index: true },
  socCaseTypeSetAt: { type: Date, default: null },
  resolvedAt: { type: Date },
  notes: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    at:   Date,
  }],

  iocMatched: { type: Boolean, default: false, index: true },
  iocMatches: [{
    indicator: String, type: String, source: String, reputation: String,
    confidenceScore: Number, firstSeen: Date, lastSeen: Date,
    malware: [String], threatActor: String, campaign: String,
    recommendedResponse: String,
  }],
  correlationIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'CorrelationEvent' }],
  investigationTimeline: [{
    type: { type: String }, at: { type: Date, default: Date.now },
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, detail: String,
  }],
  auditHistory: [{
    action: String, at: { type: Date, default: Date.now },
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, metadata: mongoose.Schema.Types.Mixed,
  }],
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },

  rawEvent: { type: mongoose.Schema.Types.Mixed },

  // ── Threat Intelligence enrichment (from threat-intel.service.js) ──────────
  tiEnriched:         { type: Boolean, default: false },
  tiConfidence:       { type: Number  },   // 0-100 confidence score
  tiSummary:          { type: String  },   // human-readable summary
  tiDomain:           { type: String  },   // DNS alert enriched domain
  tiDomainMalicious:  { type: Boolean },   // is the domain malicious per OTX
  tiFeeds: {
    abuseScore:        { type: Number },
    otxPulses:         { type: Number },
    feedSource:        { type: String },
    malwareFamilies:   { type: [String], set: value => normalizeThreatLabels(value, { limit: 10 }) },
  },
  tiBlockedAt:        { type: Date },      // when TI auto-block was applied
}, { timestamps: true });

AlertSchema.index({ tenantId: 1, companyId: 1, createdAt: -1 });
AlertSchema.index({ tenantId: 1, partnerId: 1, createdAt: -1 });
// Critical Kafka idempotency lookup. Production collections can already
// contain legacy duplicate eventIds, so keep this sparse/non-unique until the
// dedicated dedup migration promotes it to a unique index.
AlertSchema.index({ companyId: 1, eventId: 1 }, { name: 'company_event_id_lookup', sparse: true });
AlertSchema.index(
  { companyId: 1, eventFingerprint: 1 },
  {
    name: 'company_event_fingerprint_unique',
    unique: true,
    partialFilterExpression: { eventFingerprint: { $type: 'string' } },
  },
);
AlertSchema.index({ companyId: 1, sourceType: 1, eventTimestamp: -1 });
AlertSchema.index({ companyId: 1, action: 1, eventTimestamp: -1 });
AlertSchema.index({ companyId: 1, username: 1, eventTimestamp: -1 });
AlertSchema.index({ companyId: 1, hostname: 1, eventTimestamp: -1 });
AlertSchema.index({ companyId: 1, signatureId: 1, eventTimestamp: -1 });
AlertSchema.index({ companyId: 1, iocMatched: 1, eventTimestamp: -1 });
AlertSchema.index({ companyId: 1, ticketCategory: 1, assignedTo: 1, status: 1 });
AlertSchema.index({ companyId: 1, source: 1, sensorEventType: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, communityId: 1, createdAt: -1 }, { sparse: true });

AlertSchema.index({ companyId: 1, eventCategory: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, createdAt: -1, capabilityIds: 1 });
AlertSchema.index({ companyId: 1, isSynthetic: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, domain: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, destip: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, normalizedDomain: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, srcip: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, endpointId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, severity: 1, status: 1, createdAt: -1 });
AlertSchema.index({ tenantId: 1, capabilityId: 1, agentId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, fimModule: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, eventCategory: 1, ruleId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, ruleId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, severity: 1 });
AlertSchema.index({ companyId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, systemId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, systemId: 1, createdAt: -1 });
// Analyst dashboards repeatedly filter personal queues by assignee/status and
// then sort the newest alerts. Keep these reads off full collection scans.
AlertSchema.index({ companyId: 1, assignedTo: 1, status: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, severity: 1, status: 1, createdAt: -1 });
AlertSchema.index({ assignedTo: 1, resolvedAt: -1 });
AlertSchema.index({ companyId: 1, srcip: 1, destip: 1, ruleId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, destip: 1, destPort: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, processName: 1, destip: 1, createdAt: -1 });
AlertSchema.index({ fileHash: 1 }, { sparse: true });
AlertSchema.index({ vtScore: -1 }, { sparse: true });
AlertSchema.index({ expiresAt: 1 }, { name: 'expires_at_ttl', expireAfterSeconds: 0, sparse: true });
AlertSchema.index({ companyId: 1, archivedAt: 1, createdAt: 1 });
// LOLBins + Ransomware detection indexes
AlertSchema.index({ companyId: 1, source: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, processName: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, riskScore: -1, createdAt: -1 });
AlertSchema.index({ companyId: 1, mitreId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, departmentId: 1, capabilityIds: 1, configurationCategory: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, configurationPlatform: 1, configurationOperation: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, configurationPolicyViolation: 1, riskScore: -1, createdAt: -1 });
AlertSchema.index({ companyId: 1, memoryMetricType: 1, systemId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, detectionRuleId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, eventType: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, departmentId: 1, capabilityIds: 1, authResult: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, username: 1, riskScore: -1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, srcip: 1, authType: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, systemChangeCategory: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, systemChangeType: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, baselineStatus: 1, riskScore: -1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, persistenceType: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, mitreTechnique: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityIds: 1, hostname: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, interpreter: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, scriptHash: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, serialNumber: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, usbPolicyId: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, emailDirection: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, threatCategory: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, capabilityId: 1, mailboxEventType: 1, createdAt: -1 });

// ── IDS/IPS dashboard compound indexes ───────────────────────────────────────
// The strictIdsIpsAlertMatch filter always starts with { companyId, createdAt }
// and then adds module/source_type/source/type OR conditions.
// These indexes let MongoDB use index-covered scans instead of full collection scans.
AlertSchema.index({ companyId: 1, module: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, source_type: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, event_category: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, blocked: 1, createdAt: -1 });
AlertSchema.index({ companyId: 1, srcip: 1, createdAt: -1 });

AlertSchema.pre('validate', async function (next) {
  // Older collectors stored aliases such as `dns`. Normalize them before
  // Mongoose enum validation whenever those records are touched again.
  this.eventCategory = normalizeEventCategory(this.eventCategory, 'other');
  const { applyCapabilityTelemetry } = require('../utils/capabilityTelemetry');
  applyCapabilityTelemetry(this);
  if (this.companyId && (!this.tenantId || this.isModified('companyId') || !this.expiresAt)) {
    const Company = require('./Company.model');
    const company = await Company.findById(this.companyId).select('tenantId partnerId retentionPolicy').lean();
    if (company) {
      this.tenantId = company.tenantId || this.tenantId;
      this.partnerId = company.partnerId || null;
      if (!this.expiresAt && !company.retentionPolicy?.legalHold) {
        const { applyRetention } = require('../utils/retentionPolicy');
        this.expiresAt = applyRetention(this.toObject(), company.retentionPolicy, this.createdAt).expiresAt;
      }
    }
  }
  next();
});

AlertSchema.pre('insertMany', async function (next, docs) {
  try {
    const { applyCapabilityTelemetry } = require('../utils/capabilityTelemetry');
    for (const doc of docs || []) applyCapabilityTelemetry(doc);
    const Company = require('./Company.model');
    const companyIds = [...new Set((docs || []).map(doc => String(doc.companyId || '')).filter(Boolean))];
    const companies = await Company.find({ _id: { $in: companyIds } }).select('tenantId partnerId retentionPolicy').lean();
    const scopeByCompany = companies.reduce((acc, company) => {
      acc[String(company._id)] = company;
      return acc;
    }, {});
    for (const doc of docs || []) {
      const company = scopeByCompany[String(doc.companyId || '')];
      if (!company) continue;
      if (!doc.tenantId) doc.tenantId = company.tenantId || null;
      if (!doc.partnerId) doc.partnerId = company.partnerId || null;
      if (!doc.expiresAt && !company.retentionPolicy?.legalHold) {
        const { applyRetention } = require('../utils/retentionPolicy');
        doc.expiresAt = applyRetention(doc, company.retentionPolicy, doc.createdAt).expiresAt;
      }
    }
    next();
  } catch (err) {
    next(err);
  }
});

module.exports = mongoose.model('Alert', AlertSchema);
