/**
 * edrdashbordpage — Barrel Index
 *
 * Sab 31 EDR capability pages ek jagah se import karo.
 *
 * Usage:
 *   import { ProcessActivityMonitoringPage } from './edrdashbordpage';
 *   import FileActivityMonitoringPage from './edrdashbordpage/File Activity Monitoring (FIM)';
 */

// ─── EDR Sub Routes (App.jsx routes component) ───────────────────────────────
export { default as EDRSubRoutes } from './EDRSubRoutes';

// ─── Cap 1 — Process Activity Monitoring ─────────────────────────────────────
export { default as ProcessActivityMonitoringPage } from './Process Activity Monitoring';

// ─── Cap 2 — File Activity Monitoring (FIM) ──────────────────────────────────
export { default as FileActivityMonitoringPage } from './File Activity Monitoring (FIM)';

// ─── Cap 3 — Network Activity Monitoring ─────────────────────────────────────
export { default as NetworkActivityMonitoringPage } from './Network Activity Monitoring';

// ─── Cap 4 — User & Authentication Monitoring ────────────────────────────────
export { default as UserAuthMonitoringPage } from './User & Authentication Monitoring';

// ─── Cap 5 — Memory Activity Monitoring ──────────────────────────────────────
export { default as MemoryActivityMonitoringPage } from './Memory Activity Monitoring';

// ─── Cap 6 — Registry Monitoring ─────────────────────────────────────────────
export { default as RegistryMonitoringPage } from './Registry Monitoring';

// ─── Cap 7 — System Changes Monitoring ───────────────────────────────────────
export { default as SystemChangesMonitoringPage } from './System Changes Monitoring';

// ─── Cap 8 — Persistence Mechanism Detection ─────────────────────────────────
export { default as PersistenceDetectionPage } from './Persistence Mechanism Detection';

// ─── Cap 9 — Web & DNS Monitoring ────────────────────────────────────────────
export { default as WebDnsMonitoringPage } from './Web & DNS Monitoring';

// ─── Cap 10 — Device Control (USB) Monitoring ────────────────────────────────
export { default as UsbMonitoringPage } from './Device Control (USB) Monitoring';

// ─── Cap 11 — Behavioral Analytics (UEBA) ────────────────────────────────────
export { default as UebaPage } from './Behavioral Analytics (UEBA)';

// ─── Cap 12 — Log Monitoring & Correlation ───────────────────────────────────

// ─── Cap 13 — Data Security Monitoring ───────────────────────────────────────
export { default as DataSecurityMonitoringPage } from './Data Security Monitoring';

// ─── Cap 14 — Credential Security Monitoring ─────────────────────────────────
export { default as CredentialSecurityPage } from './Credential Security Monitoring';

// ─── Cap 15 — Exploit Detection ──────────────────────────────────────────────

// ─── Cap 16 — Lateral Movement Detection ─────────────────────────────────────
export { default as LateralMovementPage } from './Lateral Movement Detection';

// ─── Cap 18 — Email Threat Monitoring ────────────────────────────────────────
export { default as EmailThreatPage } from './Email Threat Monitoring';

// ─── Cap 19 — Insider Threat Detection ───────────────────────────────────────
export { default as InsiderThreatPage } from './Insider Threat Detection';

// ─── Cap 20 — Patch & Vulnerability Monitoring ───────────────────────────────
export { default as PatchVulnerabilityPage } from './Patch & Vulnerability Monitoring';

// ─── Cap 21 — Sandbox Analysis ───────────────────────────────────────────────
export { default as SandboxAnalysisPage } from './Sandbox Analysis';

// ─── Cap 22 — Kernel-Level Monitoring ────────────────────────────────────────
export { default as KernelMonitoringPage } from './Kernel-Level Monitoring';

// ─── Cap 23 — API Call Monitoring ────────────────────────────────────────────
export { default as ApiCallMonitoringPage } from './API Call Monitoring';

// ─── Cap 24 — Script Execution Monitoring ────────────────────────────────────
export { default as ScriptExecutionPage } from './Script Execution Monitoring';

// ─── Cap 26 — Time-Based Anomaly Detection ───────────────────────────────────
export { default as TimeAnomalyPage } from './Time-Based Anomaly Detection';

// ─── Cap 27 — Geolocation Anomaly Detection ──────────────────────────────────
export { default as GeoAnomalyPage } from './Geolocation Anomaly Detection';

// ─── Cap 28 — Service Monitoring ─────────────────────────────────────────────
export { default as ServiceMonitoringPage } from './Service Monitoring';

// ─── Cap 31 — Beaconing Detection ────────────────────────────────────────────
export { default as BeaconingDetectionPage } from './Beaconing Detection';

// ─── Cap 32 — Encryption / Ransomware Detection ──────────────────────────────
export { default as RansomwareDetectionPage } from './Encryption Ransomware Detection';

// ─── Cap 33 — Living-off-the-Land (LOLBins) Detection ────────────────────────
export { default as LolbinsDetectionPage } from './Living-off-the-Land (LOLBins) Detection';

// ─── Cap 35 — Automated Response Capability ──────────────────────────────────

// ─── Cap 36 — Memory Overflow Detection ──────────────────────────────────────
export { default as MemoryOverflowPage } from './Memory Overflow Detection';

// ─── Cap 37 — DNS Cache Poisoning Detection ──────────────────────────────────
export { default as DnsCachePoisoningPage } from './DNS Cache Poisoning Detection';

// ─── Cap 38 — DNS Sinkhole ───────────────────────────────────────────────────
export { default as DnsSinkholePage } from './DNS Sinkhole';

// ─── Shared primitives ────────────────────────────────────────────────────────
export {
  ProcessActivityDashboardPanel,
  summaryInventoryRows,
  procName,
  procMem,
  SEV,
  SEVBG,
  RISK,
  VtBadge,
  vtIsThreaten,
  processStatusSafe,
  processStatusStyle,
} from './Process Activity Monitoring';

// ─── SubTabPage exports (App.jsx routes ke liye) ──────────────────────────────
// Ye sab App.jsx mein routes pe use hote hain jaise:
// <Route path="/edr-dashboard-details/process/:tab" element={<ProcessSubTabPage />} />

export { ProcessSubTabPage }                   from './Process Activity Monitoring';
export { FIMSubTabPage, FIM_TABS }             from './File Activity Monitoring (FIM)';
export { NetworkSubTabPage }                   from './Network Activity Monitoring';
export { AuthSubTabPage }                      from './User & Authentication Monitoring';
export { MemorySubTabPage }                    from './Memory Activity Monitoring';
export { RegistrySubTabPage }                  from './Registry Monitoring';
export { SystemChangesSubTabPage }             from './System Changes Monitoring';
export { PersistenceSubTabPage }               from './Persistence Mechanism Detection';
export { WebDnsSubTabPage }                    from './Web & DNS Monitoring';
export { UsbSubTabPage }                       from './Device Control (USB) Monitoring';
export { UebaSubTabPage }                      from './Behavioral Analytics (UEBA)';
export { DataSecuritySubTabPage }              from './Data Security Monitoring';
export { CredentialSecuritySubTabPage }        from './Credential Security Monitoring';
export { LateralMovementSubTabPage }           from './Lateral Movement Detection';
export { EmailThreatSubTabPage }               from './Email Threat Monitoring';
export { InsiderThreatSubTabPage }             from './Insider Threat Detection';
export { PatchVulnerabilitySubTabPage }        from './Patch & Vulnerability Monitoring';
export { SandboxAnalysisSubTabPage }           from './Sandbox Analysis';
export { KernelMonitoringSubTabPage }          from './Kernel-Level Monitoring';
export { ApiCallMonitoringSubTabPage }         from './API Call Monitoring';
export { ScriptExecutionSubTabPage }           from './Script Execution Monitoring';
export { TimeAnomalySubTabPage }               from './Time-Based Anomaly Detection';
export { GeoAnomalySubTabPage }                from './Geolocation Anomaly Detection';
export { ServiceMonitoringSubTabPage }         from './Service Monitoring';
export { BeaconingSubTabPage }                 from './Beaconing Detection';
export { RansomwareSubTabPage }                from './Encryption Ransomware Detection';
export { LolbinsSubTabPage }                   from './Living-off-the-Land (LOLBins) Detection';
export { MemoryOverflowSubTabPage }            from './Memory Overflow Detection';
export { DnsCachePoisoningSubTabPage }         from './DNS Cache Poisoning Detection';
export { DnsSinkholeSubTabPage }               from './DNS Sinkhole';
