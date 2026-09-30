/**
 * EDRSubRoutes.jsx
 * 
 * Sab /edr-dashboard-details/* routes yahan hain.
 * App.jsx mein sirf yeh ek import kaafi hai.
 */
import React from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
const CapabilityDataPage = () => null;
const CapabilityAgentsPage = () => null;
const ProcessSubTabPage = () => null;
import {
  FIMSubTabPage,
  NetworkSubTabPage,
  AuthSubTabPage,
  MemorySubTabPage,
  RegistrySubTabPage,
  SystemChangesSubTabPage,
  PersistenceSubTabPage,
  WebDnsSubTabPage,
  UsbSubTabPage,
  UebaSubTabPage,
  DataSecuritySubTabPage,
  CredentialSecuritySubTabPage,
  LateralMovementSubTabPage,
  EmailThreatSubTabPage,
  InsiderThreatSubTabPage,
  PatchVulnerabilitySubTabPage,
  SandboxAnalysisSubTabPage,
  KernelMonitoringSubTabPage,
  ApiCallMonitoringSubTabPage,
  ScriptExecutionSubTabPage,
  TimeAnomalySubTabPage,
  GeoAnomalySubTabPage,
  ServiceMonitoringSubTabPage,
  BeaconingSubTabPage,
  RansomwareSubTabPage,
  LolbinsSubTabPage,
  MemoryOverflowSubTabPage,
  DnsCachePoisoningSubTabPage,
  DnsSinkholeSubTabPage,
} from './index';

// Guard is passed as a prop from App.jsx — no need to redefine it here

export default function EDRSubRoutes({ Guard }) {
  return (
    <Routes>
      <Route path="threatintel/*" element={<Navigate to="/company-admin/threat-intelligence" replace />} />
      <Route path="threatintegration/*" element={<Navigate to="/company-admin/threat-intelligence" replace />} />
      <Route path="process/:tab"              element={<Guard><ProcessSubTabPage /></Guard>} />
      <Route path="network/activity-logs"     element={<Guard><CapabilityDataPage kind="network" mode="activity" /></Guard>} />
      <Route path="network/alert-logs"        element={<Guard><CapabilityDataPage kind="network" mode="alerts" /></Guard>} />
      <Route path="network/:tab"              element={<Guard><NetworkSubTabPage /></Guard>} />
      <Route path="auth/activity-logs"        element={<Guard><CapabilityDataPage kind="auth" mode="activity" /></Guard>} />
      <Route path="auth/alert-logs"           element={<Guard><CapabilityDataPage kind="auth" mode="alerts" /></Guard>} />
      <Route path="auth/agents"               element={<Guard><CapabilityAgentsPage kind="auth" /></Guard>} />
      <Route path="auth/:tab"                 element={<Guard><AuthSubTabPage /></Guard>} />
      <Route path="memory/:tab"               element={<Guard><MemorySubTabPage /></Guard>} />
      <Route path="registry/activity-logs"    element={<Guard><CapabilityDataPage kind="registry" mode="activity" /></Guard>} />
      <Route path="registry/alert-logs"       element={<Guard><CapabilityDataPage kind="registry" mode="alerts" /></Guard>} />
      <Route path="registry/agents"           element={<Guard><CapabilityAgentsPage kind="registry" /></Guard>} />
      <Route path="registry/:tab"             element={<Guard><RegistrySubTabPage /></Guard>} />
      <Route path="systemchanges/:tab"        element={<Guard><SystemChangesSubTabPage /></Guard>} />
      <Route path="persistence/:tab"          element={<Guard><PersistenceSubTabPage /></Guard>} />
      <Route path="webdns/:tab"               element={<Guard><WebDnsSubTabPage /></Guard>} />
      <Route path="usb/:tab"                  element={<Guard><UsbSubTabPage /></Guard>} />
      <Route path="ueba/:tab"                 element={<Guard><UebaSubTabPage /></Guard>} />
      <Route path="datasecurity/:tab"         element={<Guard><DataSecuritySubTabPage /></Guard>} />
      <Route path="credentialsecurity/:tab"   element={<Guard><CredentialSecuritySubTabPage /></Guard>} />
      <Route path="lateralmovement/:tab"      element={<Guard><LateralMovementSubTabPage /></Guard>} />
      <Route path="emailthreat/:tab"          element={<Guard><EmailThreatSubTabPage /></Guard>} />
      <Route path="insiderthreat/:tab"        element={<Guard><InsiderThreatSubTabPage /></Guard>} />
      <Route path="patchvulnerability/:tab"   element={<Guard><PatchVulnerabilitySubTabPage /></Guard>} />
      <Route path="sandboxanalysis/:tab"      element={<Guard><SandboxAnalysisSubTabPage /></Guard>} />
      <Route path="kernelmonitoring/:tab"     element={<Guard><KernelMonitoringSubTabPage /></Guard>} />
      <Route path="apicallmonitoring/:tab"    element={<Guard><ApiCallMonitoringSubTabPage /></Guard>} />
      <Route path="scriptmonitoring/:tab"     element={<Guard><ScriptExecutionSubTabPage /></Guard>} />
      <Route path="timeanomaly/:tab"          element={<Guard><TimeAnomalySubTabPage /></Guard>} />
      <Route path="geoanomaly/:tab"           element={<Guard><GeoAnomalySubTabPage /></Guard>} />
      <Route path="servicemonitoring/:tab"    element={<Guard><ServiceMonitoringSubTabPage /></Guard>} />
      <Route path="beaconing/:tab"            element={<Guard><BeaconingSubTabPage /></Guard>} />
      <Route path="ransomware/:tab"           element={<Guard><RansomwareSubTabPage /></Guard>} />
      <Route path="lolbins/:tab"              element={<Guard><LolbinsSubTabPage /></Guard>} />
      <Route path="memoryoverflow/:tab"       element={<Guard><MemoryOverflowSubTabPage /></Guard>} />
      <Route path="dnscachepoisoning/:tab"    element={<Guard><DnsCachePoisoningSubTabPage /></Guard>} />
      <Route path="dnssinkhole/:tab"          element={<Guard><DnsSinkholeSubTabPage /></Guard>} />
      <Route path="fim/activity"              element={<Guard><CapabilityDataPage kind="fim" mode="activity" /></Guard>} />
      <Route path="fim/alert-logs"            element={<Guard><CapabilityDataPage kind="fim" mode="alerts" /></Guard>} />
      <Route path="fim"                       element={<Guard><FIMSubTabPage /></Guard>} />
      <Route path="fim/:tab"                  element={<Guard><FIMSubTabPage /></Guard>} />
    </Routes>
  );
}
