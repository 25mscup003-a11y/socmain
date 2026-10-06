import { useEffect, useState, createContext, useContext as _useContext } from 'react';
import { Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useAuth } from './context/AuthContext';
import api from './api/axios';

import LoginPage from './pages/LoginPage';
import HomePage from './pages/HomePage';
import PartnerRegistrationPage from './pages/PartnerRegistrationPage';
import RegisterPage from './pages/RegisterPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import AcceptInvitePage from './pages/AcceptInvitePage';

// Company admin / dept admin pages
import DashboardPage from './pages/DashboardPage';
import PartnerDashboardPage from './pages/PartnerDashboardPage';
import PartnerAuditPage from './pages/PartnerAuditPage';
import PartnerPaymentPage from './pages/PartnerPaymentPage';
import AlertsPage from './pages/AlertsPage';
import DepartmentsPage from './pages/DepartmentsPage';
import SystemsPage from './pages/SystemsPage';
import SystemSetupPage from './pages/SystemSetupPage';
import EDRSystemSetupPage from './pages/EDRSystemSetupPage';
import EDRSystemSystemsPage from './pages/EDRSystemSystemsPage';
import DnsSinkholeSetupPage from './pages/DnsSinkholeSetupPage';
import DnsCachePoisoningSetupPage from './pages/DnsCachePoisoningSetupPage';
import RansomwareSetupPage from './pages/RansomwareSetupPage';
import MemoryOverflowSetupPage from './pages/MemoryOverflowSetupPage';
import BeaconingSetupPage from './pages/BeaconingSetupPage';
import TimeAnomalySetupPage from './pages/TimeAnomalySetupPage';
import SystemMonitoringDashboard from './pages/SystemMonitoringDashboard';
import MonitoringPage from './pages/MonitoringPage';
import AgentDownloadPage from './pages/AgentDownloadPage';
import SoarPage from './pages/SoarPage';
import ReportsPage from './pages/ReportsPage';
import PaymentsPage from './pages/PaymentsPage';
import CheckoutPage from './pages/CheckoutPage';
import AgentLicenseCheckoutPage from './pages/AgentLicenseCheckoutPage';
import SettingsPage from './pages/SettingsPage';
import TeamPage from './pages/TeamPage';

// Analyst-only pages
import AnalystDashboard from './pages/analyst/AnalystDashboard';
import AnalystAlerts from './pages/analyst/AnalystAlerts';
import AnalystReports from './pages/analyst/AnalystReports';
import AnalystSettings from './pages/analyst/AnalystSettings';

import Layout from './components/Layout';
import PartnerUserPasswords from './components/PartnerUserPasswords';
import AnalystLayout from './components/AnalystLayout';
import SocDashboardLayout, { DASHBOARD as SOC_DASHBOARD } from './components/SocDashboardLayout';
import LogMonitorDashboard from './pages/LogMonitorDashboard';
import CompliancePage from './pages/CompliancePage';
import ThreatInvestigationPage from './pages/ThreatInvestigationPage';
import CompanyIncidentsPage from './pages/CompanyIncidentsPage';
import CorrelationPage from './pages/CorrelationPage';
import ForensicsPage from './pages/ForensicsPage';
import SelectPlanPage from './pages/SelectPlanPage';
import UsersPage from './pages/UsersPage';
import PartnerSocManagerPage from './pages/PartnerSocManagerPage';
import SecurityScorePage from './pages/SecurityScorePage';
import EDRPage from './pages/EDRPage';
import SIEMPage from './pages/SIEMPage';
import IDSPage from './pages/IDSPage';
import FirewallPage from './pages/FirewallPage';
import WhitelistPage from './pages/WhitelistPage';
import EncryptionCenterPage from './pages/EncryptionCenterPage';

import FraudDashboardPage from './pages/FraudDashboardPage';
import EDRSubRoutes from './pages/edrdashbordpage/EDRSubRoutes';
import LiveNetworkMapPage from './pages/LiveNetworkMapPage';
import RoleDashboardPage from './pages/analyst/soc/RoleDashboardPage';
import SocWorkspacePage from './pages/analyst/soc/SocWorkspacePage';
import AlertDetailPage from './pages/analyst/soc/AlertDetailPage';
import IncidentDetailPage from './pages/analyst/soc/IncidentDetailPage';
import SocChatPage from './pages/SocChatPage';
import IncidentAuditPage from './pages/analyst/soc/IncidentAuditPage';
import SocManagerGeolocationPage from './pages/analyst/soc/SocManagerGeolocationPage';
import ProfileLockEventsPage from './pages/ProfileLockEventsPage';
import { DASHBOARD_ROUTES } from './config/menuConfig';

const isAnalystRole = role => ['analyst', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(role);
const isSocRole = role => ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(role);

function Guard({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="loading">Loading…</div>;
  return user ? children : <Navigate to="/login" replace />;
}

// Route to correct layout based on role
function RoleRouter() {
  const { user, loading } = useAuth();
  if (loading) return <div className="loading">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  if (isSocRole(user.role)) return <SocDashboardLayout />;
  if (isAnalystRole(user.role)) return <AnalystLayout />;
  return <Layout />;
}

const PartnerPlanContext = createContext(null);
export const usePartnerPlan = () => _useContext(PartnerPlanContext);

function RootRouter() {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) return <div className="loading">Loading…</div>;
  if (user?.role === 'partner_admin') return <PartnerPortalGate />;
  if (isSocRole(user?.role)) return <SocDashboardLayout />;
  if (user) return isAnalystRole(user.role) ? <AnalystLayout /> : <Layout />;
  if (location.pathname === '/') return <HomePage />;
  return <Navigate to="/login" replace />;
}

function PartnerPortalGate() {
  const location = useLocation();

  // Initialize from cache immediately — render without waiting for API
  const [planData, setPlanData] = useState(() => {
    try {
      const cached = sessionStorage.getItem('partner_plan');
      const parsed = cached ? JSON.parse(cached) : null;
      const cachedAmount = Number(parsed?.amountInr || parsed?.quote?.amountInr || parsed?.partner?.plan?.quote?.amountInr || 0);
      return parsed && (parsed.isPaid || cachedAmount > 0) ? parsed : null;
    } catch { return null; }
  });

  const savePlan = (data) => {
    try { sessionStorage.setItem('partner_plan', JSON.stringify(data)); } catch { }
    setPlanData(data);
  };

  // Background verification — never blocks UI
  const verify = () => {
    api.get(`/payment/partner-plan?t=${Date.now()}`)
      .then(({ data }) => { savePlan(data); })
      // Authorization and availability errors are handled without destroying
      // the portal login. The global auth layer separately confirms expired
      // tokens with /auth/me before redirecting.
      .catch(() => { });
  };

  useEffect(() => { verify(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Render immediately — no loading spinner needed
  const isPaid = Boolean(planData?.isPaid);
  const profileSetupComplete = Boolean(planData?.profileSetupComplete);

  // ── Gate 1: Not paid → Payment page ──
  if (!isPaid) {
    return (
      <PartnerPaymentPage
        initialPlanData={planData}
        onPaid={() => {
          const updated = { ...(planData || {}), isPaid: true, profileSetupComplete: false };
          savePlan(updated);
        }}
        onRetry={verify}
      />
    );
  }

  // ── Gate 2: Paid, profile setup pending ──
  const isOnProfilePage = location.pathname === '/partner-profile';
  if (!profileSetupComplete && !isOnProfilePage) {
    return <Layout />;
  }

  // ── Gate 3: Full access ──
  return (
    <PartnerPlanContext.Provider value={planData}>
      <Layout />
    </PartnerPlanContext.Provider>
  );
}

function PartnerUsersRedirect() {
  const { search, hash } = useLocation();
  return <Navigate to={{ pathname: '/partner/analyst', search, hash }} replace />;
}

export default function App() {
  return (
    <>
      <Toaster position="top-right" />
      <Routes>
        {/* Public */}
        <Route path="/login" element={<LoginPage />} />
        <Route path="/partner-registration" element={<PartnerRegistrationPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/register/:referralSlug" element={<RegisterPage />} />
        <Route path="/checkout" element={<CheckoutPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route path="/reset-password" element={<ResetPasswordPage />} />
        <Route path="/accept-invite" element={<AcceptInvitePage />} />

        {/* Public home for visitors, role dashboard for logged-in users */}
        <Route path="/" element={<RootRouter />}>

          {/* ── Role Dashboards ── */}
          <Route index element={<RoleAwareIndex />} />
          <Route path="soc-manager/alerts/:id" element={<SocRoleOnly role="soc_manager"><AlertDetailPage /></SocRoleOnly>} />
          <Route path="soc-manager/queue/alerts/:id" element={<SocRoleOnly role="soc_manager"><AlertDetailPage /></SocRoleOnly>} />
          <Route path="soc-manager/tickets/:id" element={<SocRoleOnly role="soc_manager"><IncidentDetailPage resourceType="ticket" /></SocRoleOnly>} />
          <Route path="soc-manager/incidents/:id" element={<SocRoleOnly role="soc_manager"><IncidentDetailPage /></SocRoleOnly>} />
          <Route path="soc-manager/dashboard" element={<SocRoleOnly role="soc_manager"><RoleDashboardPage /></SocRoleOnly>} />
          <Route path="soc-manager/investigate" element={<SocRoleOnly role="soc_manager"><ThreatInvestigationPage /></SocRoleOnly>} />
          <Route path="soc-manager/ioc" element={<SocRoleOnly role="soc_manager"><ThreatInvestigationPage defaultTab="search" pageTitle="🎯 IOC Investigation" pageDescription="Search and investigate indicators of compromise across authorized companies" /></SocRoleOnly>} />
          <Route path="soc-manager/threat-intelligence" element={<SocRoleOnly role="soc_manager"><SocWorkspacePage viewOverride="threat-intelligence" /></SocRoleOnly>} />
          <Route path="soc-manager/ids" element={<SocRoleOnly role="soc_manager"><IDSPage initialModule="ids" /></SocRoleOnly>} />
          <Route path="soc-manager/ips" element={<SocRoleOnly role="soc_manager"><IDSPage initialModule="ips" /></SocRoleOnly>} />
          <Route path="soc-manager/firewall" element={<SocRoleOnly role="soc_manager"><FirewallPage /></SocRoleOnly>} />
          <Route path="soc-manager/encryption" element={<SocRoleOnly role="soc_manager"><EncryptionCenterPage /></SocRoleOnly>} />
          <Route path="soc-manager/edrsystemstupe" element={<SocRoleOnly role="soc_manager"><EDRSystemSetupPage /></SocRoleOnly>} />
          <Route path="soc-manager/edrsystemstupe/systems" element={<SocRoleOnly role="soc_manager"><EDRSystemSystemsPage /></SocRoleOnly>} />
          <Route path="soc-manager/edrsystemstupe/dns-sinkhole" element={<SocRoleOnly role="soc_manager"><DnsSinkholeSetupPage /></SocRoleOnly>} />
          <Route path="soc-manager/edrsystemstupe/dns-cache-poisoning" element={<SocRoleOnly role="soc_manager"><DnsCachePoisoningSetupPage /></SocRoleOnly>} />
          <Route path="soc-manager/edrsystemstupe/encryption-ransomware-detection" element={<SocRoleOnly role="soc_manager"><RansomwareSetupPage /></SocRoleOnly>} />
          <Route path="soc-manager/edrsystemstupe/memory-overflow-detection" element={<SocRoleOnly role="soc_manager"><MemoryOverflowSetupPage /></SocRoleOnly>} />
          <Route path="soc-manager/edrsystemstupe/beaconing-detection" element={<SocRoleOnly role="soc_manager"><BeaconingSetupPage /></SocRoleOnly>} />
          <Route path="soc-manager/edrsystemstupe/time-based-anomaly-detection" element={<SocRoleOnly role="soc_manager"><TimeAnomalySetupPage /></SocRoleOnly>} />
          <Route path="soc-manager/geolocation" element={<SocRoleOnly role="soc_manager"><SocManagerGeolocationPage /></SocRoleOnly>} />
          <Route path="soc-manager/profile-locks" element={<SocRoleOnly role="soc_manager"><ProfileLockEventsPage /></SocRoleOnly>} />
          <Route path="soc-manager/soar" element={<SocRoleOnly role="soc_manager"><SoarPage defaultTab="dashboard" /></SocRoleOnly>} />
          <Route path="soc-manager/correlation" element={<SocRoleOnly role="soc_manager"><CorrelationPage /></SocRoleOnly>} />
          <Route path="soc-manager/playbooks" element={<SocRoleOnly role="soc_manager"><SoarPage defaultTab="playbooks" /></SocRoleOnly>} />
          <Route path="soc-manager/reports" element={<SocRoleOnly role="soc_manager"><ReportsPage /></SocRoleOnly>} />
          <Route path="soc-manager/settings" element={<SocRoleOnly role="soc_manager"><SettingsPage /></SocRoleOnly>} />
          <Route path="soc-manager/contact-support" element={<SocRoleOnly role="soc_manager"><SocChatPage heading="SOC Communications" /></SocRoleOnly>} />
          <Route path="soc-manager/audit" element={<SocRoleOnly role="soc_manager"><IncidentAuditPage /></SocRoleOnly>} />
          <Route path="soc-manager/threat-audit" element={<SocRoleOnly role="soc_manager"><IncidentAuditPage auditType="threat" /></SocRoleOnly>} />
          <Route path="soc-manager/:view" element={<SocRoleOnly role="soc_manager"><SocWorkspacePage /></SocRoleOnly>} />

          <Route path="l1/alerts/:id" element={<SocRoleOnly role="l1_analyst"><AlertDetailPage /></SocRoleOnly>} />
          <Route path="l1/queue/alerts/:id" element={<SocRoleOnly role="l1_analyst"><AlertDetailPage /></SocRoleOnly>} />
          <Route path="l1/tickets/:id" element={<SocRoleOnly role="l1_analyst"><IncidentDetailPage resourceType="ticket" /></SocRoleOnly>} />
          <Route path="l1/incidents/:id" element={<SocRoleOnly role="l1_analyst"><IncidentDetailPage /></SocRoleOnly>} />
          <Route path="l1/dashboard" element={<SocRoleOnly role="l1_analyst"><RoleDashboardPage /></SocRoleOnly>} />
          <Route path="l1/investigate" element={<SocRoleOnly role="l1_analyst"><ThreatInvestigationPage /></SocRoleOnly>} />
          <Route path="l1/settings" element={<SocRoleOnly role="l1_analyst"><SettingsPage /></SocRoleOnly>} />
          <Route path="l1/contact-support" element={<SocRoleOnly role="l1_analyst"><SocChatPage /></SocRoleOnly>} />
          <Route path="l1/audit" element={<SocRoleOnly role="l1_analyst"><IncidentAuditPage /></SocRoleOnly>} />
          <Route path="l1/:view" element={<SocRoleOnly role="l1_analyst"><SocWorkspacePage /></SocRoleOnly>} />

          <Route path="l2/alerts/:id" element={<SocRoleOnly role="l2_analyst"><AlertDetailPage /></SocRoleOnly>} />
          <Route path="l2/queue/alerts/:id" element={<SocRoleOnly role="l2_analyst"><AlertDetailPage /></SocRoleOnly>} />
          <Route path="l2/tickets/:id" element={<SocRoleOnly role="l2_analyst"><IncidentDetailPage resourceType="ticket" /></SocRoleOnly>} />
          <Route path="l2/incidents/:id" element={<SocRoleOnly role="l2_analyst"><IncidentDetailPage /></SocRoleOnly>} />
          <Route path="l2/dashboard" element={<SocRoleOnly role="l2_analyst"><RoleDashboardPage /></SocRoleOnly>} />
          <Route path="l2/investigate" element={<SocRoleOnly role="l2_analyst"><ThreatInvestigationPage /></SocRoleOnly>} />
          <Route path="l2/soar" element={<SocRoleOnly role="l2_analyst"><SoarPage /></SocRoleOnly>} />
          <Route path="l2/escalate-to-l3" element={<SocRoleOnly role="l2_analyst"><SocWorkspacePage viewOverride="escalate-to-l3" /></SocRoleOnly>} />
          <Route path="l2/settings" element={<SocRoleOnly role="l2_analyst"><SettingsPage /></SocRoleOnly>} />
          <Route path="l2/contact-support" element={<SocRoleOnly role="l2_analyst"><SocChatPage /></SocRoleOnly>} />
          <Route path="l2/audit" element={<SocRoleOnly role="l2_analyst"><IncidentAuditPage /></SocRoleOnly>} />
          <Route path="l2/ids" element={<SocRoleOnly role="l2_analyst"><IDSPage initialModule="ids" /></SocRoleOnly>} />
          <Route path="l2/ips" element={<SocRoleOnly role="l2_analyst"><IDSPage initialModule="ips" /></SocRoleOnly>} />
          <Route path="l2/edr" element={<SocRoleOnly role="l2_analyst"><EDRPage /></SocRoleOnly>} />
          <Route path="l2/:view" element={<SocRoleOnly role="l2_analyst"><SocWorkspacePage /></SocRoleOnly>} />

          <Route path="l3/alerts/:id" element={<SocRoleOnly role="l3_analyst"><AlertDetailPage /></SocRoleOnly>} />
          <Route path="l3" element={<SocRoleOnly role="l3_analyst"><Navigate to="/l3/dashboard" replace /></SocRoleOnly>} />
          <Route path="l3/queue/alerts/:id" element={<SocRoleOnly role="l3_analyst"><AlertDetailPage /></SocRoleOnly>} />
          <Route path="l3/tickets/:id" element={<SocRoleOnly role="l3_analyst"><IncidentDetailPage resourceType="ticket" /></SocRoleOnly>} />
          <Route path="l3/incidents/:id" element={<SocRoleOnly role="l3_analyst"><IncidentDetailPage /></SocRoleOnly>} />
          <Route path="l3/dashboard" element={<SocRoleOnly role="l3_analyst"><RoleDashboardPage /></SocRoleOnly>} />
          <Route path="l3/investigate" element={<SocRoleOnly role="l3_analyst"><ThreatInvestigationPage /></SocRoleOnly>} />
          <Route path="l3/soar" element={<SocRoleOnly role="l3_analyst"><SoarPage /></SocRoleOnly>} />
          <Route path="l3/correlation" element={<SocRoleOnly role="l3_analyst"><CorrelationPage /></SocRoleOnly>} />
          <Route path="l3/escalate" element={<SocRoleOnly role="l3_analyst"><SocWorkspacePage viewOverride="l3-incoming-escalations" /></SocRoleOnly>} />
          <Route path="l3/reports" element={<SocRoleOnly role="l3_analyst"><ReportsPage /></SocRoleOnly>} />
          <Route path="l3/settings" element={<SocRoleOnly role="l3_analyst"><SettingsPage /></SocRoleOnly>} />
          <Route path="l3/contact-support" element={<SocRoleOnly role="l3_analyst"><SocChatPage /></SocRoleOnly>} />
          <Route path="l3/audit" element={<SocRoleOnly role="l3_analyst"><IncidentAuditPage /></SocRoleOnly>} />
          <Route path="l3/ids" element={<SocRoleOnly role="l3_analyst"><IDSPage initialModule="ids" /></SocRoleOnly>} />
          <Route path="l3/ips" element={<SocRoleOnly role="l3_analyst"><IDSPage initialModule="ips" /></SocRoleOnly>} />
          <Route path="l3/system-monitoring" element={<SocRoleOnly role="l3_analyst"><SystemMonitoringDashboard /></SocRoleOnly>} />
          <Route path="l3/encryption" element={<SocRoleOnly role="l3_analyst"><EncryptionCenterPage /></SocRoleOnly>} />
          <Route path="l3/:view" element={<SocRoleOnly role="l3_analyst"><SocWorkspacePage /></SocRoleOnly>} />

          <Route path="l4/dashboard" element={<SocRoleOnly role="l4_analyst"><RoleDashboardPage /></SocRoleOnly>} />
          <Route path="l4" element={<SocRoleOnly role="l4_analyst"><Navigate to="/l4/dashboard" replace /></SocRoleOnly>} />
          <Route path="l4/tickets/:id" element={<SocRoleOnly role="l4_analyst"><IncidentDetailPage resourceType="ticket" /></SocRoleOnly>} />
          <Route path="l4/incidents/:id" element={<SocRoleOnly role="l4_analyst"><IncidentDetailPage /></SocRoleOnly>} />
          <Route path="l4/incidents" element={<SocRoleOnly role="l4_analyst"><SocWorkspacePage viewOverride="incidents" /></SocRoleOnly>} />
          <Route path="l4/tickets" element={<SocRoleOnly role="l4_analyst"><SocWorkspacePage viewOverride="tickets" /></SocRoleOnly>} />
          <Route path="l4/ids" element={<SocRoleOnly role="l4_analyst"><IDSPage initialModule="ids" /></SocRoleOnly>} />
          <Route path="l4/ips" element={<SocRoleOnly role="l4_analyst"><IDSPage initialModule="ips" /></SocRoleOnly>} />
          <Route path="l4/firewall" element={<SocRoleOnly role="l4_analyst"><FirewallPage /></SocRoleOnly>} />
          <Route path="l4/encryption" element={<SocRoleOnly role="l4_analyst"><EncryptionCenterPage /></SocRoleOnly>} />
          <Route path="l4/settings" element={<SocRoleOnly role="l4_analyst"><SettingsPage /></SocRoleOnly>} />
          <Route path="l4/contact-support" element={<SocRoleOnly role="l4_analyst"><SocChatPage /></SocRoleOnly>} />
          <Route path="l4/audit" element={<SocRoleOnly role="l4_analyst"><IncidentAuditPage auditType="threat" /></SocRoleOnly>} />
          <Route path="l4/shifts" element={<SocRoleOnly role="l4_analyst"><SocWorkspacePage viewOverride="shifts" /></SocRoleOnly>} />

          <Route path="dashboard/company-admin" element={<AdminOnly role="company_admin"><DashboardPage /></AdminOnly>} />
          <Route path="company-admin" element={<AdminOnly role="company_admin"><DashboardPage /></AdminOnly>} />
          <Route path="company-admin/dashboard" element={<AdminOnly role="company_admin"><DashboardPage /></AdminOnly>} />
          <Route path="company-admin/alerts" element={<RoleAwareAlerts />} />
          <Route path="company-admin/incidents" element={<AdminOnly role="company_admin"><CompanyIncidentsPage /></AdminOnly>} />
          <Route path="company-admin/incidents/:id" element={<AdminOnly role="company_admin"><IncidentDetailPage /></AdminOnly>} />
          <Route path="company-admin/reports" element={<RoleAwareReports />} />
          <Route path="company-admin/settings" element={<RoleAwareSettings />} />
          <Route path="company-admin/departments" element={<AdminOnly><DepartmentsPage /></AdminOnly>} />
          <Route path="company-admin/systems" element={<AdminOnly><SystemsPage /></AdminOnly>} />
          <Route path="company-admin/assets" element={<AdminOnly><SystemsPage /></AdminOnly>} />
          <Route path="company-admin/users" element={<PartnerOrAdminOnly><UsersPage /></PartnerOrAdminOnly>} />
          <Route path="company-admin/team" element={<AdminOnly><TeamPage /></AdminOnly>} />
          <Route path="company-admin/log-monitor" element={<LogMonitorDashboard />} />
          <Route path="company-admin/audit-logs" element={<LogMonitorDashboard />} />
          <Route path="company-admin/compliance" element={<CompliancePage />} />
          <Route path="company-admin/threat-intelligence" element={<AdminOnly role="company_admin"><CompanyIncidentsPage threatIntelligence /></AdminOnly>} />
          <Route path="company-admin/investigate" element={<Navigate to="/company-admin/threat-intelligence" replace />} />
          <Route path="company-admin/correlation" element={<CorrelationPage />} />
          <Route path="company-admin/forensics" element={<ForensicsPage />} />
          <Route path="company-admin/forensic" element={<ForensicsPage />} />
          <Route path="company-admin/forince" element={<ForensicsPage />} />
          <Route path="company-admin/siem" element={<SIEMPage />} />
          <Route path="company-admin/edr" element={<EDRPage />} />
          <Route path="company-admin/dns-sinkhole" element={<Navigate to="/company-admin/edr?capabilityId=31&capability=dns-sinkhole" replace />} />
          <Route path="company-admin/ids" element={<IDSPage initialModule="ids" />} />
          <Route path="company-admin/ips" element={<IDSPage initialModule="ips" />} />
          <Route path="company-admin/firewall" element={<FirewallPage />} />
          <Route path="company-admin/whitelist" element={<WhitelistPage />} />
          <Route path="company-admin/security-score" element={<SecurityScorePage />} />
          <Route path="company-admin/encryption" element={<AdminOnly role="company_admin"><EncryptionCenterPage /></AdminOnly>} />
          <Route path="company-admin/system-setup" element={<AdminOnly><SystemSetupPage /></AdminOnly>} />
          <Route path="company-admin/edrsystemstupe" element={<AdminOnly><EDRSystemSetupPage /></AdminOnly>} />
          <Route path="company-admin/edrsystemstupe/systems" element={<AdminOnly><EDRSystemSystemsPage /></AdminOnly>} />
          <Route path="company-admin/edrsystemstupe/dns-sinkhole" element={<AdminOnly><DnsSinkholeSetupPage /></AdminOnly>} />
          <Route path="company-admin/edrsystemstupe/dns-cache-poisoning" element={<AdminOnly><DnsCachePoisoningSetupPage /></AdminOnly>} />
          <Route path="company-admin/edrsystemstupe/encryption-ransomware-detection" element={<AdminOnly><RansomwareSetupPage /></AdminOnly>} />
          <Route path="company-admin/edrsystemstupe/memory-overflow-detection" element={<AdminOnly><MemoryOverflowSetupPage /></AdminOnly>} />
          <Route path="company-admin/edrsystemstupe/beaconing-detection" element={<AdminOnly><BeaconingSetupPage /></AdminOnly>} />
          <Route path="company-admin/edrsystemstupe/time-based-anomaly-detection" element={<AdminOnly><TimeAnomalySetupPage /></AdminOnly>} />
          <Route path="company-admin/monitoring" element={<MonitoringPage />} />
          <Route path="company-admin/system-monitoring" element={<SystemMonitoringDashboard />} />
          <Route path="company-admin/download-agent" element={<AdminOnly><AgentDownloadPage /></AdminOnly>} />
          <Route path="company-admin/soar" element={<AdminOnly><SoarPage /></AdminOnly>} />
          <Route path="company-admin/payments" element={<AdminOnly><PaymentsPage /></AdminOnly>} />
          <Route path="company-admin/soc-manager" element={<AdminOnly role="company_admin"><SocChatPage heading="SOC Manager Chat" /></AdminOnly>} />
          <Route path="company-admin/profile-locks" element={<AdminOnly role="company_admin"><ProfileLockEventsPage /></AdminOnly>} />
          <Route path="profile-locks" element={<ProfileLockOnly><ProfileLockEventsPage /></ProfileLockOnly>} />
          <Route path="dashboard/company-admin/alerts" element={<RoleAwareAlerts />} />
          <Route path="dashboard/company-admin/incidents" element={<AdminOnly role="company_admin"><CompanyIncidentsPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/incidents/:id" element={<AdminOnly role="company_admin"><IncidentDetailPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/reports" element={<RoleAwareReports />} />
          <Route path="dashboard/company-admin/settings" element={<RoleAwareSettings />} />
          <Route path="dashboard/company-admin/departments" element={<AdminOnly><DepartmentsPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/systems" element={<AdminOnly><SystemsPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/assets" element={<AdminOnly><SystemsPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/users" element={<PartnerOrAdminOnly><UsersPage /></PartnerOrAdminOnly>} />
          <Route path="dashboard/company-admin/team" element={<AdminOnly><TeamPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/log-monitor" element={<LogMonitorDashboard />} />
          <Route path="dashboard/company-admin/compliance" element={<CompliancePage />} />
          <Route path="dashboard/company-admin/threat-intelligence" element={<AdminOnly role="company_admin"><CompanyIncidentsPage threatIntelligence /></AdminOnly>} />
          <Route path="dashboard/company-admin/investigate" element={<Navigate to="/company-admin/threat-intelligence" replace />} />
          <Route path="dashboard/company-admin/siem" element={<SIEMPage />} />
          <Route path="dashboard/company-admin/edr" element={<EDRPage />} />
          <Route path="dashboard/company-admin/dns-sinkhole" element={<Navigate to="/company-admin/edr?capabilityId=31&capability=dns-sinkhole" replace />} />
          <Route path="dashboard/company-admin/ids" element={<IDSPage initialModule="ids" />} />
          <Route path="dashboard/company-admin/ips" element={<IDSPage initialModule="ips" />} />
          <Route path="dashboard/company-admin/firewall" element={<FirewallPage />} />
          <Route path="dashboard/company-admin/whitelist" element={<WhitelistPage />} />
          <Route path="dashboard/company-admin/security-score" element={<SecurityScorePage />} />
          <Route path="dashboard/company-admin/encryption" element={<AdminOnly role="company_admin"><EncryptionCenterPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/download-agent" element={<AdminOnly><AgentDownloadPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/soar" element={<AdminOnly><SoarPage /></AdminOnly>} />
          <Route path="dashboard/company-admin/payments" element={<AdminOnly><PaymentsPage /></AdminOnly>} />
          <Route path="dashboard/department-admin" element={<AdminOnly role="department_admin"><Navigate to="/department-admin/dashboard" replace /></AdminOnly>} />
          <Route path="department-admin" element={<AdminOnly role="department_admin"><Navigate to="/department-admin/dashboard" replace /></AdminOnly>} />
          <Route path="department-admin/dashboard" element={<AdminOnly role="department_admin"><DashboardPage /></AdminOnly>} />
          <Route path="department-admin/soc-manager" element={<AdminOnly role="department_admin"><SocChatPage heading="SOC Manager Chat" /></AdminOnly>} />
          <Route path="department-admin/profile-locks" element={<AdminOnly role="department_admin"><ProfileLockEventsPage /></AdminOnly>} />
          <Route path="department-admin/edrsystemstupe" element={<AdminOnly role="department_admin"><EDRSystemSetupPage /></AdminOnly>} />
          <Route path="department-admin/departments" element={<AdminOnly role="department_admin"><DepartmentsPage /></AdminOnly>} />
          <Route path="department-admin/systems" element={<AdminOnly role="department_admin"><SystemsPage /></AdminOnly>} />
          <Route path="department-admin/download-agent" element={<AdminOnly role="department_admin"><AgentDownloadPage /></AdminOnly>} />
          <Route path="department-admin/team" element={<AdminOnly role="department_admin"><TeamPage /></AdminOnly>} />
          <Route path="department-admin/payments" element={<AdminOnly role="department_admin"><PaymentsPage /></AdminOnly>} />
          <Route path="department-admin/settings" element={<AdminOnly role="department_admin"><RoleAwareSettings /></AdminOnly>} />
          <Route path="department-admin/system-monitoring" element={<AdminOnly role="department_admin"><SystemMonitoringDashboard /></AdminOnly>} />
          <Route path="department-admin/alerts" element={<AdminOnly role="department_admin"><RoleAwareAlerts /></AdminOnly>} />
          <Route path="department-admin/siem" element={<AdminOnly role="department_admin"><SIEMPage /></AdminOnly>} />
          <Route path="department-admin/soar" element={<AdminOnly role="department_admin"><SoarPage /></AdminOnly>} />
          <Route path="department-admin/correlation" element={<AdminOnly role="department_admin"><CorrelationPage /></AdminOnly>} />
          <Route path="department-admin/edr" element={<AdminOnly role="department_admin"><RoleAwareEDR /></AdminOnly>} />
          <Route path="department-admin/ids" element={<AdminOnly role="department_admin"><IDSPage initialModule="ids" /></AdminOnly>} />
          <Route path="department-admin/ips" element={<AdminOnly role="department_admin"><IDSPage initialModule="ips" /></AdminOnly>} />
          <Route path="department-admin/firewall" element={<AdminOnly role="department_admin"><FirewallPage /></AdminOnly>} />
          <Route path="department-admin/threat-intelligence" element={<AdminOnly role="department_admin"><CompanyIncidentsPage threatIntelligence /></AdminOnly>} />
          <Route path="department-admin/incidents" element={<AdminOnly role="department_admin"><CompanyIncidentsPage /></AdminOnly>} />
          <Route path="department-admin/investigate" element={<AdminOnly role="department_admin"><ThreatInvestigationPage /></AdminOnly>} />
          <Route path="department-admin/forensics" element={<AdminOnly role="department_admin"><ForensicsPage /></AdminOnly>} />
          <Route path="department-admin/log-monitor" element={<AdminOnly role="department_admin"><LogMonitorDashboard /></AdminOnly>} />
          <Route path="department-admin/compliance" element={<AdminOnly role="department_admin"><CompliancePage /></AdminOnly>} />
          <Route path="department-admin/security-score" element={<AdminOnly role="department_admin"><SecurityScorePage /></AdminOnly>} />
          <Route path="department-admin/reports" element={<AdminOnly role="department_admin"><RoleAwareReports /></AdminOnly>} />
          <Route path="dashboard/partner-admin" element={<PartnerOnly><Navigate to="/partner/companies" replace /></PartnerOnly>} />
          <Route path="dashboard/super-admin" element={<SuperOrPartnerOnly><RoleDashboardPage /></SuperOrPartnerOnly>} />
          <Route path="soc-managers" element={<SuperOrPartnerOnly><PartnerSocManagerPage /></SuperOrPartnerOnly>} />
          <Route path="soc-workspace/:view" element={<SocRoleOnly><SocWorkspacePage /></SocRoleOnly>} />
          
          {/* ── Partner Admin /partner/... Routes ── */}
          <Route path="partner/dashboard" element={<PartnerOnly><PartnerDashboardPage viewOverride="dashboard" /></PartnerOnly>} />
          <Route path="partner/companies" element={<PartnerOnly><PartnerDashboardPage viewOverride="companies" /></PartnerOnly>} />
          <Route path="partner/companies/:companyId" element={<PartnerOnly><PartnerDashboardPage /></PartnerOnly>} />
          <Route path="partner/analyst" element={<PartnerOrAdminOnly><UsersPage /></PartnerOrAdminOnly>} />
          <Route path="partner/users" element={<PartnerOrAdminOnly><PartnerUsersRedirect /></PartnerOrAdminOnly>} />
          <Route path="partner/soc-managers" element={<PartnerOnly><PartnerSocManagerPage /></PartnerOnly>} />
          <Route path="partner/revenue" element={<PartnerOnly><PartnerDashboardPage viewOverride="revenue" /></PartnerOnly>} />
          <Route path="partner/payment-control" element={<PartnerOnly><PartnerDashboardPage viewOverride="payment-control" /></PartnerOnly>} />
          <Route path="partner/fraud-intelligence" element={<SuperOrPartnerOnly><FraudDashboardPage /></SuperOrPartnerOnly>} />
          <Route path="partner/company-support" element={<PartnerOnly><PartnerDashboardPage viewOverride="tenant-support" /></PartnerOnly>} />
          <Route path="partner/user-passwords" element={<PartnerOnly><PartnerUserPasswords /></PartnerOnly>} />
          <Route path="partner/audit" element={<PartnerOnly><PartnerAuditPage /></PartnerOnly>} />
          <Route path="partner/support" element={<PartnerOnly><PartnerDashboardPage viewOverride="tenant-support" /></PartnerOnly>} />
          <Route path="partner/resources" element={<PartnerOnly><PartnerDashboardPage viewOverride="requests" /></PartnerOnly>} />
          <Route path="partner/subscription" element={<PartnerOnly><PartnerDashboardPage viewOverride="subscription" /></PartnerOnly>} />
          <Route path="partner/agents" element={<PartnerOnly><PartnerDashboardPage viewOverride="companies" /></PartnerOnly>} />

          {/* Legacy partner routes */}
          <Route path="partner-companies" element={<PartnerOnly><PartnerDashboardPage /></PartnerOnly>} />
          <Route path="partner-companies/:companyId" element={<PartnerOnly><PartnerDashboardPage /></PartnerOnly>} />
          <Route path="partner-soc-managers" element={<PartnerOnly><PartnerSocManagerPage /></PartnerOnly>} />
          <Route path="partner-agents" element={<PartnerOnly><PartnerDashboardPage /></PartnerOnly>} />
          <Route path="partner-resources" element={<PartnerOnly><PartnerDashboardPage /></PartnerOnly>} />
          <Route path="partner-subscription" element={<PartnerOnly><PartnerDashboardPage /></PartnerOnly>} />
          <Route path="partner-company-support" element={<PartnerOnly><PartnerDashboardPage /></PartnerOnly>} />
          <Route path="partner-support" element={<PartnerOnly><RoleAwareSettings /></PartnerOnly>} />
          <Route path="partner-profile" element={<PartnerOnly><RoleAwareSettings /></PartnerOnly>} />
          <Route path="partner/profile" element={<PartnerOnly><RoleAwareSettings /></PartnerOnly>} />
          <Route path="agent-license-checkout" element={<PartnerOnly><AgentLicenseCheckoutPage /></PartnerOnly>} />
          <Route path="alerts" element={<RoleAwareAlerts />} />
          <Route path="reports" element={<RoleAwareReports />} />
          <Route path="settings" element={<RoleAwareSettings />} />

          {/* ── Company admin / dept admin only ── */}
          <Route path="system-setup" element={<AdminOnly><SystemSetupPage /></AdminOnly>} />
          <Route path="edrsystemstupe" element={<AdminOnly><EDRSystemSetupPage /></AdminOnly>} />
          <Route path="edrsystemstupe/systems" element={<AdminOnly><EDRSystemSystemsPage /></AdminOnly>} />
          <Route path="edrsystemstupe/dns-sinkhole" element={<AdminOnly><DnsSinkholeSetupPage /></AdminOnly>} />
          <Route path="edrsystemstupe/dns-cache-poisoning" element={<AdminOnly><DnsCachePoisoningSetupPage /></AdminOnly>} />
          <Route path="edrsystemstupe/encryption-ransomware-detection" element={<AdminOnly><RansomwareSetupPage /></AdminOnly>} />
          <Route path="edrsystemstupe/memory-overflow-detection" element={<AdminOnly><MemoryOverflowSetupPage /></AdminOnly>} />
          <Route path="edrsystemstupe/beaconing-detection" element={<AdminOnly><BeaconingSetupPage /></AdminOnly>} />
          <Route path="edrsystemstupe/time-based-anomaly-detection" element={<AdminOnly><TimeAnomalySetupPage /></AdminOnly>} />
          <Route path="monitoring" element={<MonitoringPage />} />
          <Route path="departments" element={<AdminOnly><DepartmentsPage /></AdminOnly>} />
          <Route path="systems" element={<AdminOnly><SystemsPage /></AdminOnly>} />
          <Route path="system-monitoring" element={<SystemMonitoringDashboard />} />
          <Route path="download-agent" element={<AdminOnly><AgentDownloadPage /></AdminOnly>} />
          <Route path="soar" element={<AdminOnly><SoarPage /></AdminOnly>} />
          <Route path="payments" element={<AdminOnly><PaymentsPage /></AdminOnly>} />

          {/* ── Log Monitor — all roles ── */}
          <Route path="log-monitor" element={<LogMonitorDashboard />} />
          {/* ── Compliance — all roles ── */}
          <Route path="compliance" element={<CompliancePage />} />
          {/* Department incident workspaces; API access is department-scoped. */}
          <Route path="incidents" element={<AdminOnly role="department_admin"><CompanyIncidentsPage /></AdminOnly>} />
          <Route path="threat-intelligence" element={<AdminOnly role="department_admin"><CompanyIncidentsPage threatIntelligence /></AdminOnly>} />
          {/* ── Threat Investigation — all roles ── */}
          <Route path="investigate" element={<ThreatInvestigationPage />} />
          <Route path="correlation" element={<CorrelationPage />} />
          <Route path="forensics" element={<ForensicsPage />} />
          <Route path="forensic" element={<ForensicsPage />} />
          <Route path="forince" element={<ForensicsPage />} />
          {/* ── Team management ── */}
          <Route path="team" element={<AdminOnly><TeamPage /></AdminOnly>} />
          <Route path="users" element={<PartnerOrAdminOnly><UsersPage /></PartnerOrAdminOnly>} />
          {/* ── SIEM, EDR, IDS, Security Score — all roles ── */}
          <Route path="siem" element={<SIEMPage />} />
          <Route path="edr" element={<RoleAwareEDR />} />
          <Route path="dns-sinkhole" element={<Navigate to="/edr?capabilityId=31&capability=dns-sinkhole" replace />} />
          <Route path="ids" element={<IDSPage initialModule="ids" />} />
          <Route path="ips" element={<IDSPage initialModule="ips" />} />
          <Route path="firewall" element={<FirewallPage />} />
          <Route path="whitelist" element={<WhitelistPage />} />
          <Route path="security-score" element={<SecurityScorePage />} />
          <Route path="fraud-intelligence" element={<SuperOrPartnerOnly><FraudDashboardPage /></SuperOrPartnerOnly>} />

        </Route>

        {/* ── EDR sub-pages: full-screen, outside Layout ── */}
        <Route path="/live-network-map" element={<Guard><LiveNetworkMapPage /></Guard>} />
        <Route path="/edr-dashboard-details/*" element={<EDRSubRoutes Guard={Guard} />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
}

// Show analyst or admin version of shared pages
const RoleAwareIndex = () => {
  const { user } = useAuth();
  if (user?.role === 'partner_admin') return <Navigate to="/partner/companies" replace />;
  const target = DASHBOARD_ROUTES[user?.role] || SOC_DASHBOARD[user?.role];
  if (target) return <Navigate to={target} replace />;
  return isAnalystRole(user?.role) ? <AnalystDashboard /> : <DashboardPage />;
};

const RoleAwareEDR = () => {
  const { user } = useAuth();
  const location = useLocation();
  if (user?.role === 'company_admin' && !location.pathname.startsWith('/company-admin')) {
    const rest = location.pathname.replace(/^\/edr/, '') || '';
    return <Navigate to={`/company-admin/edr${rest}${location.search}`} replace />;
  }
  return <EDRPage />;
};

const RoleAwareAlerts = () => {
  const { user } = useAuth();
  const location = useLocation();
  if (user?.role === 'company_admin' && !location.pathname.startsWith('/company-admin')) {
    const rest = location.pathname.replace(/^\/alerts/, '') || '';
    return <Navigate to={`/company-admin/alerts${rest}${location.search}`} replace />;
  }
  return isAnalystRole(user?.role) ? <AnalystAlerts /> : <AlertsPage />;
};

const RoleAwareReports = () => {
  const { user } = useAuth();
  const location = useLocation();
  if (user?.role === 'company_admin' && !location.pathname.startsWith('/company-admin')) {
    return <Navigate to={`/company-admin/reports${location.search}`} replace />;
  }
  return isAnalystRole(user?.role) ? <AnalystReports /> : <ReportsPage />;
};

const RoleAwareSettings = () => {
  const { user } = useAuth();
  const location = useLocation();
  if (user?.role === 'company_admin' && !location.pathname.startsWith('/company-admin') && !location.pathname.startsWith('/partner')) {
    return <Navigate to={`/company-admin/settings${location.search}`} replace />;
  }
  if (user?.role === 'department_admin' && !location.pathname.startsWith('/department-admin')) {
    return <Navigate to={`/department-admin/settings${location.search}`} replace />;
  }
  return isAnalystRole(user?.role) ? <AnalystSettings /> : <SettingsPage />;
};



// Block analyst from admin pages
function AdminOnly({ role, children }) {
  const { user } = useAuth();
  if (isAnalystRole(user?.role)) return <Navigate to="/" replace />;
  if (role && user?.role !== role) return <Navigate to={DASHBOARD_ROUTES[user?.role] || '/'} replace />;
  return children;
}

// Only superadmin and partner_admin may access
function SuperOrPartnerOnly({ children }) {
  const { user } = useAuth();
  if (!['superadmin', 'partner_admin'].includes(user?.role)) return <Navigate to="/" replace />;
  return children;
}

// Allow partner_admin or company_admin/dept_admin (block analyst)
function PartnerOrAdminOnly({ children }) {
  const { user } = useAuth();
  if (!['partner_admin', 'company_admin', 'department_admin', 'soc_manager'].includes(user?.role)) return <Navigate to="/" replace />;
  return children;
}

function ProfileLockOnly({ children }) {
  const { user } = useAuth();
  if (!['company_admin', 'department_admin', 'soc_manager'].includes(user?.role)) return <Navigate to="/" replace />;
  return children;
}

function PartnerOnly({ children }) {
  const { user } = useAuth();
  if (user?.role !== 'partner_admin') return <Navigate to="/" replace />;
  return children;
}

function SocRoleOnly({ role, children }) {
  const { user } = useAuth();
  if (!isSocRole(user?.role)) return <Navigate to="/" replace />;
  const target = DASHBOARD_ROUTES[user?.role] || SOC_DASHBOARD[user?.role];
  if (role && user.role !== role) return <Navigate to={target} replace />;
  return children;
}
