import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuth } from './context/AuthContext';

import LoginPage from './pages/LoginPage';
import SignupPage from './pages/SignupPage';
import Layout from './components/Layout';
import DashboardPage from './pages/DashboardPage';
import CompaniesPage from './pages/CompaniesPage';
import CompanyDetail from './pages/CompanyDetail';
import CompanyDashboard from './pages/CompanyDashboard';
import DeptDashboard from './pages/DeptDashboard';
import DeptDetail from './pages/DeptDetail';
import SystemDetail from './pages/SystemDetail';
import UsersPage from './pages/UsersPage';
import AnalyticsPage from './pages/AnalyticsPage';
import AlertsPage from './pages/AlertsPage';
import ReportsPage from './pages/ReportsPage';
import LogMonitorDashboard from './pages/LogMonitorDashboard';
import RevenuePage from './pages/RevenuePage';
import EDRPage from './pages/EDRPage';
import IDSPage from './pages/IDSPage';
import FirewallPage from './pages/FirewallPage';
import SecurityScorePage from './pages/SecurityScorePage';
import InvestigatePage from './pages/InvestigatePage';
import CompliancePage from './pages/CompliancePage';
import SettingsPage from './pages/SettingsPage';
import SystemMonitoringDashboard from './pages/SystemMonitoringDashboard';
import PaymentManagementPage from './pages/PaymentManagementPage';
import PartnersPage from './pages/PartnersPage';
import PartnerDashboardPage from './pages/PartnerDashboardPage';
import FraudDashboardPage from './pages/FraudDashboardPage';
import SOCManagersPage from './pages/SOCManagersPage';
import SoarPage from './pages/SoarPage';
import AgentSecurityPage from './pages/AgentSecurityPage';
import CorrelationPage from './pages/CorrelationPage';
import ForensicsPage from './pages/ForensicsPage';

import { ToastProvider } from './components/Toast';

function Guard({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="loading">Loading…</div>;
  return user ? children : <Navigate to="/login" replace />;
}

function RoleOnly({ roles, children }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="loading">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return roles.includes(user.role) ? children : <Navigate to="/" replace />;
}

function HomeRedirect() {
  return <DashboardPage />;
}

export default function App() {
  return (
    <ToastProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/signup" element={<SignupPage />} />

      {/* Main /superadmin prefixed route */}
      <Route path="/superadmin" element={<Guard><Layout /></Guard>}>
        <Route index element={<HomeRedirect />} />
        <Route path="dashboard" element={<RoleOnly roles={['superadmin']}><DashboardPage /></RoleOnly>} />
        <Route path="companies" element={<RoleOnly roles={['superadmin']}><CompaniesPage /></RoleOnly>} />
        <Route path="partners" element={<RoleOnly roles={['superadmin']}><PartnersPage /></RoleOnly>} />
        <Route path="partner-dashboard" element={<RoleOnly roles={['superadmin', 'partner_admin']}><PartnerDashboardPage /></RoleOnly>} />
        <Route path="partnerdashboard" element={<RoleOnly roles={['superadmin', 'partner_admin']}><PartnerDashboardPage /></RoleOnly>} />
        <Route path="partnerdashbos" element={<RoleOnly roles={['superadmin', 'partner_admin']}><PartnerDashboardPage /></RoleOnly>} />
        <Route path="partner-company" element={<RoleOnly roles={['superadmin']}><CompaniesPage /></RoleOnly>} />
        <Route path="partnercompany" element={<RoleOnly roles={['superadmin']}><CompaniesPage /></RoleOnly>} />
        <Route path="partnercompanies" element={<RoleOnly roles={['superadmin']}><CompaniesPage /></RoleOnly>} />
        <Route path="companies/:companyId" element={<RoleOnly roles={['superadmin']}><CompanyDetail /></RoleOnly>} />
        <Route path="companies/:companyId/dashboard" element={<RoleOnly roles={['superadmin']}><CompanyDashboard /></RoleOnly>} />
        <Route path="companies/:companyId/dept-dashboard/:deptId" element={<RoleOnly roles={['superadmin']}><DeptDashboard /></RoleOnly>} />
        <Route path="companies/:companyId/departments/:deptId" element={<RoleOnly roles={['superadmin']}><DeptDetail /></RoleOnly>} />
        <Route path="companies/:companyId/departments/:deptId/systems/:systemId" element={<RoleOnly roles={['superadmin']}><SystemDetail /></RoleOnly>} />
        <Route path="alerts" element={<RoleOnly roles={['superadmin']}><AlertsPage /></RoleOnly>} />
        <Route path="system-monitoring" element={<RoleOnly roles={['superadmin']}><SystemMonitoringDashboard /></RoleOnly>} />
        <Route path="edr" element={<RoleOnly roles={['superadmin']}><EDRPage /></RoleOnly>} />
        <Route path="ids" element={<RoleOnly roles={['superadmin']}><IDSPage initialModule="ids" /></RoleOnly>} />
        <Route path="ips" element={<RoleOnly roles={['superadmin']}><IDSPage initialModule="ips" /></RoleOnly>} />
        <Route path="firewall" element={<RoleOnly roles={['superadmin']}><FirewallPage /></RoleOnly>} />
        <Route path="security-score" element={<RoleOnly roles={['superadmin']}><SecurityScorePage /></RoleOnly>} />
        <Route path="investigate" element={<RoleOnly roles={['superadmin']}><InvestigatePage /></RoleOnly>} />
        <Route path="correlation" element={<RoleOnly roles={['superadmin']}><CorrelationPage /></RoleOnly>} />
        <Route path="forensics" element={<RoleOnly roles={['superadmin']}><ForensicsPage /></RoleOnly>} />
        <Route path="forensic" element={<RoleOnly roles={['superadmin']}><ForensicsPage /></RoleOnly>} />
        <Route path="forince" element={<RoleOnly roles={['superadmin']}><ForensicsPage /></RoleOnly>} />
        <Route path="log-monitor" element={<RoleOnly roles={['superadmin']}><LogMonitorDashboard /></RoleOnly>} />
        <Route path="compliance" element={<RoleOnly roles={['superadmin']}><CompliancePage /></RoleOnly>} />
        <Route path="reports" element={<RoleOnly roles={['superadmin']}><ReportsPage /></RoleOnly>} />
        <Route path="users" element={<RoleOnly roles={['superadmin']}><UsersPage /></RoleOnly>} />
        <Route path="soc-managers" element={<RoleOnly roles={['superadmin']}><SOCManagersPage /></RoleOnly>} />
        <Route path="SORA" element={<RoleOnly roles={['superadmin']}><SoarPage /></RoleOnly>} />
        <Route path="soar" element={<RoleOnly roles={['superadmin']}><SoarPage /></RoleOnly>} />
        <Route path="revenue" element={<RoleOnly roles={['superadmin']}><RevenuePage /></RoleOnly>} />
        <Route path="payment-management" element={<RoleOnly roles={['superadmin']}><PaymentManagementPage /></RoleOnly>} />
        <Route path="analytics" element={<RoleOnly roles={['superadmin']}><AnalyticsPage /></RoleOnly>} />
        <Route path="settings" element={<RoleOnly roles={['superadmin']}><SettingsPage /></RoleOnly>} />
        <Route path="fraud-intelligence" element={<RoleOnly roles={['superadmin']}><FraudDashboardPage /></RoleOnly>} />
        <Route path="ajantsecurity" element={<RoleOnly roles={['superadmin']}><AgentSecurityPage /></RoleOnly>} />
        <Route path="ajant-security" element={<RoleOnly roles={['superadmin']}><AgentSecurityPage /></RoleOnly>} />
        <Route path="agent-security" element={<RoleOnly roles={['superadmin']}><AgentSecurityPage /></RoleOnly>} />
        <Route path="agentsecurity" element={<RoleOnly roles={['superadmin']}><AgentSecurityPage /></RoleOnly>} />
      </Route>

      {/* Direct root fallback route to support legacy un-prefixed URLs as well */}
      <Route path="/" element={<Guard><Layout /></Guard>}>
        <Route index element={<HomeRedirect />} />
        <Route path="dashboard" element={<RoleOnly roles={['superadmin']}><DashboardPage /></RoleOnly>} />
        <Route path="companies" element={<RoleOnly roles={['superadmin']}><CompaniesPage /></RoleOnly>} />
        <Route path="partners" element={<RoleOnly roles={['superadmin']}><PartnersPage /></RoleOnly>} />
        <Route path="partner-dashboard" element={<RoleOnly roles={['superadmin', 'partner_admin']}><PartnerDashboardPage /></RoleOnly>} />
        <Route path="partnerdashboard" element={<RoleOnly roles={['superadmin', 'partner_admin']}><PartnerDashboardPage /></RoleOnly>} />
        <Route path="partnerdashbos" element={<RoleOnly roles={['superadmin', 'partner_admin']}><PartnerDashboardPage /></RoleOnly>} />
        <Route path="partner-company" element={<RoleOnly roles={['superadmin']}><CompaniesPage /></RoleOnly>} />
        <Route path="partnercompany" element={<RoleOnly roles={['superadmin']}><CompaniesPage /></RoleOnly>} />
        <Route path="partnercompanies" element={<RoleOnly roles={['superadmin']}><CompaniesPage /></RoleOnly>} />
        <Route path="companies/:companyId" element={<RoleOnly roles={['superadmin']}><CompanyDetail /></RoleOnly>} />
        <Route path="companies/:companyId/dashboard" element={<RoleOnly roles={['superadmin']}><CompanyDashboard /></RoleOnly>} />
        <Route path="companies/:companyId/dept-dashboard/:deptId" element={<RoleOnly roles={['superadmin']}><DeptDashboard /></RoleOnly>} />
        <Route path="companies/:companyId/departments/:deptId" element={<RoleOnly roles={['superadmin']}><DeptDetail /></RoleOnly>} />
        <Route path="companies/:companyId/departments/:deptId/systems/:systemId" element={<RoleOnly roles={['superadmin']}><SystemDetail /></RoleOnly>} />
        <Route path="alerts" element={<RoleOnly roles={['superadmin']}><AlertsPage /></RoleOnly>} />
        <Route path="system-monitoring" element={<RoleOnly roles={['superadmin']}><SystemMonitoringDashboard /></RoleOnly>} />
        <Route path="edr" element={<RoleOnly roles={['superadmin']}><EDRPage /></RoleOnly>} />
        <Route path="ids" element={<RoleOnly roles={['superadmin']}><IDSPage initialModule="ids" /></RoleOnly>} />
        <Route path="ips" element={<RoleOnly roles={['superadmin']}><IDSPage initialModule="ips" /></RoleOnly>} />
        <Route path="firewall" element={<RoleOnly roles={['superadmin']}><FirewallPage /></RoleOnly>} />
        <Route path="security-score" element={<RoleOnly roles={['superadmin']}><SecurityScorePage /></RoleOnly>} />
        <Route path="investigate" element={<RoleOnly roles={['superadmin']}><InvestigatePage /></RoleOnly>} />
        <Route path="correlation" element={<RoleOnly roles={['superadmin']}><CorrelationPage /></RoleOnly>} />
        <Route path="forensics" element={<RoleOnly roles={['superadmin']}><ForensicsPage /></RoleOnly>} />
        <Route path="forensic" element={<RoleOnly roles={['superadmin']}><ForensicsPage /></RoleOnly>} />
        <Route path="forince" element={<RoleOnly roles={['superadmin']}><ForensicsPage /></RoleOnly>} />
        <Route path="log-monitor" element={<RoleOnly roles={['superadmin']}><LogMonitorDashboard /></RoleOnly>} />
        <Route path="compliance" element={<RoleOnly roles={['superadmin']}><CompliancePage /></RoleOnly>} />
        <Route path="reports" element={<RoleOnly roles={['superadmin']}><ReportsPage /></RoleOnly>} />
        <Route path="users" element={<RoleOnly roles={['superadmin']}><UsersPage /></RoleOnly>} />
        <Route path="soc-managers" element={<RoleOnly roles={['superadmin']}><SOCManagersPage /></RoleOnly>} />
        <Route path="SORA" element={<RoleOnly roles={['superadmin']}><SoarPage /></RoleOnly>} />
        <Route path="soar" element={<RoleOnly roles={['superadmin']}><SoarPage /></RoleOnly>} />
        <Route path="revenue" element={<RoleOnly roles={['superadmin']}><RevenuePage /></RoleOnly>} />
        <Route path="payment-management" element={<RoleOnly roles={['superadmin']}><PaymentManagementPage /></RoleOnly>} />
        <Route path="analytics" element={<RoleOnly roles={['superadmin']}><AnalyticsPage /></RoleOnly>} />
        <Route path="settings" element={<RoleOnly roles={['superadmin']}><SettingsPage /></RoleOnly>} />
        <Route path="fraud-intelligence" element={<RoleOnly roles={['superadmin']}><FraudDashboardPage /></RoleOnly>} />
        <Route path="ajantsecurity" element={<RoleOnly roles={['superadmin']}><AgentSecurityPage /></RoleOnly>} />
        <Route path="ajant-security" element={<RoleOnly roles={['superadmin']}><AgentSecurityPage /></RoleOnly>} />
        <Route path="agent-security" element={<RoleOnly roles={['superadmin']}><AgentSecurityPage /></RoleOnly>} />
        <Route path="agentsecurity" element={<RoleOnly roles={['superadmin']}><AgentSecurityPage /></RoleOnly>} />
      </Route>

      <Route path="*" element={<Navigate to="/superadmin" replace />} />
    </Routes>
  </ToastProvider>
  );
}
