import { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, pollingSocketOptions, socketOptions, io } from '../api/config';
import Swal from 'sweetalert2';
import PartnerDashboardPage from './PartnerDashboardPage';
import { openRazorpay } from '../utils/razorpay';

const fmtDate = (d) => d ? new Date(d).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
const fmtInr = (n) => `₹${Number(n || 0).toLocaleString('en-IN')}`;
const titleCase = (value) => String(value || '—').replace(/[._-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
const mergeSupportReadReceipts = (current, updated) => {
  if (!current || current._id !== updated?._id) return current;
  const receipts = new Map((updated.messages || []).filter(message => message.readAt).map(message => [message._id, message.readAt]));
  if (!(current.messages || []).some(message => !message.readAt && receipts.has(message._id))) return current;
  return { ...current, messages: current.messages.map(message => receipts.has(message._id) ? { ...message, readAt: message.readAt || receipts.get(message._id) } : message) };
};
const accountRoleLabel = role => ({
  company_admin: 'Company Admin',
  department_admin: 'Department Admin',
}[role] || titleCase(role));
const departmentAdminSettingsTabIds = new Set([
  'profile',
  'security',
  'notifications',
  'activity',
]);
const socProfileByRole = {
  soc_manager: {
    label: 'SOC Manager',
    heading: 'SOC Manager Details',
    subtitle: 'Your SOC management account and profile information',
    scope: 'SOC Operations & Analyst Management',
    icon: '🧑‍💼',
  },
  l1_analyst: {
    label: 'L1 Triage Analyst',
    heading: 'L1 Triage Analyst Details',
    subtitle: 'Your triage analyst account and profile information',
    scope: 'Alert Triage & Initial Validation',
    icon: '🛡️',
  },
  l2_analyst: {
    label: 'L2 Investigation Analyst',
    heading: 'L2 Investigation Analyst Details',
    subtitle: 'Your investigation analyst account and profile information',
    scope: 'Incident Investigation & Response',
    icon: '🔎',
  },
  l3_analyst: {
    label: 'L3 Forensic Analyst',
    heading: 'L3 Forensic Analyst Details',
    subtitle: 'Your forensic analyst account and profile information',
    scope: 'Advanced Forensics & Escalations',
    icon: '🧪',
  },
  l4_analyst: {
    label: 'L4 Threat Intelligence Analyst',
    heading: 'L4 Threat Intelligence Analyst Details',
    subtitle: 'Your threat-intelligence analyst account and profile information',
    scope: 'Threat Intelligence Incidents',
    icon: '⌖',
  },
};
const kycDocFields = {
  'GST Certificate': ['gstCertificateName', 'gstCertificateType', 'gstCertificateDataUrl', 'gstCertificateFilePath'],
  'PAN Card': ['panCardName', 'panCardType', 'panCardDataUrl', 'panCardFilePath'],
  'Business Registration': ['businessRegistrationName', 'businessRegistrationType', 'businessRegistrationDataUrl', 'businessRegistrationFilePath'],
};
const kycDocLabels = ['GST Certificate', 'PAN Card', 'Business Registration'];
const kycDocTypeMap = {
  'GST Certificate': 'gstCertificate',
  'PAN Card': 'panCard',
  'Business Registration': 'businessRegistration',
};
const partnerProfileSectionIds = new Set(['dashboard', 'agents', 'subscription', 'requests', 'profile', 'company', 'kyc', 'bank', 'users', 'security', 'notifications', 'activity', 'support']);
const sectionFromSearch = search => {
  const section = new URLSearchParams(search || '').get('section');
  return partnerProfileSectionIds.has(section) ? section : 'profile';
};
const displayFileName = value => {
  let name = String(value || '');
  if (/[ÃÂâðï]/.test(name)) {
    try {
      name = decodeURIComponent([...name].map(char => `%${char.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''));
    } catch { }
  }
  return name
    .replace(/^(?:[\s"'`*_.,:;|/\\-]|[^\x20-\x7E]|[^\p{L}\p{N}._-])+/u, '')
    .replace(/^(?:ðŸ|ï¸|¿|¢|â|Ã|Â|[^\p{L}\p{N}._-])+/u, '')
    .trim() || 'Uploaded document';
};
const kycDisplayName = (name, verified) => name ? displayFileName(name) : verified ? 'Verified' : 'Not Uploaded';
const kycDocsFromServer = serverDocs => {
  const docs = {};
  Object.entries(kycDocFields).forEach(([label, [nameKey, typeKey, dataKey, pathKey]]) => {
    if (serverDocs?.[nameKey] || serverDocs?.[pathKey] || serverDocs?.[dataKey]) {
      docs[label] = {
        name: serverDocs[nameKey] || '',
        type: serverDocs[typeKey] || '',
        previewUrl: serverDocs[dataKey] || '',
        filePath: serverDocs[pathKey] || '',
      };
    }
  });
  return docs;
};
const mergeStoredDocs = (serverDocs, storedDocs) => {
  const merged = { ...storedDocs };
  kycDocLabels.forEach(label => {
    const serverDoc = serverDocs[label] || {};
    const storedDoc = storedDocs[label] || {};
    const cleanStoredDoc = Object.fromEntries(Object.entries(storedDoc).filter(([, value]) => Boolean(value)));
    merged[label] = { ...cleanStoredDoc, ...serverDoc };
  });
  return merged;
};

// ─────────────────────────────────────────────────────────────────────────────
// ProfileEditTab  — editable My Profile page
// ─────────────────────────────────────────────────────────────────────────────
function ProfileEditTab({ user, company, subData, isImpersonating, onRefresh }) {
  const [companyForm, setCompanyForm] = useState({
    name: company?.name || '',
    phone: company?.phone || '',
    industry: company?.industry || '',
    website: company?.website || '',
    companySize: company?.companySize || '',
    country: company?.country || '',
  });
  const [companyErrs, setCompanyErrs] = useState({});
  const [companyBusy, setCompanyBusy] = useState(false);
  const [companyMsg, setCompanyMsg] = useState('');
  const [companyErr, setCompanyErr] = useState('');

  const [adminForm, setAdminForm] = useState({
    name: user?.name || '',
    phone: user?.phone || '',
  });
  const [adminErrs, setAdminErrs] = useState({});
  const [adminBusy, setAdminBusy] = useState(false);
  const [adminMsg, setAdminMsg] = useState('');
  const [adminErr, setAdminErr] = useState('');

  /* ── Validation helpers ── */
  const phoneRe = /^(\+?[0-9\s\-().]{7,20})$/;
  const urlRe = /^(https?:\/\/)?([\w-]+\.)+[\w]{2,}(\/.*)?$/i;

  const validateCompany = (f = companyForm) => {
    const e = {};
    if (!f.name.trim()) e.name = 'Company name is required.';
    if (f.phone && !phoneRe.test(f.phone)) e.phone = 'Enter a valid phone number.';
    if (f.website && !urlRe.test(f.website)) e.website = 'Enter a valid website URL.';
    if (!f.industry) e.industry = 'Please select an industry.';
    if (!f.companySize) e.companySize = 'Please select company size.';
    if (!f.country) e.country = 'Please select a country.';
    return e;
  };

  const validateAdmin = (f = adminForm) => {
    const e = {};
    if (!f.name.trim()) e.name = 'Admin name is required.';
    else if (f.name.trim().length < 2) e.name = 'Name must be at least 2 characters.';
    if (f.phone && !phoneRe.test(f.phone)) e.phone = 'Enter a valid phone number.';
    return e;
  };

  const cardStyle = {
    background: 'linear-gradient(135deg, rgba(15,23,42,0.96) 0%, rgba(10,18,38,0.92) 100%)',
    borderRadius: 14, padding: '24px 28px', marginBottom: 20,
    border: '1px solid rgba(100,116,139,0.15)',
    boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05), 0 4px 20px rgba(0,0,0,0.35)',
  };
  const hdrStyle = (color) => ({
    display: 'flex', alignItems: 'center', gap: 10,
    marginBottom: 20, paddingBottom: 14,
    borderBottom: `1px solid ${color}33`,
  });
  const hdrIcon = (color) => ({
    width: 36, height: 36, borderRadius: 10, display: 'grid', placeItems: 'center',
    background: `${color}18`, border: `1px solid ${color}44`, fontSize: 17,
  });
  const hdrText = { fontSize: 15, color: '#e2e8f0', fontWeight: 800 };
  const gridTwo = { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 };
  const fldWrap = { display: 'grid', gap: 5 };
  const lbl = { fontSize: 11, color: '#64748b', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6 };
  const errTxt = { fontSize: 11, color: '#f87171', marginTop: 3, fontWeight: 600 };
  const inp = (hasErr) => ({
    width: '100%', padding: '10px 14px', borderRadius: 9,
    background: 'rgba(15,23,42,0.7)',
    border: `1px solid ${hasErr ? '#ef444488' : 'rgba(100,116,139,0.25)'}`,
    color: '#e2e8f0', fontSize: 13, fontFamily: 'inherit', boxSizing: 'border-box',
    outline: 'none', transition: 'border-color 0.2s',
  });
  const sel = (hasErr) => ({ ...inp(hasErr), background: 'rgba(15,23,42,0.85)', cursor: 'pointer' });
  const readonlyInp = { ...inp(false), color: '#475569', background: 'rgba(15,23,42,0.4)', cursor: 'not-allowed' };
  const saveBtn = (color, disabled) => ({
    marginTop: 8, padding: '10px 28px', borderRadius: 9, border: 'none',
    background: disabled ? 'rgba(100,116,139,0.2)' : `linear-gradient(135deg, ${color}, ${color}cc)`,
    color: disabled ? '#475569' : '#fff', fontSize: 13, fontWeight: 800,
    cursor: disabled ? 'not-allowed' : 'pointer',
    boxShadow: disabled ? 'none' : `0 4px 14px ${color}44`,
    transition: 'all 0.2s',
  });
  const msgOk = { marginTop: 12, padding: '10px 14px', borderRadius: 8, fontSize: 13, fontWeight: 700, background: 'rgba(16,185,129,0.12)', color: '#34d399', border: '1px solid rgba(16,185,129,0.3)' };
  const msgErr = { marginTop: 12, padding: '10px 14px', borderRadius: 8, fontSize: 13, fontWeight: 700, background: 'rgba(239,68,68,0.12)', color: '#f87171', border: '1px solid rgba(239,68,68,0.3)' };

  const saveCompany = async (e) => {
    e.preventDefault();
    const errs = validateCompany();
    if (Object.keys(errs).length) { setCompanyErrs(errs); return; }
    if (isImpersonating) return setCompanyErr('Updates disabled during Super Admin partner login.');
    setCompanyBusy(true); setCompanyMsg(''); setCompanyErr('');
    try {
      await api.patch('/company/profile', companyForm);
      setCompanyMsg('Company details updated successfully.');
      setCompanyErrs({});
      onRefresh?.();
    } catch (err) { setCompanyErr(err.response?.data?.message || 'Failed to update'); }
    finally { setCompanyBusy(false); }
  };

  const saveAdmin = async (e) => {
    e.preventDefault();
    const errs = validateAdmin();
    if (Object.keys(errs).length) { setAdminErrs(errs); return; }
    if (isImpersonating) return setAdminErr('Updates disabled during Super Admin partner login.');
    setAdminBusy(true); setAdminMsg(''); setAdminErr('');
    try {
      await api.patch('/users/me', adminForm);
      setAdminMsg('Admin details updated successfully.');
      setAdminErrs({});
      onRefresh?.();
    } catch (err) { setAdminErr(err.response?.data?.message || 'Failed to update'); }
    finally { setAdminBusy(false); }
  };

  /* blur-time per-field validation */
  const blurCompany = (field) => {
    const errs = validateCompany();
    setCompanyErrs(prev => errs[field] ? { ...prev, [field]: errs[field] } : (({ [field]: _, ...rest }) => rest)(prev));
  };
  const blurAdmin = (field) => {
    const errs = validateAdmin();
    setAdminErrs(prev => errs[field] ? { ...prev, [field]: errs[field] } : (({ [field]: _, ...rest }) => rest)(prev));
  };

  const INDUSTRIES = ['Technology', 'Finance & Banking', 'Healthcare', 'Education', 'Retail & E-Commerce', 'Manufacturing', 'Logistics', 'Government', 'Media & Entertainment', 'Other'];
  const SIZES = ['1–10', '11–50', '51–200', '201–500', '501–1000', '1000+'];
  const COUNTRIES = ['India', 'United States', 'United Kingdom', 'UAE', 'Singapore', 'Australia', 'Canada', 'Germany', 'France', 'Other'];

  return (
    <div>
      {/* ── Company Details ── */}
      {user?.role !== 'department_admin' && <div style={cardStyle}>
        <div style={hdrStyle('#f59e0b')}>
          <div style={hdrIcon('#f59e0b')}>🏢</div>
          <span style={hdrText}>Company Details</span>
        </div>
        <form onSubmit={saveCompany} noValidate>
          <div style={{ ...gridTwo, marginBottom: 16 }}>
            <div style={fldWrap}>
              <label style={lbl}>Company Name <span style={{ color: '#ef4444' }}>*</span></label>
              <input style={inp(!!companyErrs.name)} value={companyForm.name}
                onChange={e => setCompanyForm(p => ({ ...p, name: e.target.value }))}
                onBlur={() => blurCompany('name')}
                placeholder="Your company name" />
              {companyErrs.name && <div style={errTxt}>⚠ {companyErrs.name}</div>}
            </div>
            <div style={fldWrap}>
              <label style={lbl}>Industry <span style={{ color: '#ef4444' }}>*</span></label>
              <select style={sel(!!companyErrs.industry)} value={companyForm.industry}
                onChange={e => setCompanyForm(p => ({ ...p, industry: e.target.value }))}
                onBlur={() => blurCompany('industry')}>
                <option value="">Select industry</option>
                {INDUSTRIES.map(i => <option key={i} value={i}>{i}</option>)}
              </select>
              {companyErrs.industry && <div style={errTxt}>⚠ {companyErrs.industry}</div>}
            </div>
            <div style={fldWrap}>
              <label style={lbl}>Website</label>
              <input style={inp(!!companyErrs.website)} value={companyForm.website}
                onChange={e => setCompanyForm(p => ({ ...p, website: e.target.value }))}
                onBlur={() => blurCompany('website')}
                placeholder="https://yourcompany.com" />
              {companyErrs.website && <div style={errTxt}>⚠ {companyErrs.website}</div>}
            </div>
            <div style={fldWrap}>
              <label style={lbl}>Company Size <span style={{ color: '#ef4444' }}>*</span></label>
              <select style={sel(!!companyErrs.companySize)} value={companyForm.companySize}
                onChange={e => setCompanyForm(p => ({ ...p, companySize: e.target.value }))}
                onBlur={() => blurCompany('companySize')}>
                <option value="">Select size</option>
                {SIZES.map(s => <option key={s} value={s}>{s} employees</option>)}
              </select>
              {companyErrs.companySize && <div style={errTxt}>⚠ {companyErrs.companySize}</div>}
            </div>
            <div style={fldWrap}>
              <label style={lbl}>Country <span style={{ color: '#ef4444' }}>*</span></label>
              <select style={sel(!!companyErrs.country)} value={companyForm.country}
                onChange={e => setCompanyForm(p => ({ ...p, country: e.target.value }))}
                onBlur={() => blurCompany('country')}>
                <option value="">Select country</option>
                {COUNTRIES.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              {companyErrs.country && <div style={errTxt}>⚠ {companyErrs.country}</div>}
            </div>
            <div style={fldWrap}>
              <label style={lbl}>Company Phone</label>
              <input style={inp(!!companyErrs.phone)} value={companyForm.phone}
                onChange={e => setCompanyForm(p => ({ ...p, phone: e.target.value }))}
                onBlur={() => blurCompany('phone')}
                placeholder="+91 98765 43210" />
              {companyErrs.phone && <div style={errTxt}>⚠ {companyErrs.phone}</div>}
            </div>
          </div>
          {companyMsg && <div style={msgOk}>✅ {companyMsg}</div>}
          {companyErr && <div style={msgErr}>⚠️ {companyErr}</div>}
          <button type="submit" disabled={companyBusy} style={saveBtn('#f59e0b', companyBusy)}>
            {companyBusy ? 'Saving...' : '💾 Save Company Details'}
          </button>
        </form>
      </div>}

      {/* ── Admin Details ── */}
      <div style={cardStyle}>
        <div style={hdrStyle('#00d9ff')}>
          <div style={hdrIcon('#00d9ff')}>👤</div>
          <span style={hdrText}>{user?.role === 'department_admin' ? 'Department Admin Details' : 'Admin Details'}</span>
        </div>
        <form onSubmit={saveAdmin} noValidate>
          <div style={{ ...gridTwo, marginBottom: 16 }}>
            <div style={fldWrap}>
              <label style={lbl}>Admin Name <span style={{ color: '#ef4444' }}>*</span></label>
              <input style={inp(!!adminErrs.name)} value={adminForm.name}
                onChange={e => setAdminForm(p => ({ ...p, name: e.target.value }))}
                onBlur={() => blurAdmin('name')}
                placeholder="Full name" />
              {adminErrs.name && <div style={errTxt}>⚠ {adminErrs.name}</div>}
            </div>
            <div style={fldWrap}>
              <label style={lbl}>Email <span style={{ fontSize: 10, color: '#475569' }}>(cannot be changed)</span></label>
              <input style={readonlyInp} value={user?.email || ''} readOnly />
            </div>
            <div style={fldWrap}>
              <label style={lbl}>Phone</label>
              <input style={inp(!!adminErrs.phone)} value={adminForm.phone}
                onChange={e => setAdminForm(p => ({ ...p, phone: e.target.value }))}
                onBlur={() => blurAdmin('phone')}
                placeholder="+91 98765 43210" />
              {adminErrs.phone && <div style={errTxt}>⚠ {adminErrs.phone}</div>}
            </div>
            <div style={fldWrap}>
              <label style={lbl}>Role</label>
              <input style={readonlyInp} value={accountRoleLabel(user?.role)} readOnly />
            </div>
          </div>
          {adminMsg && <div style={msgOk}>✅ {adminMsg}</div>}
          {adminErr && <div style={msgErr}>⚠️ {adminErr}</div>}
          <button type="submit" disabled={adminBusy} style={saveBtn('#00d9ff', adminBusy)}>
            {adminBusy ? 'Saving...' : '💾 Save Admin Details'}
          </button>
        </form>
      </div>
    </div>
  );
}



const Section = ({ title, icon, borderColor, children }) => (
  <div style={{
    background: 'linear-gradient(135deg, rgba(15,23,42,0.9) 0%, rgba(20,30,48,0.8) 100%)',
    borderRadius: 12, padding: '24px 28px', border: '1px solid rgba(100,116,139,0.15)',
    borderTop: `3px solid ${borderColor}`, marginBottom: 24,
    boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05), 0 4px 12px rgba(0,0,0,0.4)'
  }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 18 }}>
      {icon && <span style={{ fontSize: 20 }}>{icon}</span>}
      <h3 style={{ fontSize: 16, color: '#e2e8f0', margin: 0, fontWeight: 700 }}>{title}</h3>
    </div>
    {children}
  </div>
);

export default function SettingsPage() {
  const { user, company, isImpersonating, refreshCompany } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const socProfile = socProfileByRole[user?.role] || null;
  const [activeTab, setActiveTab] = useState(() => {
    const params = new URLSearchParams(window.location.search);
    const requestedTab = params.get('section') || params.get('tab');
    if (user?.role === 'department_admin') {
      return departmentAdminSettingsTabIds.has(requestedTab) ? requestedTab : 'profile';
    }
    return requestedTab || 'dashboard';
  });
  const [freshProfileUser, setFreshProfileUser] = useState(null);
  const [partnerStats, setPartnerStats] = useState(null);
  const [partnerPlanInfo, setPartnerPlanInfo] = useState(null);
  const [dashboardRefreshKey, setDashboardRefreshKey] = useState(0);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  // Password change
  const [pwForm, setPwForm] = useState({ currentPassword: '', newPassword: '', confirm: '' });
  const [pwMsg, setPwMsg] = useState('');
  const [pwErr, setPwErr] = useState('');
  const [pwBusy, setPwBusy] = useState(false);

  // 2FA state
  const [tfaStatus, setTfaStatus] = useState(null);
  const [tfaLoading, setTfaLoading] = useState(false);
  const [tfaQR, setTfaQR] = useState(null);
  const [tfaSecret, setTfaSecret] = useState('');
  const [tfaCode, setTfaCode] = useState('');
  const [tfaCopied, setTfaCopied] = useState(false);
  const [tfaErr, setTfaErr] = useState('');
  const [tfaMsg, setTfaMsg] = useState('');
  const [disableCode, setDisableCode] = useState('');

  // Subscription
  const [subData, setSubData] = useState(null);
  const [pricing, setPricing] = useState(null);
  const [subLoading, setSubLoading] = useState(false);

  // AutoPay
  const [autoPayBusy, setAutoPayBusy] = useState(false);

  // Add-system subscriptions tab
  const [addSubs, setAddSubs] = useState([]);
  const [addSubsLoad, setAddSubsLoad] = useState(false);
  const [addSubsFilter, setAddSubsFilter] = useState('all'); // 'all' | 'active' | 'expired'
  const [addSubsBusy, setAddSubsBusy] = useState(false);

  // Standard user extra state hooks
  const [standardSystems, setStandardSystems] = useState([]);
  const [standardAlertsCount, setStandardAlertsCount] = useState(0);
  const [standardAuditLogs, setStandardAuditLogs] = useState([]);
  const [activityPage, setActivityPage] = useState(1);
  const [standardTeam, setStandardTeam] = useState([]);
  const [standardDepts, setStandardDepts] = useState([]);
  const [loadingDashboard, setLoadingDashboard] = useState(false);
  const [loadingAgents, setLoadingAgents] = useState(false);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [auditError, setAuditError] = useState('');
  const [loadingTeam, setLoadingTeam] = useState(false);

  // Support Request
  const [supportForm, setSupportForm] = useState({ subject: '', message: '', severity: 'low' });
  const [supportBusy, setSupportBusy] = useState(false);
  const [supportSuccess, setSupportSuccess] = useState('');
  const [supportTickets, setSupportTickets] = useState([]);
  const [loadingSupport, setLoadingSupport] = useState(false);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [replyMessage, setReplyMessage] = useState('');
  const [replyBusy, setReplyBusy] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const [notifFilter, setNotifFilter] = useState('all');

  // Invite member inline form
  const [inviteForm, setInviteForm] = useState({ email: '', role: 'analyst', departmentId: '' });
  const [inviteBusy, setInviteBusy] = useState(false);
  const [inviteSuccess, setInviteSuccess] = useState('');
  const [inviteError, setInviteError] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const section = params.get('section') || params.get('tab');
    if (user?.role === 'department_admin') {
      setActiveTab(departmentAdminSettingsTabIds.has(section) ? section : 'profile');
    } else if (section) {
      setActiveTab(section);
    }
  }, [location.search, user?.role]);

  const allTabs = [
    { id: 'dashboard', label: 'Dashboard', icon: '⌂', color: '#4259ff' },
    { id: 'agents', label: 'Agent', icon: '◫', color: '#4259ff' },
    { id: 'subscription', label: 'Subscription & Payments', icon: '▤', color: '#ffaa00' },
    { id: 'requests', label: 'Buy Agent License', icon: '▱', color: '#60a5fa' },
    { id: 'profile', label: 'My Profile', icon: '♙', color: '#00d9ff' },
    { id: 'company', label: 'Company Information', icon: '▥', color: '#ff3333' },
    { id: 'kyc', label: 'KYC Documents', icon: '▧', color: '#4259ff' },
    { id: 'users', label: 'Users & Permissions', icon: '♧', color: '#4259ff' },
    { id: 'security', label: 'Security', icon: '⬡', color: '#00d98e' },
    { id: 'notifications', label: 'Notifications', icon: '♢', color: '#4259ff' },
    { id: 'activity', label: 'Activity Log', icon: '◷', color: '#4259ff' },
    { id: 'support', label: 'Support', icon: '?', color: '#4259ff' },
  ];
  const tabs = user?.role === 'department_admin'
    ? allTabs.filter(tab => departmentAdminSettingsTabIds.has(tab.id))
    : allTabs;

  useEffect(() => {
    if (user?.role === 'partner_admin') {
      api.get('/partner/dashboard').then(r => setPartnerStats(r.data)).catch(() => { });
      api.get('/payment/partner-plan').then(r => setPartnerPlanInfo(r.data)).catch(() => { });
      if (!tfaStatus) api.get('/2fa/status').then(r => setTfaStatus(r.data)).catch(() => { });
    } else if (socProfile) {
      if (!tfaStatus) api.get('/2fa/status').then(r => setTfaStatus(r.data)).catch(() => { });
      api.get('/soc-dashboard/notifications', { params: { limit: 100 }, skipCache: true })
        .then(async r => {
          const items = r.data?.items || [];
          const viewingNotifications = activeTab === 'notifications';
          setNotifications(viewingNotifications ? items.map(item => ({ ...item, read: true })) : items);
          setUnreadNotifications(viewingNotifications ? 0 : Number(r.data?.unread || 0));
          if (viewingNotifications && Number(r.data?.unread || 0) > 0) {
            await api.patch('/soc-dashboard/notifications/read', {}).catch(() => { });
            window.dispatchEvent(new CustomEvent('soc-notifications:unread', { detail: { unread: 0 } }));
          }
        })
        .catch(() => { });
      if (activeTab === 'activity') {
        setLoadingAudit(true);
        setAuditError('');
        api.get('/soc-dashboard/audit-events')
          .then(r => {
            setStandardAuditLogs(r.data?.items || r.data || []);
            setActivityPage(1);
          })
          .catch(err => {
            setStandardAuditLogs([]);
            setAuditError(err.response?.data?.message || 'Audit activity could not be loaded.');
          })
          .finally(() => setLoadingAudit(false));
      }
    } else {
      // Always fetch notifications unread count for standard users
      api.get('/company/notifications')
        .then(r => setUnreadNotifications(r.data?.unread || 0))
        .catch(() => { });

      // Standard user data fetching
      if (activeTab === 'dashboard') {
        setLoadingDashboard(true);
        Promise.all([
          api.get('/systems').then(r => setStandardSystems(r.data || [])).catch(() => { }),
          api.get('/alerts?status=open&limit=1').then(r => setStandardAlertsCount(r.data?.total || 0)).catch(() => { }),
          api.get('/payment/status').then(r => setSubData(r.data)).catch(() => { }),
          api.get('/users').then(r => setStandardTeam(r.data || [])).catch(() => { }),
          api.get('/company/activity-log').then(r => setStandardAuditLogs(r.data || [])).catch(() => { }),
          api.get('/company/notifications').then(r => {
            const items = r.data?.items || [];
            const unread = Number(r.data?.unread ?? items.filter(i => !i.read).length ?? 0);
            setNotifications(items);
            setUnreadNotifications(unread);
            window.dispatchEvent(new CustomEvent('company-notifications:unread', { detail: { unread } }));
          }).catch(() => { }),
          api.get('/2fa/status').then(r => setTfaStatus(r.data)).catch(() => { })
        ]).finally(() => setLoadingDashboard(false));
      }
      if (activeTab === 'agents') {
        setLoadingAgents(true);
        api.get('/systems')
          .then(r => setStandardSystems(r.data || []))
          .catch(() => { })
          .finally(() => setLoadingAgents(false));
      }
      if (activeTab === 'users') {
        setLoadingTeam(true);
        Promise.all([
          api.get('/users').then(r => setStandardTeam(r.data || [])).catch(() => { }),
          api.get('/department').then(r => setStandardDepts(r.data || [])).catch(() => { })
        ]).finally(() => setLoadingTeam(false));
      }
      if (activeTab === 'activity') {
        setLoadingAudit(true);
        api.get('/company/activity-log')
          .then(r => {
            setStandardAuditLogs(r.data || []);
            setActivityPage(1);
          })
          .catch(() => { })
          .finally(() => setLoadingAudit(false));
      }
      if (activeTab === 'support') {
        setLoadingSupport(true);
        api.get('/company/support-tickets')
          .then(r => {
            const tickets = r.data || [];
            setSupportTickets(tickets);
            setSelectedTicket(prev => prev ? (tickets.find(t => t._id === prev._id) || prev) : null);
          })
          .catch(() => { })
          .finally(() => setLoadingSupport(false));
      }
      if (activeTab === 'notifications') {
        if (user?.role === 'partner_admin') {
          api.get('/partner/notifications')
            .then(r => {
              setNotifications(r.data?.items || []);
              setUnreadNotifications(0);
              api.patch('/partner/notifications/read').catch(() => { });
            })
            .catch(() => { setNotifications([]); });
        } else if (socProfile) {
          api.get('/soc-dashboard/notifications', { params: { limit: 100 }, skipCache: true })
            .then(r => {
              setNotifications(r.data?.items || []);
              setUnreadNotifications(0);
              api.patch('/soc-dashboard/notifications/read', {}).catch(() => { });
            })
            .catch(() => { });
        } else {
          api.get('/company/notifications')
            .then(r => {
              const items = r.data?.items || [];
              const unread = Number(r.data?.unread ?? items.filter(i => !i.read).length ?? 0);
              setNotifications(items);
              setUnreadNotifications(unread);
              window.dispatchEvent(new CustomEvent('company-notifications:unread', { detail: { unread } }));
            })
            .catch(() => { });
        }
      }
      if (activeTab === 'subscription') {
        setSubLoading(true);
        Promise.all([
          api.get('/payment/status'),
          api.get('/payment/pricing'),
        ]).then(([a, b]) => {
          setSubData(a.data);
          setPricing(b.data);
        }).catch(() => { }).finally(() => setSubLoading(false));
      }
      if (activeTab === 'requests') {
        setAddSubsLoad(true);
        api.get('/add-system/list')
          .then(r => setAddSubs(r.data || []))
          .catch(() => setAddSubs([]))
          .finally(() => setAddSubsLoad(false));
      }
      if (activeTab === 'security' && !tfaStatus) {
        api.get('/2fa/status').then(r => setTfaStatus(r.data)).catch(() => { });
      }
    }
  }, [activeTab, user?.role, socProfile]);

  useEffect(() => {
    if (!socProfile || !user?._id) {
      setFreshProfileUser(null);
      return;
    }
    api.get('/users/me')
      .then(r => setFreshProfileUser(r.data || null))
      .catch(() => setFreshProfileUser(null));
  }, [socProfile, user?._id]);

  useEffect(() => {
    if (!socProfile || !user?._id) return undefined;
    const socket = io(SOCKET_URL, socketOptions);
    const onNotification = notification => {
      const isVisible = activeTab === 'notifications';
      const nextNotification = isVisible ? { ...notification, read: true, readAt: new Date().toISOString() } : notification;
      setNotifications(items => [nextNotification, ...items.filter(item => item._id !== notification._id)].slice(0, 100));
      if (isVisible) {
        api.patch('/soc-dashboard/notifications/read', { notificationId: notification._id }).catch(() => { });
      } else if (!notification.read) {
        setUnreadNotifications(count => count + 1);
      }
    };
    const onNotificationsRead = event => {
      setUnreadNotifications(Number(event?.unread || 0));
      if (!event?.unread) setNotifications(items => items.map(item => ({ ...item, read: true })));
    };
    socket.on('soc:notification', onNotification);
    socket.on('soc:notifications:read', onNotificationsRead);
    const disconnect = connectSocket(socket);
    return () => {
      socket.off('soc:notification', onNotification);
      socket.off('soc:notifications:read', onNotificationsRead);
      disconnect();
    };
  }, [socProfile, user?._id, activeTab]);

  useEffect(() => {
    if (user?.role !== 'partner_admin' || !user?.partnerId) return undefined;
    const socket = io(SOCKET_URL, socketOptions);
    socket.emit('join:partner', user.partnerId);
    socket.on('partner:update', (event) => {
      if (String(event.partnerId) !== String(user.partnerId)) return;
      // Refresh sidebar stats
      api.get('/partner/dashboard').then(r => setPartnerStats(r.data)).catch(() => { });
      api.get('/payment/partner-plan').then(r => setPartnerPlanInfo(r.data)).catch(() => { });
      // Force embedded PartnerDashboardPage to remount and reload
      setDashboardRefreshKey(prev => prev + 1);
    });
    return connectSocket(socket);
  }, [user?.role, user?.partnerId]);

  useEffect(() => {
    if (user?.role === 'partner_admin' || !company?._id) return undefined;
    const socket = io(SOCKET_URL, socketOptions);
    socket.emit('join:company', company._id);

    const handleCompanyUpdate = () => {
      refreshCompany();
      setRefreshTrigger(prev => prev + 1);
    };

    const handleTicketStatusUpdate = (event) => {
      if (event?.ticket) {
        const updated = event.ticket;
        setSupportTickets(prev => prev.map(t => t._id === updated._id ? { ...t, status: updated.status } : t));
        setSelectedTicket(prev => prev?._id === updated._id ? { ...prev, status: updated.status } : prev);
      }
    };

    const handleNewMessage = (event) => {
      if (event?.ticket) {
        const updated = event.ticket;
        setSupportTickets(prev => prev.map(t => t._id === updated._id ? updated : t));
        setSelectedTicket(prev => prev?._id === updated._id ? updated : prev);
      }
    };

    socket.on('company:update', handleCompanyUpdate);
    socket.on('department:update', handleCompanyUpdate);
    socket.on('user:update', handleCompanyUpdate);
    socket.on('alert:new', handleCompanyUpdate);
    socket.on('activity:new', handleCompanyUpdate);
    socket.on('support:ticket_new', handleCompanyUpdate);
    socket.on('support:message_new', handleNewMessage);
    socket.on('support:ticket_updated', handleTicketStatusUpdate);

    return connectSocket(socket);
  }, [user?.role, company?._id, refreshCompany]);

  useEffect(() => {
    if (activeTab !== 'support' || user?.role === 'partner_admin' || !company?._id) return undefined;
    const socket = io(SOCKET_URL, socketOptions);
    socket.emit('join:company', company._id);
    const onRead = event => {
      setSupportTickets(current => current.map(item => mergeSupportReadReceipts(item, event?.ticket)));
      setSelectedTicket(current => mergeSupportReadReceipts(current, event?.ticket));
    };
    socket.on('support:messages_read', onRead);
    const disconnect = connectSocket(socket);
    return () => { socket.off('support:messages_read', onRead); disconnect(); };
  }, [activeTab, user?.role, company?._id]);

  useEffect(() => {
    if (activeTab !== 'support' || user?.role === 'partner_admin' || !selectedTicket) return undefined;
    const messageIds = (selectedTicket.messages || []).filter(message => message._id && !message.readAt && ['superadmin', 'partner_admin'].includes(message.senderRole)).slice(0, 200).map(message => message._id);
    if (!messageIds.length) return undefined;
    const controller = new AbortController();
    let pending = false;
    const acknowledge = async () => {
      if (document.visibilityState !== 'visible' || pending) return;
      pending = true;
      try {
        const { data } = await api.post(`/company/support-tickets/${selectedTicket._id}/read`, { messageIds }, { signal: controller.signal });
        if (!controller.signal.aborted) {
          setSupportTickets(current => current.map(item => mergeSupportReadReceipts(item, data)));
          setSelectedTicket(current => mergeSupportReadReceipts(current, data));
        }
      } catch { /* Keep unread until the server acknowledges a visible chat. */ }
      finally { pending = false; }
    };
    acknowledge();
    document.addEventListener('visibilitychange', acknowledge);
    const timer = window.setInterval(acknowledge, 10000);
    return () => { controller.abort(); window.clearInterval(timer); document.removeEventListener('visibilitychange', acknowledge); };
  }, [activeTab, selectedTicket, user?.role]);

  // ── Change password ──
  const changePassword = async (e) => {
    e.preventDefault();
    if (isImpersonating) { setPwErr('Password changes are disabled during Super Admin partner login.'); return; }
    if (pwForm.newPassword !== pwForm.confirm) { setPwErr('Passwords do not match'); return; }
    setPwBusy(true); setPwMsg(''); setPwErr('');
    try {
      await api.post('/users/change-password', { currentPassword: pwForm.currentPassword, newPassword: pwForm.newPassword });
      setPwMsg('Password updated successfully.');
      setPwForm({ currentPassword: '', newPassword: '', confirm: '' });
    } catch (err) {
      setPwErr(err.response?.data?.message || 'Failed to update password');
    } finally { setPwBusy(false); }
  };

  // ── 2FA: Start setup ──
  const handle2FASetup = async () => {
    if (isImpersonating) { setTfaErr('2FA changes are disabled during Super Admin partner login.'); return; }
    setTfaLoading(true); setTfaErr(''); setTfaMsg('');
    try {
      const { data } = await api.post('/2fa/setup');
      setTfaQR(data.qrCode);
      setTfaSecret(data.secret);
      setTfaCode('');
      setTfaCopied(false);
    } catch (err) {
      setTfaErr(err.response?.data?.message || 'Failed to start 2FA setup');
    } finally { setTfaLoading(false); }
  };

  // ── 2FA: Verify & enable ──
  const handle2FAVerify = async () => {
    if (isImpersonating) { setTfaErr('2FA changes are disabled during Super Admin partner login.'); return; }
    if (tfaCode.length !== 6) { setTfaErr('Enter the 6-digit code from Google Authenticator'); return; }
    setTfaLoading(true); setTfaErr(''); setTfaMsg('');
    try {
      await api.post('/2fa/verify', { code: tfaCode });
      setTfaMsg('✅ 2FA enabled successfully!');
      setTfaStatus({ enabled: true, pending: false });
      setTfaQR(null); setTfaCode(''); setTfaSecret('');
      setTfaCopied(false);
      Swal.fire({ icon: 'success', title: '🔐 2FA Enabled', text: 'Google Authenticator is now protecting your account.', background: '#fff' });
    } catch (err) {
      setTfaErr(err.response?.data?.message || 'Invalid code. Please try again.');
    } finally { setTfaLoading(false); }
  };

  const handle2FACancel = async () => {
    if (tfaLoading) return;
    setTfaLoading(true); setTfaErr(''); setTfaMsg('');
    try {
      await api.post('/2fa/cancel');
      setTfaQR(null); setTfaSecret(''); setTfaCode(''); setTfaCopied(false);
      setTfaStatus({ enabled: false, pending: false });
    } catch (err) {
      setTfaErr(err.response?.data?.message || 'Could not cancel 2FA setup');
    } finally {
      setTfaLoading(false);
    }
  };

  // ── 2FA: Disable ──
  const handle2FADisable = async () => {
    if (isImpersonating) { setTfaErr('2FA changes are disabled during Super Admin partner login.'); return; }
    if (disableCode.length !== 6) { setTfaErr('Enter your 6-digit code to disable 2FA'); return; }
    setTfaLoading(true); setTfaErr('');
    try {
      await api.post('/2fa/disable', { code: disableCode });
      setTfaStatus({ enabled: false, pending: false });
      setDisableCode('');
      Swal.fire({ icon: 'info', title: '2FA Disabled', text: '2FA has been turned off for your account.', background: '#fff' });
    } catch (err) {
      setTfaErr(err.response?.data?.message || 'Invalid code');
    } finally { setTfaLoading(false); }
  };

  // ── Add-system: disable autopay (free) ──
  const disableBatchAutoPay = async (batch) => {
    if (isImpersonating) return Swal.fire({ icon: 'warning', title: 'Disabled', text: 'AutoPay changes are disabled during Super Admin partner login.', background: '#fff' });
    setAddSubsBusy(true);
    try {
      await api.post(`/add-system/autopay/${batch._id}`, { enabled: false });
      const { data } = await api.get('/add-system/list');
      setAddSubs(data || []);
      Swal.fire({ icon: 'success', title: 'AutoPay Disabled', timer: 1600, showConfirmButton: false, background: '#fff' });
    } catch (err) { Swal.fire({ icon: 'error', title: 'Error', text: err.response?.data?.message || 'Failed', background: '#fff' }); }
    finally { setAddSubsBusy(false); }
  };

  // ── Add-system: enable autopay (opens PaymentsPage) ──
  const enableBatchAutoPay = (batch) => {
    if (isImpersonating) return Swal.fire({ icon: 'warning', title: 'Disabled', text: 'AutoPay changes are disabled during Super Admin partner login.', background: '#fff' });
    Swal.fire({
      icon: 'info', title: 'Enable AutoPay for Batch',
      html: `<p style="font-size:13px">Go to <strong>Payments → Add Systems</strong> to authorize AutoPay for <strong>+${batch.addedSystemCount} Systems, +${batch.addedServerCount || 0} Servers, +${batch.addedPhoneCount || 0} Phones batch</strong>.</p>`,
      confirmButtonText: 'Go to Payments', background: '#fff',
    }).then(r => { if (r.isConfirmed) window.location.href = '/payments'; });
  };

  // ── AutoPay toggle (base plan) ──
  const toggleAutoPay = async () => {
    if (isImpersonating) return Swal.fire({ icon: 'warning', title: 'Disabled', text: 'AutoPay changes are disabled during Super Admin partner login.', background: '#fff' });
    setAutoPayBusy(true);
    try {
      const enabled = !subData?.plan?.autoPay;
      if (!enabled) {
        const { data } = await api.post('/payment/autopay', { enabled: false });
        setSubData(data.company);
        Swal.fire({ icon: 'success', title: '✅ AutoPay Disabled', timer: 2000, showConfirmButton: false, background: '#fff' });
        return;
      }

      const confirm = await Swal.fire({
        icon: 'info',
        title: 'Enable AutoPay',
        html: '<p style="font-size:14px;color:#64748b">Authorize a real recurring PhonePe/UPI AutoPay mandate through Razorpay Subscriptions.</p>',
        showCancelButton: true,
        confirmButtonText: 'Authorize AutoPay',
        background: '#fff',
      });
      if (!confirm.isConfirmed) return;

      const { data } = await api.post('/payment/autopay-order');
      await openRazorpay({
        order: data.order,
        subscription: data.subscription,
        planLabel: 'Base Plan AutoPay',
        email: user?.email,
        phone: user?.phone,
        onSuccess: async (response) => {
          const { data: confirmed } = await api.post('/payment/autopay-confirm', response);
          setSubData(confirmed.company);
          Swal.fire({ icon: 'success', title: '✅ AutoPay Enabled', timer: 2000, showConfirmButton: false, background: '#fff' });
        },
        onFailure: (msg) => Swal.fire({ icon: 'error', title: 'Payment Failed', text: msg || 'Payment could not be processed.', background: '#fff' }),
      });
    } catch (err) { Swal.fire({ icon: 'error', title: 'Error', text: err.response?.data?.message || 'Failed', background: '#fff' }); }
    finally { setAutoPayBusy(false); }
  };

  if (user?.role === 'partner_admin') {
    const partnerFromPlan = partnerPlanInfo?.partner;
    const mergedPartnerStats = partnerStats
      ? { ...partnerStats, partner: { ...(partnerStats.partner || {}), ...(partnerFromPlan || {}) } }
      : (partnerFromPlan ? { partner: partnerFromPlan } : null);
    return (
      <PartnerProfileMode
        user={user}
        partner={mergedPartnerStats?.partner}
        stats={mergedPartnerStats}
        dashboardRefreshKey={dashboardRefreshKey}
        pwForm={pwForm}
        setPwForm={setPwForm}
        pwMsg={pwMsg}
        pwErr={pwErr}
        pwBusy={pwBusy}
        changePassword={changePassword}
        isImpersonating={isImpersonating}
        onPartnerSaved={updatedPartner => setPartnerStats(prev => prev ? {
          ...prev,
          partner: updatedPartner,
          agentLicenses: updatedPartner?.agentLicensePurchases || prev.agentLicenses,
          agentLicenseSummary: updatedPartner?.agentLicenseSummary || prev.agentLicenseSummary,
        } : prev)}
        tfaStatus={tfaStatus}
        tfaLoading={tfaLoading}
        tfaQR={tfaQR}
        tfaSecret={tfaSecret}
        tfaCode={tfaCode}
        setTfaCode={setTfaCode}
        tfaErr={tfaErr}
        tfaMsg={tfaMsg}
        disableCode={disableCode}
        setDisableCode={setDisableCode}
        handle2FASetup={handle2FASetup}
        handle2FAVerify={handle2FAVerify}
        handle2FADisable={handle2FADisable}
        cancel2FASetup={() => { setTfaQR(null); setTfaSecret(''); setTfaCode(''); setTfaErr(''); setTfaMsg(''); }}
      />
    );
  }

  if (socProfile) {
    const profileAccount = freshProfileUser || user;
    const managerDetails = [
      ['Full Name', profileAccount?.name],
      ['Official Email', profileAccount?.email],
      ['Role', socProfile.label],
      ['Operational Scope', socProfile.scope],
      ['Phone', profileAccount?.phone || '—'],
      ['Account Status', titleCase(profileAccount?.accountStatus || (profileAccount?.isActive === false ? 'disabled' : 'active'))],
      ['Last Login', profileAccount?.lastLogin ? new Date(profileAccount.lastLogin).toLocaleString('en-IN') : '—'],
    ];
    const managerCard = { background: 'linear-gradient(135deg, rgba(15,23,42,.96), rgba(10,18,38,.92))', border: '1px solid #1e3a5f', borderRadius: 14, padding: 24 };
    const actionButton = { padding: '9px 16px', borderRadius: 8, border: 'none', background: '#2563eb', color: '#fff', fontSize: 12, fontWeight: 800, cursor: 'pointer' };
    const managerTabs = [
      ['profile', '♙', 'My Profile'],
      ['notifications', '◇', 'Notifications'],
      ['security', '🔐', '2-Step Verification'],
      ['activity', '◷', 'Audit Trail'],
    ];
    const managerTab = managerTabs.some(([id]) => id === activeTab) ? activeTab : 'profile';
    const managerAuditPageSize = 10;
    const managerAuditTotalPages = Math.max(1, Math.ceil(standardAuditLogs.length / managerAuditPageSize));
    const managerAuditPage = Math.min(activityPage, managerAuditTotalPages);
    const managerAuditLogs = standardAuditLogs.slice(
      (managerAuditPage - 1) * managerAuditPageSize,
      managerAuditPage * managerAuditPageSize,
    );
    return (
      <div style={partnerProfilePage}>
        <aside style={partnerProfileSidebar}>
          {managerTabs.map(([id, icon, label]) => (
            <button key={id} type="button" onClick={() => {
              setActiveTab(id);
              navigate(`${location.pathname}?section=${id}`, { replace: true });
            }} style={{ ...profileNav, display: 'flex', alignItems: 'center', gap: 8, ...(managerTab === id ? profileNavActive : {}) }}>
              <span style={{ fontSize: 16 }}>{icon}</span>
              <span style={{ flex: 1, textAlign: 'left' }}>{label}</span>
              {id === 'notifications' && unreadNotifications > 0 && (
                <span style={{ minWidth: 18, height: 18, padding: '0 5px', display: 'grid', placeItems: 'center', borderRadius: 10, background: '#ef4444', color: '#fff', fontSize: 9, fontWeight: 900 }}>
                  {unreadNotifications > 99 ? '99+' : unreadNotifications}
                </span>
              )}
            </button>
          ))}
        </aside>
        <main style={{ ...profileContentMain, display: 'grid', alignContent: 'start' }}>
          {managerTab === 'profile' && (
            <div style={{ background: 'linear-gradient(135deg, rgba(15,23,42,.96), rgba(10,18,38,.92))', border: '1px solid #1e3a5f', borderRadius: 14, padding: 28 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, paddingBottom: 18, marginBottom: 8, borderBottom: '1px solid #1e3a5f' }}>
                <div style={{ width: 44, height: 44, borderRadius: 12, display: 'grid', placeItems: 'center', background: 'rgba(6,182,212,.14)', border: '1px solid rgba(34,211,238,.35)', fontSize: 21 }}>{socProfile.icon}</div>
                <div>
                  <h2 style={{ margin: 0, color: '#e2e8f0', fontSize: 20 }}>{socProfile.heading}</h2>
                  <div style={{ color: '#67e8f9', fontSize: 12, marginTop: 3 }}>{socProfile.subtitle}</div>
                </div>
              </div>
              {managerDetails.map(([label, value]) => (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: 20, padding: '14px 2px', borderBottom: '1px solid rgba(100,116,139,.12)', fontSize: 13 }}>
                  <span style={{ color: '#64748b', fontWeight: 700 }}>{label}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700, textAlign: 'right' }}>{value || '—'}</span>
                </div>
              ))}
            </div>
          )}

          {managerTab === 'notifications' && (
            <div style={{ display: 'grid', gap: 16 }}>
              <div style={managerCard}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                  <div>
                    <h3 style={{ margin: 0, color: '#e2e8f0', fontSize: 16 }}>◇ Notifications</h3>
                    <div style={{ color: '#64748b', fontSize: 11, marginTop: 4 }}>Tickets, Super Admin/SOC Manager changes and chat messages</div>
                  </div>
                  <button type="button" onClick={async () => {
                    const { data } = await api.patch('/soc-dashboard/notifications/read', {}).catch(() => ({ data: { unread: unreadNotifications } }));
                    setUnreadNotifications(Number(data?.unread || 0));
                    setNotifications(items => items.map(item => ({ ...item, read: true, readAt: item.readAt || new Date().toISOString() })));
                    window.dispatchEvent(new CustomEvent('soc-notifications:unread', { detail: { unread: Number(data?.unread || 0) } }));
                  }} style={{ ...actionButton, padding: '8px 12px', background: '#172554', border: '1px solid #2563eb' }}>Mark All Read</button>
                </div>
                <div style={{ display: 'grid', gap: 9 }}>
                  {notifications.length ? notifications.slice(0, 5).map(notification => (
                    <button
                      key={notification._id}
                      type="button"
                      onClick={() => notification.link && navigate(notification.link)}
                      style={{ width: '100%', display: 'grid', gridTemplateColumns: '36px minmax(0,1fr) auto', alignItems: 'start', gap: 11, padding: 13, textAlign: 'left', borderRadius: 10, border: notification.read ? '1px solid #1e3a5f' : '1px solid #2563eb', background: notification.read ? '#081426' : 'rgba(37,99,235,.12)', color: '#cbd5e1', cursor: notification.link ? 'pointer' : 'default' }}
                    >
                      <span style={{ width: 34, height: 34, display: 'grid', placeItems: 'center', borderRadius: 9, background: notification.type === 'chat_message' ? 'rgba(16,185,129,.13)' : notification.type === 'admin_change' ? 'rgba(168,85,247,.13)' : 'rgba(37,99,235,.13)', fontSize: 16 }}>
                        {notification.type === 'chat_message' ? '💬' : notification.type === 'admin_change' ? '⚙' : '🎟'}
                      </span>
                      <span style={{ minWidth: 0 }}>
                        <b style={{ display: 'block', color: '#e2e8f0', fontSize: 13 }}>{notification.title}</b>
                        <span style={{ display: 'block', color: '#94a3b8', fontSize: 11, lineHeight: 1.5, marginTop: 4 }}>{notification.message}</span>
                        <small style={{ display: 'block', color: '#64748b', marginTop: 6 }}>
                          {new Date(notification.createdAt).toLocaleString('en-IN')}
                          {notification.actorId?.name ? ` · ${notification.actorId.name}` : ''}
                          {notification.companyId?.name ? ` · ${notification.companyId.name}` : ''}
                        </small>
                      </span>
                      {!notification.read && <span style={{ borderRadius: 999, background: '#ef4444', color: '#fff', padding: '3px 7px', fontSize: 9, fontWeight: 900 }}>New</span>}
                    </button>
                  )) : <div style={{ padding: 26, textAlign: 'center', color: '#64748b', fontSize: 12 }}>No notifications yet.</div>}
                </div>
              </div>

            </div>
          )}

          {managerTab === 'security' && (
            <div style={{ ...managerCard, maxWidth: 920 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 16, alignItems: 'flex-start', paddingBottom: 18, borderBottom: '1px solid #1e3a5f' }}>
                <div>
                  <h3 style={{ margin: 0, color: '#f1f5f9', fontSize: 18 }}>🔐 2-Step Verification</h3>
                  <p style={{ color: '#94a3b8', fontSize: 12, lineHeight: 1.55, margin: '6px 0 0' }}>Protect your {socProfile.label} account with a time-based code from Google Authenticator or another TOTP app.</p>
                </div>
                <span style={{ flexShrink: 0, borderRadius: 999, padding: '6px 10px', color: tfaStatus?.enabled ? '#6ee7b7' : tfaStatus?.pending ? '#fcd34d' : '#cbd5e1', background: tfaStatus?.enabled ? 'rgba(16,185,129,.13)' : tfaStatus?.pending ? 'rgba(245,158,11,.13)' : 'rgba(100,116,139,.15)', border: `1px solid ${tfaStatus?.enabled ? 'rgba(16,185,129,.4)' : tfaStatus?.pending ? 'rgba(245,158,11,.4)' : 'rgba(100,116,139,.35)'}`, fontSize: 10, fontWeight: 900, textTransform: 'uppercase', letterSpacing: '.06em' }}>
                  {tfaStatus === null ? 'Checking…' : tfaStatus.enabled ? '● Enabled' : tfaQR || tfaStatus.pending ? '● Setup pending' : '○ Disabled'}
                </span>
              </div>

              {tfaStatus === null && <div style={{ padding: '32px 0', color: '#94a3b8', fontSize: 13 }}>Checking two-step verification status…</div>}

              {tfaStatus && !tfaStatus.enabled && !tfaQR && (
                <div style={{ maxWidth: 610, paddingTop: 22 }}>
                  <div style={{ display: 'grid', gap: 10, marginBottom: 18 }}>
                    {[
                      ['1', 'Install an authenticator app', 'Use Google Authenticator, Microsoft Authenticator or any TOTP-compatible app.'],
                      ['2', 'Scan and verify', 'Scan the QR code, then enter the current 6-digit code to finish setup.'],
                      ['3', 'Use it at sign-in', 'After password/email verification, the authenticator code will be required before dashboard access.'],
                    ].map(([number, title, text]) => (
                      <div key={number} style={{ display: 'grid', gridTemplateColumns: '30px 1fr', gap: 10, alignItems: 'start' }}>
                        <span style={{ width: 28, height: 28, display: 'grid', placeItems: 'center', borderRadius: 9, background: 'rgba(37,99,235,.18)', border: '1px solid rgba(59,130,246,.45)', color: '#93c5fd', fontSize: 11, fontWeight: 900 }}>{number}</span>
                        <span><b style={{ display: 'block', color: '#e2e8f0', fontSize: 12 }}>{title}</b><small style={{ color: '#64748b', lineHeight: 1.5 }}>{text}</small></span>
                      </div>
                    ))}
                  </div>
                  <button type="button" onClick={handle2FASetup} disabled={tfaLoading || isImpersonating} style={{ ...actionButton, opacity: tfaLoading || isImpersonating ? .6 : 1 }}>
                    {tfaLoading ? 'Preparing secure setup…' : tfaStatus.pending ? 'Restart Authenticator Setup' : 'Set Up Authenticator'}
                  </button>
                </div>
              )}

              {tfaStatus && !tfaStatus.enabled && tfaQR && (
                <form onSubmit={e => { e.preventDefault(); handle2FAVerify(); }} className="soc-2fa-setup-grid" style={{ display: 'grid', gridTemplateColumns: '220px minmax(280px,1fr)', gap: 26, alignItems: 'start', paddingTop: 22 }}>
                  <div style={{ display: 'grid', justifyItems: 'center', gap: 9, padding: 14, borderRadius: 13, background: '#f8fafc', border: '1px solid #cbd5e1' }}>
                    <img src={tfaQR} alt="Scan this QR code in your authenticator app" style={{ display: 'block', width: 184, height: 184 }} />
                    <span style={{ color: '#334155', fontSize: 10, fontWeight: 800 }}>SCAN WITH AUTHENTICATOR APP</span>
                  </div>

                  <div style={{ display: 'grid', gap: 13 }}>
                    <div>
                      <b style={{ color: '#e2e8f0', fontSize: 13 }}>1. Scan the QR code</b>
                      <p style={{ color: '#94a3b8', fontSize: 11, lineHeight: 1.55, margin: '4px 0 0' }}>Open your authenticator app, add a new account and scan the code shown here.</p>
                    </div>
                    <div>
                      <b style={{ color: '#e2e8f0', fontSize: 13 }}>Manual setup key</b>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 7 }}>
                        <code style={{ flex: 1, minWidth: 0, padding: '9px 10px', borderRadius: 8, background: '#060e1a', border: '1px solid #1e3a5f', color: '#93c5fd', fontSize: 11, wordBreak: 'break-all', userSelect: 'all' }}>{tfaSecret}</code>
                        <button type="button" onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(tfaSecret);
                            setTfaCopied(true);
                            window.setTimeout(() => setTfaCopied(false), 1600);
                          } catch { setTfaErr('Copy failed. Select the setup key manually.'); }
                        }} style={{ ...actionButton, padding: '9px 11px', background: '#172554' }}>{tfaCopied ? 'Copied' : 'Copy'}</button>
                      </div>
                    </div>
                    <label style={{ display: 'grid', gap: 7 }}>
                      <b style={{ color: '#e2e8f0', fontSize: 13 }}>2. Enter the 6-digit code</b>
                      <input
                        value={tfaCode}
                        onChange={e => { setTfaCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setTfaErr(''); }}
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        maxLength={6}
                        autoFocus
                        aria-label="Six-digit authenticator verification code"
                        placeholder="000000"
                        style={{ width: '100%', boxSizing: 'border-box', padding: '12px 14px', borderRadius: 9, border: `1px solid ${tfaErr ? '#ef4444' : '#294765'}`, background: '#060e1a', color: '#f8fafc', fontSize: 20, fontWeight: 850, letterSpacing: '.32em', textAlign: 'center', outline: 'none' }}
                      />
                    </label>
                    <div style={{ display: 'flex', gap: 9, flexWrap: 'wrap' }}>
                      <button type="submit" disabled={tfaLoading || tfaCode.length !== 6} style={{ ...actionButton, minWidth: 150, opacity: tfaLoading || tfaCode.length !== 6 ? .55 : 1 }}>
                        {tfaLoading ? 'Verifying…' : 'Verify & Enable'}
                      </button>
                      <button type="button" onClick={handle2FACancel} disabled={tfaLoading} style={{ padding: '9px 15px', borderRadius: 8, border: '1px solid #334155', background: '#111827', color: '#cbd5e1', fontSize: 12, fontWeight: 800, cursor: 'pointer' }}>Cancel Setup</button>
                    </div>
                    <small style={{ color: '#f59e0b', lineHeight: 1.5 }}>Never share this QR code, setup key or verification code with anyone.</small>
                  </div>
                </form>
              )}

              {tfaStatus?.enabled && (
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(280px,380px)', gap: 20, alignItems: 'start', paddingTop: 22 }} className="soc-2fa-enabled-grid">
                  <div style={{ padding: 18, borderRadius: 12, border: '1px solid rgba(16,185,129,.38)', background: 'rgba(16,185,129,.08)' }}>
                    <b style={{ color: '#6ee7b7', fontSize: 14 }}>✓ Authenticator protection is active</b>
                    <p style={{ color: '#94a3b8', fontSize: 12, lineHeight: 1.6, margin: '7px 0 0' }}>Your password alone cannot complete sign-in. A valid 6-digit authenticator code is also required.</p>
                  </div>
                  <form onSubmit={e => { e.preventDefault(); handle2FADisable(); }} style={{ padding: 16, borderRadius: 12, border: '1px solid rgba(239,68,68,.32)', background: 'rgba(127,29,29,.09)' }}>
                    <b style={{ color: '#fecaca', fontSize: 13 }}>Disable 2-Step Verification</b>
                    <p style={{ color: '#94a3b8', fontSize: 11, lineHeight: 1.5, margin: '5px 0 10px' }}>Enter the current authenticator code to confirm.</p>
                    <input value={disableCode} onChange={e => { setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setTfaErr(''); }} inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="6-digit code" style={{ width: '100%', boxSizing: 'border-box', padding: '10px 12px', borderRadius: 8, border: '1px solid #7f1d1d', background: '#090d17', color: '#fff', letterSpacing: '.18em', textAlign: 'center' }} />
                    <button type="submit" disabled={tfaLoading || disableCode.length !== 6} style={{ width: '100%', marginTop: 9, padding: '9px 12px', borderRadius: 8, border: '1px solid #dc2626', background: '#991b1b', color: '#fff', fontSize: 12, fontWeight: 850, cursor: 'pointer', opacity: tfaLoading || disableCode.length !== 6 ? .55 : 1 }}>{tfaLoading ? 'Disabling…' : 'Disable 2FA'}</button>
                  </form>
                </div>
              )}

              {tfaErr && <div role="alert" style={{ color: '#fecaca', background: 'rgba(127,29,29,.18)', border: '1px solid rgba(239,68,68,.35)', borderRadius: 8, padding: '9px 11px', fontSize: 11, marginTop: 14 }}>{tfaErr}</div>}
              {tfaMsg && <div style={{ color: '#6ee7b7', background: 'rgba(16,185,129,.1)', border: '1px solid rgba(16,185,129,.32)', borderRadius: 8, padding: '9px 11px', fontSize: 11, marginTop: 14 }}>{tfaMsg}</div>}
              <style>{`@media(max-width:720px){.soc-2fa-setup-grid,.soc-2fa-enabled-grid{grid-template-columns:1fr!important}.soc-2fa-setup-grid>div:first-child{justify-self:center}}`}</style>
            </div>
          )}

          {managerTab === 'activity' && (
            <div style={managerCard}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 14 }}>
                <div>
                  <h3 style={{ margin: 0, color: '#e2e8f0', fontSize: 16 }}>◷ Audit Trail</h3>
                  <div style={{ color: '#64748b', fontSize: 11, marginTop: 4 }}>Your authentication and L4 threat-intelligence actions</div>
                </div>
                {!loadingAudit && !auditError && <span style={{ color: '#67e8f9', fontSize: 11, fontWeight: 800 }}>{standardAuditLogs.length} events</span>}
              </div>
              {loadingAudit ? (
                <div style={{ color: '#60a5fa', fontSize: 13, padding: '12px 0' }}>Loading audit activity…</div>
              ) : auditError ? (
                <div style={{ color: '#fca5a5', background: 'rgba(127,29,29,.18)', border: '1px solid rgba(248,113,113,.28)', borderRadius: 8, padding: 12, fontSize: 12 }}>{auditError}</div>
              ) : standardAuditLogs.length ? managerAuditLogs.map((log, index) => {
                const label = log.label || titleCase(log.action || 'Account activity');
                const details = log.details && log.details !== label ? log.details : '';
                const actor = log.actor?.name || log.actor?.email || profileAccount?.name || 'Current user';
                const actorMeta = [log.actor?.email, log.ipAddress, log.device].filter(Boolean).join(' • ');
                const failed = log.status === 'failed';
                return (
                  <div key={log._id || index} style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 1.5fr) minmax(170px, 1fr) auto', gap: 18, alignItems: 'center', padding: '13px 0', borderBottom: '1px solid rgba(100,116,139,.12)', fontSize: 12 }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ color: '#e2e8f0', fontWeight: 800 }}>{label}</div>
                      {details && <div style={{ color: '#64748b', fontSize: 11, marginTop: 4, overflowWrap: 'anywhere' }}>{details}</div>}
                      <span style={{ display: 'inline-block', marginTop: 6, color: log.source === 'soc' ? '#67e8f9' : '#a5b4fc', background: log.source === 'soc' ? 'rgba(8,145,178,.14)' : 'rgba(79,70,229,.14)', borderRadius: 999, padding: '3px 7px', fontSize: 9, fontWeight: 800, textTransform: 'uppercase' }}>{log.category || titleCase(log.source || 'activity')}</span>
                    </div>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ color: '#cbd5e1', fontWeight: 700 }}>{actor}</div>
                      {actorMeta && <div style={{ color: '#64748b', fontSize: 10, marginTop: 4, overflowWrap: 'anywhere' }}>{actorMeta}</div>}
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ color: failed ? '#f87171' : '#34d399', fontSize: 9, fontWeight: 900, textTransform: 'uppercase' }}>{failed ? 'Failed' : 'Success'}</div>
                      <div style={{ color: '#64748b', whiteSpace: 'nowrap', marginTop: 5 }}>{log.createdAt ? new Date(log.createdAt).toLocaleString('en-IN') : '—'}</div>
                    </div>
                  </div>
                );
              }) : <div style={{ color: '#64748b', fontSize: 13 }}>No personal authentication or threat-intelligence activity recorded yet.</div>}
              {!loadingAudit && standardAuditLogs.length > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginTop: 16, paddingTop: 14, borderTop: '1px solid rgba(100,116,139,.18)' }}>
                  <button
                    type="button"
                    onClick={() => setActivityPage(page => Math.max(1, page - 1))}
                    disabled={managerAuditPage === 1}
                    style={{ ...actionButton, background: managerAuditPage === 1 ? '#1e293b' : '#1d4ed8', color: managerAuditPage === 1 ? '#64748b' : '#fff', cursor: managerAuditPage === 1 ? 'not-allowed' : 'pointer' }}
                  >
                    ← Previous
                  </button>
                  <span style={{ color: '#94a3b8', fontSize: 12 }}>
                    Page <strong style={{ color: '#e2e8f0' }}>{managerAuditPage}</strong> of <strong style={{ color: '#e2e8f0' }}>{managerAuditTotalPages}</strong>
                  </span>
                  <button
                    type="button"
                    onClick={() => setActivityPage(page => Math.min(managerAuditTotalPages, page + 1))}
                    disabled={managerAuditPage === managerAuditTotalPages}
                    style={{ ...actionButton, background: managerAuditPage === managerAuditTotalPages ? '#1e293b' : '#2563eb', color: managerAuditPage === managerAuditTotalPages ? '#64748b' : '#fff', cursor: managerAuditPage === managerAuditTotalPages ? 'not-allowed' : 'pointer' }}
                  >
                    Next →
                  </button>
                </div>
              )}
            </div>
          )}

        </main>
      </div>
    );
  }

  const infoRow = (label, value) => (
    <div style={{
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      padding: '12px 0', borderBottom: '1px solid rgba(100,116,139,0.1)', fontSize: 13
    }}>
      <span style={{ color: '#94a3b8', fontWeight: 500 }}>{label}</span>
      <span style={{ color: '#e2e8f0', fontWeight: 600, maxWidth: '60%', textAlign: 'right', wordBreak: 'break-word' }}>{value || '—'}</span>
    </div>
  );

  const inpStyle = {
    width: '100%', padding: '10px 12px', borderRadius: 8,
    background: 'linear-gradient(135deg, rgba(15,23,42,0.5) 0%, rgba(20,30,48,0.3) 100%)',
    border: '1px solid rgba(100,116,139,0.3)', color: '#e2e8f0', fontSize: 13,
    boxSizing: 'border-box', fontFamily: 'inherit',
  };

  const renderContent = () => {
    if (activeTab === 'dashboard') {
      const totalSystemsLimit = company?.plan?.systemCount || company?.plan?.systemLimit || 10;
      const nextRenewalDate = company?.plan?.expiresAt ? fmtDate(company?.plan?.expiresAt) : '—';
      const planActive = subData?.plan?.isActive || company?.plan?.isActive;

      const checkAgentOnline = (s) => {
        if (!s) return false;
        const st = String(s.status || '').toLowerCase();
        if (st === 'offline' || st === 'disconnected' || st === 'inactive' || s.isActive === false) return false;
        if (s.isOnline === false) return false;
        if (!s.lastSeen) return false;
        const diffMs = Date.now() - new Date(s.lastSeen).getTime();
        if (diffMs > 300000) return false;
        return s.isOnline === true || st === 'active' || st === 'online' || st === 'connected';
      };

      const onlineCount = standardSystems.filter(checkAgentOnline).length;
      const registeredCount = standardSystems.length;

      const settingsSummaryCards = [
        {
          id: 'agents', icon: '🖥️', tone: '#3b82f6',
          title: 'Agent', subtitle: 'Endpoint Telemetry',
          stat: `${onlineCount} Active`,
          substat: `${registeredCount} / ${totalSystemsLimit} registered`,
          badge: onlineCount > 0 ? 'Active' : 'Inactive',
          badgeOk: onlineCount > 0,
          desc: 'Manage and download EDR telemetry agents for endpoints.',
        },
        {
          id: 'subscription', icon: '💳', tone: '#10b981',
          title: 'Subscription & Payments', subtitle: 'Billing Overview',
          stat: planActive ? '✅ Active' : '⚠️ Inactive',
          substat: nextRenewalDate !== '—' ? `Renews ${nextRenewalDate}` : 'No renewal date',
          badge: planActive ? 'Active' : 'Inactive',
          badgeOk: planActive,
          desc: 'View billing cycle, plan details, and payment history.',
        },
        {
          id: 'requests', icon: '🔑', tone: '#60a5fa',
          title: 'Buy Agent License', subtitle: 'License Management',
          stat: `${company?.plan?.systemCount || 0} Systems`,
          substat: `${company?.plan?.serverCount || 0} Servers · ${company?.plan?.phoneCount || 0} Phones`,
          badge: (company?.plan?.systemCount || 0) > 0 ? 'Licensed' : 'None',
          badgeOk: (company?.plan?.systemCount || 0) > 0,
          desc: 'Purchase additional system, server, or phone agent slots.',
        },
        {
          id: 'profile', icon: '👤', tone: '#00d9ff',
          title: 'My Profile', subtitle: 'Account Information',
          stat: user?.name || '—',
          substat: user?.email || '—',
          badge: user?.role === 'department_admin' ? 'Dept Admin' : user?.role === 'company_admin' ? 'Admin' : 'Analyst',
          badgeOk: true,
          desc: 'View and manage your personal account credentials.',
        },
        {
          id: 'company', icon: '🏢', tone: '#f59e0b',
          title: 'Company Information', subtitle: 'Organisation Details',
          stat: company?.name || '—',
          substat: company?.email || '—',
          badge: company?.status ? (company.status.charAt(0).toUpperCase() + company.status.slice(1)) : 'Active',
          badgeOk: company?.status !== 'suspended',
          desc: 'View company details, plan limits, and contact info.',
        },
        {
          id: 'users', icon: '👥', tone: '#06b6d4',
          title: 'Users & Permissions', subtitle: 'Team Management',
          stat: `${standardTeam.length || '—'} Members`,
          substat: `${standardTeam.filter(u => u.isActive).length || 0} active users`,
          badge: standardTeam.length > 0 ? 'Configured' : 'No Users',
          badgeOk: standardTeam.length > 0,
          desc: 'Invite team members and manage role-based access.',
        },
        {
          id: 'notifications', icon: '🔔', tone: '#f97316',
          title: 'Notifications', subtitle: 'Administrative Feed',
          stat: `${unreadNotifications} Unread`,
          substat: `${notifications.length} recent notifications loaded`,
          badge: unreadNotifications > 0 ? 'Action Required' : 'Up to Date',
          badgeOk: unreadNotifications === 0,
          desc: 'Review company alerts, account changes, and administrative updates.',
        },
        {
          id: 'security', icon: '🔐', tone: '#ef4444',
          title: 'Security', subtitle: 'Account Protection',
          stat: tfaStatus?.enabled ? '2FA Enabled' : '2FA Disabled',
          substat: 'Password & authenticator',
          badge: tfaStatus?.enabled ? '2FA On' : '2FA Off',
          badgeOk: Boolean(tfaStatus?.enabled),
          desc: 'Change password and configure Google Authenticator 2FA.',
        },
        {
          id: 'activity', icon: '📜', tone: '#84cc16',
          title: 'Activity Log', subtitle: 'Audit Trail',
          stat: `${standardAuditLogs.length || 0} Events`,
          substat: 'Recent account actions',
          badge: 'Logging',
          badgeOk: true,
          desc: 'Full audit trail of account and security events.',
        },
        {
          id: 'support', icon: '💬', tone: '#cbd5e1',
          title: 'Support', subtitle: 'Help & Tickets',
          stat: 'Create Ticket',
          substat: 'Help & issue tracking',
          badge: 'Available',
          badgeOk: true,
          desc: 'Contact support team for platform issues or questions.',
        },
      ];

      return (
        <>
          {/* ── Section Overview Title ── */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 18 }}>
            <div style={{ height: 3, flex: 1, background: 'linear-gradient(90deg, #3b82f6, transparent)', borderRadius: 2 }} />
            <span style={{ fontSize: 12, color: '#475569', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.2, whiteSpace: 'nowrap' }}>Settings Overview</span>
            <div style={{ height: 3, flex: 1, background: 'linear-gradient(270deg, #3b82f6, transparent)', borderRadius: 2 }} />
          </div>

          {/* ── Settings Summary Cards Grid ── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 16, marginBottom: 28 }}>
            {settingsSummaryCards.map(card => (
              <button
                key={card.id}
                onClick={() => setActiveTab(card.id)}
                style={{
                  textAlign: 'left', padding: 0, border: `1px solid ${card.tone}28`,
                  borderRadius: 16, cursor: 'pointer', outline: 'none',
                  background: `linear-gradient(135deg, rgba(10,20,40,0.95) 0%, rgba(15,25,50,0.9) 100%)`,
                  boxShadow: `0 4px 20px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.04)`,
                  transition: 'transform 0.15s ease, box-shadow 0.15s ease',
                  overflow: 'hidden', display: 'flex', flexDirection: 'column',
                  fontFamily: 'inherit',
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.transform = 'translateY(-2px)';
                  e.currentTarget.style.boxShadow = `0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px ${card.tone}44, inset 0 1px 0 rgba(255,255,255,0.06)`;
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.transform = 'translateY(0)';
                  e.currentTarget.style.boxShadow = `0 4px 20px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.04)`;
                }}
              >
                {/* Card top accent bar */}
                <div style={{ height: 3, background: `linear-gradient(90deg, ${card.tone}, ${card.tone}66)`, borderRadius: '16px 16px 0 0' }} />

                <div style={{ padding: '18px 20px', flex: 1 }}>
                  {/* Header row */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div style={{
                        width: 44, height: 44, borderRadius: 12, display: 'grid', placeItems: 'center',
                        background: `${card.tone}16`, border: `1px solid ${card.tone}44`, fontSize: 20, flexShrink: 0,
                      }}>{card.icon}</div>
                      <div>
                        <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 800, lineHeight: 1.2 }}>{card.title}</div>
                        <div style={{ fontSize: 10, color: '#475569', marginTop: 3, fontWeight: 600 }}>{card.subtitle}</div>
                      </div>
                    </div>
                    <span style={{
                      fontSize: 9, padding: '4px 9px', borderRadius: 20, fontWeight: 800,
                      background: card.badgeOk ? `${card.tone}18` : 'rgba(239,68,68,0.15)',
                      color: card.badgeOk ? card.tone : '#f87171',
                      border: `1px solid ${card.badgeOk ? card.tone + '44' : 'rgba(239,68,68,0.4)'}`,
                      whiteSpace: 'nowrap',
                    }}>{card.badge}</span>
                  </div>

                  {/* Stat */}
                  <div style={{ fontSize: 17, color: card.tone, fontWeight: 900, lineHeight: 1.1, marginBottom: 4, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{card.stat}</div>
                  <div style={{ fontSize: 11, color: '#64748b', marginBottom: 12, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{card.substat}</div>

                  {/* Divider */}
                  <div style={{ height: 1, background: 'rgba(100,116,139,0.1)', marginBottom: 12 }} />

                  {/* Description & CTA */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
                    <div style={{ fontSize: 11, color: '#475569', lineHeight: 1.5, flex: 1 }}>{card.desc}</div>
                    <div style={{
                      fontSize: 11, color: card.tone, fontWeight: 800, whiteSpace: 'nowrap',
                      display: 'flex', alignItems: 'center', gap: 4,
                    }}>Open ↗</div>
                  </div>
                </div>
              </button>
            ))}
          </div>

        </>
      );
    }

    if (activeTab === 'agents') {
      return (
        <>
          <Section title="Registered Agent Roster" icon="⚙️" borderColor="#10b981">
            {loadingAgents ? (
              <div style={{ textAlign: 'center', color: '#60a5fa', padding: 20 }}>Loading agents...</div>
            ) : standardSystems.length === 0 ? (
              <div style={{ textAlign: 'center', color: '#94a3b8', padding: 20 }}>No endpoints connected. Download the agent above to get started.</div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid rgba(100,116,139,0.2)' }}>
                      {['Host Name', 'Operating System', 'IP Address', 'Agent Version', 'Status'].map(h => (
                        <th key={h} style={{ padding: '8px 10px', fontSize: 10, color: '#475569', fontWeight: 700, textTransform: 'uppercase', textAlign: 'left' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {standardSystems.map((s, idx) => {
                      const isOnline = Boolean(
                        s.isOnline !== undefined ? s.isOnline :
                        (s.status === 'active' || s.status === 'online' || s.status === 'connected') &&
                        s.isActive !== false &&
                        (!s.lastSeen || (Date.now() - new Date(s.lastSeen).getTime()) < 300000)
                      );
                      const statusLabel = isOnline ? 'ONLINE' : (s.status?.toUpperCase() || 'OFFLINE');
                      return (
                        <tr key={s._id || idx} style={{ background: idx % 2 === 0 ? 'rgba(0,0,0,0.15)' : 'transparent' }}>
                          <td style={{ padding: '10px', fontSize: 12, color: '#e2e8f0', fontWeight: 600 }}>{s.hostname || s.name || 'Unknown Host'}</td>
                          <td style={{ padding: '10px', fontSize: 12, color: '#94a3b8' }}>{s.os || s.platform || 'Linux'}</td>
                          <td style={{ padding: '10px', fontSize: 12, color: '#94a3b8', fontFamily: 'monospace' }}>{s.ipAddress || s.ip || '—'}</td>
                          <td style={{ padding: '10px', fontSize: 12, color: '#94a3b8' }}>v{s.version || s.agentVersion || '1.0.0'}</td>
                          <td style={{ padding: '10px', fontSize: 12 }}>
                            <span style={{
                              display: 'inline-block', padding: '2px 8px', borderRadius: 12, fontSize: 10, fontWeight: 700,
                              background: isOnline ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                              color: isOnline ? '#34d399' : '#f87171',
                              border: `1px solid ${isOnline ? '#10b981' : '#ef4444'}`
                            }}>{statusLabel}</span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
        </>
      );
    }

    if (activeTab === 'profile') {
      return <ProfileEditTab
        user={user}
        company={company}
        subData={subData}
        tfaStatus={tfaStatus}
        pwForm={pwForm} setPwForm={setPwForm}
        pwMsg={pwMsg} pwErr={pwErr} pwBusy={pwBusy}
        changePassword={changePassword}
        handle2FASetup={handle2FASetup}
        handle2FAVerify={handle2FAVerify}
        handle2FADisable={handle2FADisable}
        tfaLoading={tfaLoading} tfaQR={tfaQR} tfaSecret={tfaSecret}
        tfaCode={tfaCode} setTfaCode={setTfaCode}
        tfaErr={tfaErr} tfaMsg={tfaMsg}
        disableCode={disableCode} setDisableCode={setDisableCode}
        cancel2FASetup={() => { setTfaQR(null); setTfaSecret(''); setTfaCode(''); setTfaErr(''); setTfaMsg(''); }}
        isImpersonating={isImpersonating}
        onRefresh={() => setRefreshTrigger(p => p + 1)}
      />;
    }

    if (activeTab === 'company') {
      const sub = subData?.plan; return (
        <Section title="Company &amp; Plan Information" icon="🏢" borderColor="#ff3333">
          {infoRow('COMPANY NAME', company?.name)}
          {infoRow('EMAIL', company?.email)}
          {infoRow('PHONE', company?.phone || '—')}
          {infoRow('SYSTEMS PURCHASED', sub?.systemCount ? `${sub.systemCount} systems` : company?.plan?.systemCount ? `${company.plan.systemCount} systems` : '—')}
          {infoRow('SERVERS PURCHASED', sub?.serverCount !== undefined ? `${sub.serverCount || 0} servers` : '—')}
          {infoRow('PHONES PURCHASED', sub?.phoneCount !== undefined ? `${sub.phoneCount || 0} phones` : company?.plan?.phoneCount !== undefined ? `${company.plan.phoneCount || 0} phones` : '—')}
          {infoRow('STATUS', company?.status?.charAt(0).toUpperCase() + company?.status?.slice(1))}
          {infoRow('PLAN ACTIVE', (sub?.isActive || company?.plan?.isActive) ? '✅ Active' : '⏸️ Inactive')}
          {infoRow('PLAN EXPIRES', fmtDate(sub?.expiresAt || company?.plan?.expiresAt))}
        </Section>
      );
    }

    if (activeTab === 'requests') {
      const fmtD = (d) => d ? new Date(d).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';
      const fmtS = (d) => d ? new Date(d).toLocaleDateString('en-IN', { day: '2-digit', month: 'short' }) : '—';
      const filtered = addSubs.filter(b => addSubsFilter === 'all' ? true : b.status === addSubsFilter);

      return (
        <Section title="Add System Subscription History" icon="⬆️" borderColor="#60a5fa">
          {/* Filter + stats */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
            <div style={{ display: 'flex', gap: 6 }}>
              {['all', 'active', 'expired'].map(f => (
                <button key={f} onClick={() => setAddSubsFilter(f)} style={{
                  padding: '5px 14px', borderRadius: 20, border: 'none', cursor: 'pointer', fontSize: 12, fontWeight: addSubsFilter === f ? 700 : 400,
                  background: addSubsFilter === f ? 'rgba(37,99,235,0.3)' : 'rgba(0,0,0,0.2)',
                  color: addSubsFilter === f ? '#93c5fd' : '#64748b',
                  outline: addSubsFilter === f ? '1px solid #2563eb' : 'none',
                }}>{f.charAt(0).toUpperCase() + f.slice(1)} ({addSubs.filter(b => f === 'all' || b.status === f).length})</button>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 12 }}>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 10, color: '#475569', textTransform: 'uppercase' }}>Total Added</div>
                <div style={{ fontSize: 18, color: '#60a5fa', fontWeight: 800 }}>{addSubs.filter(b => b.status === 'active').reduce((s, b) => s + b.addedSystemCount, 0)} sys · {addSubs.filter(b => b.status === 'active').reduce((s, b) => s + (b.addedPhoneCount || 0), 0)} phone</div>
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 10, color: '#475569', textTransform: 'uppercase' }}>Batches</div>
                <div style={{ fontSize: 18, color: '#34d399', fontWeight: 800 }}>{addSubs.filter(b => b.status === 'active').length} active</div>
              </div>
            </div>
          </div>

          {addSubsLoad ? (
            <div style={{ textAlign: 'center', color: '#60a5fa', padding: 30, fontSize: 13 }}>Loading…</div>
          ) : filtered.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#94a3b8', padding: 30, fontSize: 13 }}>
              {addSubs.length === 0 ? '📭 No add-system subscriptions yet. Use Payments → Add Systems to purchase.' : `No ${addSubsFilter} batches found.`}
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid rgba(100,116,139,0.2)' }}>
                    {['Add Date', 'Systems', 'Servers/Details', 'Start', 'End', 'Billing', 'Amount', 'Payment ID', 'AutoPay', 'Status', 'Action'].map(h => (
                      <th key={h} style={{ padding: '8px 10px', fontSize: 10, color: '#475569', fontWeight: 700, textTransform: 'uppercase', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((b, idx) => {
                    const bEnd = new Date(b.endDate || 0);
                    const bNow = new Date();
                    const bActive = b.status === 'active' && bNow < bEnd;
                    const bNear = bActive && (bEnd - bNow) < 7 * 24 * 60 * 60 * 1000;
                    const rowBg = idx % 2 === 0 ? 'rgba(0,0,0,0.15)' : 'transparent';
                    const tdS = { padding: '10px 10px', fontSize: 12, color: '#94a3b8', whiteSpace: 'nowrap', background: rowBg };
                    return (
                      <tr key={b._id}>
                        <td style={tdS}>{fmtD(b.addedDate)}</td>
                        <td style={{ ...tdS, color: '#60a5fa', fontWeight: 700 }}>+{b.addedSystemCount}</td>
                        <td style={{ ...tdS, color: b.addedServerCount > 0 ? '#a78bfa' : '#334155' }}>
                          {[
                            b.addedServerCount > 0 ? `+${b.addedServerCount} srv` : '',
                            b.addedPhoneCount > 0 ? `+${b.addedPhoneCount} phone` : '',
                          ].filter(Boolean).join(' · ') || '—'}{b.serverDetails ? ` · ${b.serverDetails}` : ''}
                        </td>
                        <td style={tdS}>{fmtS(b.startDate)}</td>
                        <td style={{ ...tdS, color: bActive ? (bNear ? '#fbbf24' : '#94a3b8') : '#f87171' }}>{fmtS(b.endDate)}</td>
                        <td style={{ ...tdS, textTransform: 'capitalize' }}>{b.billingCycle || '—'}</td>
                        <td style={{ ...tdS, color: '#34d399', fontWeight: 700 }}>₹{Number(b.amountPaid || 0).toLocaleString('en-IN')}</td>
                        <td style={{ ...tdS, fontFamily: 'monospace', fontSize: 10 }}>{b.paymentId ? b.paymentId.slice(0, 14) + '…' : '—'}</td>
                        <td style={tdS}>
                          {b.status === 'active' ? (
                            <button onClick={() => b.autoPay ? disableBatchAutoPay(b) : enableBatchAutoPay(b)} disabled={addSubsBusy} style={{
                              padding: '3px 10px', borderRadius: 20, cursor: 'pointer', fontSize: 11, fontWeight: 700, border: 'none',
                              background: b.autoPay ? 'rgba(16,185,129,0.2)' : 'rgba(100,116,139,0.2)',
                              color: b.autoPay ? '#34d399' : '#64748b',
                              outline: `1px solid ${b.autoPay ? '#10b981' : '#475569'}`,
                            }}>{b.autoPay ? '✅ ON' : '⏸ OFF'}</button>
                          ) : '—'}
                        </td>
                        <td style={tdS}>
                          <span style={{
                            display: 'inline-block', padding: '2px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
                            background: bActive ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                            color: bActive ? '#34d399' : '#f87171',
                            border: `1px solid ${bActive ? '#10b981' : '#ef4444'}`,
                          }}>{bActive ? (bNear ? '⚠️ Expiring' : 'Active') : b.status.charAt(0).toUpperCase() + b.status.slice(1)}</span>
                        </td>
                        <td style={tdS}>
                          {b.status !== 'cancelled' && (
                            <button onClick={() => window.location.href = '/payments'} style={{
                              padding: '4px 12px', borderRadius: 6, border: '1px solid #2563eb',
                              background: 'rgba(37,99,235,0.15)', color: '#60a5fa', fontSize: 11, cursor: 'pointer', fontWeight: 600,
                            }}>Renew ↗</button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          <div style={{ marginTop: 16, fontSize: 12, color: '#334155', textAlign: 'center' }}>
            ℹ️ Each batch is billed independently. To renew a specific batch, go to <a href="/payments" style={{ color: '#60a5fa' }}>Payments → Renew Plan → Add-System Batch</a>.
          </div>
        </Section>
      );
    }

    if (activeTab === 'subscription') {
      const plan = subData?.plan;
      const planActive = plan?.isActive && new Date() < new Date(plan?.expiresAt || 0);

      if (subLoading) return <div style={{ textAlign: 'center', color: '#60a5fa', padding: 40 }}>Loading subscription…</div>;

      return (
        <Section title="Subscription Details" icon="📊" borderColor="#ffaa00">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
            {[
              { label: 'Systems', value: `${plan?.systemCount || 0}`, unit: 'systems' },
              { label: 'Servers', value: `${plan?.serverCount || 0}`, unit: 'servers' },
              { label: 'Phones', value: `${plan?.phoneCount || 0}`, unit: 'Android + iPhone' },
            ].map(({ label, value, unit }) => (
              <div key={label} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 10, padding: 16, textAlign: 'center' }}>
                <div style={{ fontSize: 11, color: '#475569', marginBottom: 6, textTransform: 'uppercase' }}>{label}</div>
                <div style={{ fontSize: 32, color: '#60a5fa', fontWeight: 800 }}>{value}</div>
                <div style={{ fontSize: 11, color: '#334155' }}>{unit}</div>
              </div>
            ))}
          </div>
          {infoRow('STATUS', planActive ? (
            <span style={{ color: '#34d399', fontWeight: 700 }}>✅ ACTIVE</span>
          ) : <span style={{ color: '#f87171' }}>⚠️ INACTIVE</span>)}
          {infoRow('BILLING CYCLE', plan?.billingCycle ? plan.billingCycle.charAt(0).toUpperCase() + plan.billingCycle.slice(1) : '—')}
          {infoRow('AMOUNT PAID', plan?.amountPaid ? fmtInr(plan.amountPaid) : '—')}
          {infoRow('PAYMENT STATUS', <span style={{ color: plan?.paymentStatus === 'paid' ? '#34d399' : '#f87171' }}>{plan?.paymentStatus?.toUpperCase() || '—'}</span>)}
          {infoRow('START DATE', fmtDate(plan?.startDate))}
          {infoRow('EXPIRY DATE', fmtDate(plan?.expiresAt))}
          {infoRow('PAYMENT ID', subData?.razorpay?.paymentId ? subData.razorpay.paymentId.slice(0, 20) + '…' : '—')}
          {infoRow('AUTOPAY', plan?.autoPay ? '✅ Enabled' : '❌ Disabled')}
          {infoRow('TOTAL DOWNLOAD LIMIT',
            <span style={{ color: '#60a5fa', fontWeight: 700 }}>
              {(plan?.systemCount || 0) + (plan?.serverCount || 0) + (plan?.phoneCount || 0)} downloads
              <span style={{ fontSize: 11, color: '#475569', fontWeight: 400, marginLeft: 6 }}>
                ({plan?.systemCount || 0} systems + {plan?.serverCount || 0} servers + {plan?.phoneCount || 0} phones)
              </span>
            </span>
          )}
          {pricing && plan?.systemCount > 0 && infoRow('RENEWAL ESTIMATE',
            `${fmtInr((plan.systemCount || 0) * pricing.pricePerSystemMonthly + (plan.phoneCount || 0) * (pricing.pricePerPhoneMonthly || pricing.pricePerSystemMonthly) + (plan.serverCount || 0) * pricing.pricePerServerMonthly)} / month`
          )}
        </Section>
      );
    }

    if (activeTab === 'kyc') {
      return (
        <Section title="Corporate KYC Verification Status" icon="▧" borderColor="#3b82f6">
          <div style={{ display: 'flex', gap: 14, alignItems: 'center', background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
            <span style={{ fontSize: 32 }}>✅</span>
            <div>
              <div style={{ color: '#34d399', fontWeight: 800, fontSize: 15, marginBottom: 4 }}>KYC Verified & Active</div>
              <p style={{ color: '#94a3b8', fontSize: 12, margin: 0 }}>
                Your enterprise account has passed Tier 1 compliance checks. GSTIN, PAN, and corporate identity certificates are verified.
              </p>
            </div>
          </div>
          {infoRow('Verification Date', company?.createdAt ? new Date(company.createdAt).toLocaleDateString('en-IN') : '—')}
          {infoRow('Corporate Status', 'Global Standard Enterprise Tenant')}
          {infoRow('GSTIN Status', 'Verified & Active')}
          {infoRow('PAN Status', 'Verified & Checked')}
        </Section>
      );
    }



    if (activeTab === 'users') {
      const inviteMember = async (e) => {
        e.preventDefault();
        setInviteBusy(true); setInviteSuccess(''); setInviteError('');
        try {
          await api.post('/users/invite', inviteForm);
          setInviteSuccess(`Invitation sent successfully to ${inviteForm.email}`);
          setInviteForm({ email: '', role: 'analyst', departmentId: '' });
          const { data } = await api.get('/users');
          setStandardTeam(data || []);
        } catch (err) {
          setInviteError(err.response?.data?.message || 'Failed to send invite');
        } finally { setInviteBusy(false); }
      };

      const toggleMemberStatus = async (m) => {
        try {
          const { data } = await api.patch(`/users/${m._id}`, { isActive: !m.isActive });
          setStandardTeam(prev => prev.map(u => u._id === data._id ? data : u));
          Swal.fire({ icon: 'success', title: 'Status Updated', text: `Successfully ${data.isActive ? 'enabled' : 'disabled'} member.`, timer: 1500, showConfirmButton: false, background: '#fff' });
        } catch (err) {
          Swal.fire({ icon: 'error', title: 'Error', text: 'Failed to update user status.', background: '#fff' });
        }
      };

      const isCompanyAdmin = user?.role === 'company_admin';
      const filteredTeam = standardTeam.filter(m => {
        if (!m) return false;
        const r = String(m.role || '').toLowerCase();
        return r === 'department_admin' || r === 'soc_manager' || r === 'company_admin';
      });

      return (
        <>
          <Section title="Users &amp; Team Roster" icon="👥" borderColor="#10b98e">
            {loadingTeam ? (
              <div style={{ textAlign: 'center', color: '#60a5fa', padding: 20 }}>Loading roster...</div>
            ) : filteredTeam.length === 0 ? (
              <div style={{ textAlign: 'center', color: '#94a3b8', padding: 20 }}>No Dept Admin or SOC Manager members found.</div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid rgba(100,116,139,0.2)' }}>
                      {['Full Name', 'Email Address', 'Role Badge', 'Status Badge', 'Action'].map(h => (
                        <th key={h} style={{ padding: '8px 10px', fontSize: 10, color: '#475569', fontWeight: 700, textTransform: 'uppercase', textAlign: 'left' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredTeam.map((m, idx) => (
                      <tr key={m._id || idx} style={{ background: idx % 2 === 0 ? 'rgba(0,0,0,0.15)' : 'transparent' }}>
                        <td style={{ padding: '10px', fontSize: 12, color: '#e2e8f0', fontWeight: 600 }}>
                          {m.name} {m._id === user?._id && <span style={{ color: '#60a5fa', fontSize: 10 }}>(You)</span>}
                        </td>
                        <td style={{ padding: '10px', fontSize: 12, color: '#94a3b8' }}>{m.email}</td>
                        <td style={{ padding: '10px', fontSize: 12 }}>
                          <span style={{
                            display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                            background: m.role === 'company_admin' ? '#2e1065' : m.role === 'soc_manager' ? '#164e63' : '#064e3b',
                            color: m.role === 'company_admin' ? '#a78bfa' : m.role === 'soc_manager' ? '#67e8f9' : '#34d399'
                          }}>{m.role === 'company_admin' ? 'Company Admin' : m.role === 'soc_manager' ? 'SOC Manager' : 'Dept Admin'}</span>
                        </td>
                        <td style={{ padding: '10px', fontSize: 12 }}>
                          <span style={{
                            display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                            background: m.isActive ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
                            color: m.isActive ? '#34d399' : '#f87171'
                          }}>{m.isActive ? 'Active' : 'Disabled'}</span>
                        </td>
                        <td style={{ padding: '10px', fontSize: 12 }}>
                          {isCompanyAdmin && m._id !== user?._id && m.role !== 'company_admin' ? (
                            <button onClick={() => toggleMemberStatus(m)} style={{
                              padding: '4px 10px', borderRadius: 6, border: 'none', fontSize: 11, cursor: 'pointer',
                              background: m.isActive ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
                              color: m.isActive ? '#f87171' : '#34d399'
                            }}>
                              {m.isActive ? 'Disable' : 'Enable'}
                            </button>
                          ) : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Section>
        </>
      );
    }

    if (activeTab === 'notifications') {
      const markAllCompanyNotificationsRead = async () => {
        if (socProfile) {
          await api.patch('/soc-dashboard/notifications/read', {}).catch(() => { });
          window.dispatchEvent(new CustomEvent('soc-notifications:unread', { detail: { unread: 0 } }));
        } else {
          await api.patch('/company/notifications/read').catch(() => { });
        }
        setNotifications(items => items.map(item => ({ ...item, read: true, readAt: item.readAt || new Date().toISOString() })));
        setUnreadNotifications(0);
      };

      const handleNotificationItemClick = async (n) => {
        if (!n) return;
        if (!n.read) {
          try {
            if (user?.role === 'partner_admin') {
              await api.patch('/partner/notifications/read', { ids: [n._id] });
            } else if (socProfile) {
              await api.patch('/soc-dashboard/notifications/read', { notificationId: n._id });
            } else {
              await api.patch('/company/notifications/read', { notificationId: n._id }).catch(() => { });
            }
          } catch { }
          setNotifications(prev => prev.map(item => item._id === n._id ? { ...item, read: true } : item));
          setUnreadNotifications(count => Math.max(0, count - 1));
        }

        const src = String(n.source || '').toLowerCase();
        const type = String(n.type || '').toLowerCase();
        const title = String(n.title || '').toLowerCase();
        const msg = String(n.message || '').toLowerCase();

        let target = n.targetUrl || n.url || n.link || n.meta?.targetUrl || n.meta?.url || n.meta?.link || n.meta?.href;

        if (user?.role === 'company_admin') {
          if (!target || target === '/company-admin/settings') {
            if (title.includes('soc operational') || (type.includes('soc_status') && !title.includes('alert'))) {
              target = '/company-admin/soc-manager';
            } else if (type.includes('alert') || type.includes('ticket') || type.includes('incident') || title.includes('alert') || title.includes('mitigated')) {
              target = '/company-admin/alerts';
            } else if (type.includes('system') || type.includes('defense') || type.includes('asset') || title.includes('system') || title.includes('endpoint') || title.includes('defense engine')) {
              target = '/company-admin/systems';
            } else if (type.includes('user') || title.includes('user') || title.includes('role') || title.includes('access audit')) {
              target = '/company-admin/users';
            } else if (type.includes('report') || title.includes('report') || title.includes('compliance')) {
              target = '/company-admin/reports';
            } else if (type.includes('department') || title.includes('department')) {
              target = '/company-admin/departments';
            } else if (!target) {
              target = '/company-admin/settings';
            }
          }
        } else if (!target) {
          if (type.includes('resource') || type.includes('request') || type.includes('license') || title.includes('resource') || title.includes('request') || msg.includes('resource') || msg.includes('request')) {
            target = 'requests';
          } else if (type.includes('subscription') || type.includes('payment') || type.includes('quote') || type.includes('plan') || title.includes('plan') || title.includes('subscri') || title.includes('quote') || msg.includes('payment')) {
            target = 'subscription';
          } else if (type.includes('settings') || type.includes('profile') || type.includes('approved') || type.includes('rejected') || title.includes('profile') || title.includes('settings') || title.includes('detail') || msg.includes('details') || msg.includes('updated by super admin')) {
            target = 'profile';
          } else if (type.includes('company') || title.includes('company') || msg.includes('company')) {
            target = 'company';
          } else if (type.includes('user') || type.includes('manager') || title.includes('user') || msg.includes('user')) {
            target = 'users';
          } else if (type.includes('security') || title.includes('security') || title.includes('password') || title.includes('2fa')) {
            target = 'security';
          } else if (type.includes('alert') || type.includes('ticket') || type.includes('incident') || title.includes('alert')) {
            target = '/alerts';
          } else {
            target = 'dashboard';
          }
        }

        if (tabs.some(tab => tab.id === target)) {
          setActiveTab(target);
          const params = new URLSearchParams(location.search);
          params.set('section', target);
          navigate({ pathname: location.pathname, search: `?${params.toString()}` });
          return;
        }
        navigate(target);
      };

      const rawList = Array.isArray(notifications) ? notifications : (Array.isArray(notifications?.items) ? notifications.items : []);
      const filteredNotifications = rawList.filter(n => {
        if (!n) return false;
        const src = String(n.source || '').toLowerCase();
        const type = String(n.type || '').toLowerCase();
        if (notifFilter === 'unread') return !n.read;
        if (notifFilter === 'soc_manager') return src === 'soc_manager' || type.includes('soc');
        if (notifFilter === 'superadmin') return src === 'superadmin' || type.includes('super');
        if (notifFilter === 'partner') return src === 'partner' || type.includes('partner');
        return true;
      });

      return (
        <div>
          <Section title="Administrative Notification Feed" icon="♢" borderColor="#8b5cf6">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, margin: '-6px 0 16px', flexWrap: 'wrap' }}>
              <span style={{ color: '#94a3b8', fontSize: 12 }}>{unreadNotifications} unread administrative updates</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <select
                  value={notifFilter}
                  onChange={e => setNotifFilter(e.target.value)}
                  style={{
                    padding: '6px 12px',
                    borderRadius: 7,
                    border: '1px solid #3b82f6',
                    background: '#0f172a',
                    color: '#93c5fd',
                    fontSize: 11,
                    fontWeight: 800,
                    cursor: 'pointer',
                    outline: 'none'
                  }}
                >
                  <option value="all">Filter: All Notifications</option>
                  <option value="unread">Filter: Unread Only</option>
                  <option value="soc_manager">Filter: SOC Manager</option>
                  <option value="superadmin">Filter: Super Admin</option>
                  <option value="partner">Filter: Partner Admin</option>
                </select>
                <button type="button" onClick={markAllCompanyNotificationsRead} style={{ padding: '7px 12px', borderRadius: 7, border: '1px solid #3b82f6', background: 'rgba(59,130,246,.14)', color: '#93c5fd', fontSize: 11, fontWeight: 800, cursor: 'pointer' }}>
                  Mark All Read
                </button>
              </div>
            </div>
            {filteredNotifications.length === 0 ? (
              <p style={{ color: '#94a3b8', fontSize: 13, padding: '16px 0' }}>No notifications match the selected filter.</p>
            ) : (
              <div style={{
                display: 'flex', flexDirection: 'column', gap: 10,
                maxHeight: 450, overflowY: 'auto', paddingRight: 8,
                scrollbarWidth: 'thin', scrollbarColor: '#3b82f6 #0f172a'
              }}>
                {filteredNotifications.map(n => {
                  const src = String(n.source || '').toLowerCase();
                  let badgeLabel = 'NOTIFICATION';
                  let badgeBg = 'rgba(59,130,246,0.2)';
                  let badgeColor = '#60a5fa';

                  if (src === 'superadmin' || n.type?.includes('super')) {
                    badgeLabel = 'SUPER ADMIN';
                    badgeBg = 'rgba(139,92,246,0.2)';
                    badgeColor = '#c084fc';
                  } else if (src === 'soc_manager' || n.type?.includes('soc')) {
                    badgeLabel = 'SOC MANAGER';
                    badgeBg = 'rgba(16,185,129,0.2)';
                    badgeColor = '#34d399';
                  } else if (src === 'partner' || n.type?.includes('partner')) {
                    badgeLabel = 'PARTNER ADMIN';
                    badgeBg = 'rgba(59,130,246,0.2)';
                    badgeColor = '#60a5fa';
                  } else {
                    badgeLabel = (n.type || 'SYSTEM ALERT').toUpperCase();
                  }

                  const isUnread = !n.read;
                  return (
                    <div
                      key={n._id || n.createdAt}
                      onClick={() => handleNotificationItemClick(n)}
                      style={{
                        padding: 14, borderRadius: 10,
                        background: isUnread ? 'rgba(30, 58, 95, 0.45)' : '#0f172a',
                        border: `1px solid ${isUnread ? 'rgba(96, 165, 250, 0.5)' : '#1e293b'}`,
                        cursor: 'pointer', transition: 'all .2s ease',
                        boxShadow: isUnread ? '0 4px 14px rgba(37,99,235,0.2)' : 'none',
                        display: 'flex', justifyContent: 'space-between', alignItems: 'center'
                      }}
                      onMouseEnter={e => {
                        e.currentTarget.style.background = 'rgba(37, 99, 235, 0.18)';
                        e.currentTarget.style.borderColor = '#3b82f6';
                      }}
                      onMouseLeave={e => {
                        e.currentTarget.style.background = isUnread ? 'rgba(30, 58, 95, 0.45)' : '#0f172a';
                        e.currentTarget.style.borderColor = isUnread ? 'rgba(96, 165, 250, 0.5)' : '#1e293b';
                      }}
                    >
                      <div style={{ minWidth: 0, flex: 1, paddingRight: 14 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                          <span style={{
                            fontSize: 10, padding: '2px 8px', borderRadius: 4,
                            background: badgeBg, color: badgeColor, fontWeight: 800
                          }}>
                            {badgeLabel}
                          </span>
                          {isUnread && (
                            <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: '#2563eb', color: '#fff', fontWeight: 800 }}>
                              NEW
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: 13, fontWeight: 'bold', color: '#f1f5f9', marginBottom: 4 }}>
                          {n.title}
                        </div>
                        <div style={{ fontSize: 12, color: '#cbd5e1', lineHeight: 1.4, marginBottom: 6 }}>
                          {n.message}
                        </div>
                        <small style={{ color: '#64748b', fontSize: 11 }}>
                          {n.createdAt ? new Date(n.createdAt).toLocaleString('en-IN') : ''}
                        </small>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleNotificationItemClick(n);
                          }}
                          style={{
                            padding: '7px 14px',
                            borderRadius: '6px',
                            border: '1px solid #3b82f6',
                            background: 'rgba(59, 130, 246, 0.2)',
                            color: '#60a5fa',
                            fontSize: '12px',
                            fontWeight: 800,
                            cursor: 'pointer',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '4px',
                            transition: 'all .15s ease'
                          }}
                          onMouseEnter={e => {
                            e.currentTarget.style.background = '#2563eb';
                            e.currentTarget.style.color = '#ffffff';
                          }}
                          onMouseLeave={e => {
                            e.currentTarget.style.background = 'rgba(59, 130, 246, 0.2)';
                            e.currentTarget.style.color = '#60a5fa';
                          }}
                        >
                          View →
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Section>
        </div>
      );
    }

    if (activeTab === 'autopay') return (
      <Section title="AutoPay Management" icon="🔄" borderColor="#00d9ff">
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px', background: 'rgba(0,0,0,0.2)', borderRadius: 10, marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 15, color: '#e2e8f0', fontWeight: 700, marginBottom: 4 }}>AutoPay Status</div>
              <div style={{ fontSize: 12, color: subData?.plan?.autoPay ? '#34d399' : '#94a3b8' }}>
                {subData?.plan?.autoPay ? '✅ Enabled — subscription auto-renews before expiry' : '❌ Disabled — you must manually renew'}
              </div>
            </div>
            <button onClick={toggleAutoPay} disabled={autoPayBusy} style={{
              padding: '10px 20px', borderRadius: 8, cursor: autoPayBusy ? 'not-allowed' : 'pointer', fontWeight: 700, fontSize: 13,
              background: subData?.plan?.autoPay
                ? 'linear-gradient(135deg, rgba(239,68,68,0.2), rgba(239,68,68,0.1))'
                : 'linear-gradient(135deg, rgba(16,185,129,0.2), rgba(16,185,129,0.1))',
              color: subData?.plan?.autoPay ? '#f87171' : '#34d399',
              border: 'none',
              outline: `1px solid ${subData?.plan?.autoPay ? '#ef4444' : '#10b981'}`,
              transition: 'all 0.2s',
            }}>
              {autoPayBusy ? 'Updating…' : subData?.plan?.autoPay ? '⏸ Disable AutoPay' : '✅ Enable AutoPay'}
            </button>
          </div>
          {subData?.plan?.autoPay && (
            <div style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)', borderRadius: 8, padding: 14, fontSize: 13, color: '#6ee7b7' }}>
              <strong>AutoPay is active.</strong> Your subscription will automatically renew using the latest pricing set by your Super Admin at the time of renewal.
            </div>
          )}
        </div>
      </Section>
    );

    if (activeTab === 'security') return (
      <>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 24 }}>
          <Section title="Change Password" icon="🔑" borderColor="#ff00ff">
            {pwMsg && <div style={{ background: 'rgba(16,185,129,0.15)', color: '#34d399', padding: '10px 14px', borderRadius: 8, marginBottom: 16, fontSize: 13, border: '1px solid rgba(16,185,129,0.3)' }}>✅ {pwMsg}</div>}
            {pwErr && <div style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', padding: '10px 14px', borderRadius: 8, marginBottom: 16, fontSize: 13, border: '1px solid rgba(239,68,68,0.3)' }}>❌ {pwErr}</div>}
            <form onSubmit={changePassword}>
              {[['currentPassword', 'Current password'], ['newPassword', 'New password'], ['confirm', 'Confirm new password']].map(([k, label]) => (
                <div key={k} style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', color: '#e2e8f0', fontSize: 12, marginBottom: 6, fontWeight: 600 }}>{label.toUpperCase()}</label>
                  <input type="password" required value={pwForm[k]}
                    onChange={e => setPwForm(f => ({ ...f, [k]: e.target.value }))}
                    placeholder={label} style={inpStyle}
                  />
                </div>
              ))}
              <button type="submit" disabled={pwBusy} style={{
                marginTop: 12, width: '100%', padding: 10, borderRadius: 8, border: 'none',
                background: pwBusy ? 'rgba(100,116,139,0.2)' : 'linear-gradient(135deg, #ff00ff, #bb00ff)',
                color: pwBusy ? '#64748b' : '#fff', fontSize: 13, cursor: pwBusy ? 'not-allowed' : 'pointer', fontWeight: 600,
              }}>
                🔑 {pwBusy ? 'Updating…' : 'Change Password'}
              </button>
            </form>
          </Section>

          <Section title="Security Status" icon="🛡️" borderColor="#00d98e">
            {infoRow('Email Verified', '✅ Verified')}
            {infoRow('OTP Login', '✅ Enabled')}
            {infoRow('2FA Auth', tfaStatus?.enabled ? '🔐 Enabled' : '⚠️ Not enabled')}
            {infoRow('Account Active', '✅ Active')}
          </Section>
        </div>

        {/* 2FA Section */}
        <Section title="Two-Factor Authentication (Google Authenticator)" icon="🔐" borderColor="#00d98e">
          {tfaMsg && <div style={{ background: 'rgba(16,185,129,0.15)', color: '#34d399', padding: '10px 14px', borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{tfaMsg}</div>}
          {tfaErr && <div style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5', padding: '10px 14px', borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{tfaErr}</div>}

          {!tfaStatus?.enabled && !tfaQR && (
            <>
              <div style={{ background: 'rgba(239,68,68,0.1)', padding: 16, borderRadius: 8, marginBottom: 20, border: '1px solid rgba(239,68,68,0.3)' }}>
                <h4 style={{ color: '#e2e8f0', margin: '0 0 6px 0', fontWeight: 600 }}>⚠️ 2FA Not Enabled</h4>
                <p style={{ color: '#cbd5e1', fontSize: 13, margin: 0 }}>
                  Add Google Authenticator for an extra layer of security. Requires a 6-digit code from your phone on every login.
                </p>
              </div>
              <button onClick={handle2FASetup} disabled={tfaLoading} style={{
                width: '100%', padding: 12, borderRadius: 8, border: 'none',
                background: 'linear-gradient(135deg, #00d98e, #00aa66)',
                color: '#000', fontSize: 14, fontWeight: 700, cursor: tfaLoading ? 'not-allowed' : 'pointer',
              }}>
                📱 {tfaLoading ? 'Setting up…' : 'Set Up Google Authenticator'}
              </button>
            </>
          )}

          {/* Show QR code for setup */}
          {!tfaStatus?.enabled && tfaQR && (
            <div>
              <div style={{ textAlign: 'center', marginBottom: 20 }}>
                <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 12 }}>
                  1. Open <strong style={{ color: '#60a5fa' }}>Google Authenticator</strong> on your phone<br />
                  2. Tap <strong>+</strong> → <strong>Scan QR code</strong><br />
                  3. Enter the 6-digit code below to confirm
                </p>
                <img src={tfaQR} alt="QR Code" style={{ width: 200, height: 200, borderRadius: 8, border: '2px solid #10b981' }} />
                <div style={{ marginTop: 12, fontSize: 11, color: '#475569' }}>
                  Manual key: <code style={{ color: '#60a5fa', wordBreak: 'break-all', background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 4 }}>{tfaSecret}</code>
                </div>
              </div>
              <div style={{ marginBottom: 14 }}>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 6 }}>Enter 6-digit code from Authenticator</label>
                <input type="text" value={tfaCode}
                  onChange={e => setTfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  maxLength="6" placeholder="000000"
                  style={{ ...inpStyle, textAlign: 'center', fontSize: 24, letterSpacing: '8px' }}
                />
              </div>
              <div style={{ display: 'flex', gap: 10 }}>
                <button onClick={() => { setTfaQR(null); setTfaSecret(''); setTfaCode(''); }} style={{
                  flex: 1, padding: 10, borderRadius: 8, border: '1px solid #1e3a5f',
                  background: 'none', color: '#94a3b8', fontSize: 13, cursor: 'pointer',
                }}>Cancel</button>
                <button onClick={handle2FAVerify} disabled={tfaLoading || tfaCode.length !== 6} style={{
                  flex: 2, padding: 10, borderRadius: 8, border: 'none',
                  background: (tfaLoading || tfaCode.length !== 6) ? '#1e3a5f' : 'linear-gradient(135deg, #00d98e, #00aa66)',
                  color: '#000', fontSize: 13, fontWeight: 700, cursor: (tfaLoading || tfaCode.length !== 6) ? 'not-allowed' : 'pointer',
                }}>
                  {tfaLoading ? 'Verifying…' : '✅ Enable 2FA'}
                </button>
              </div>
            </div>
          )}

          {/* 2FA enabled — show disable option */}
          {tfaStatus?.enabled && (
            <div>
              <div style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                <div style={{ color: '#34d399', fontWeight: 700, fontSize: 15, marginBottom: 4 }}>🔐 2FA is Active</div>
                <p style={{ color: '#94a3b8', fontSize: 13, margin: 0 }}>
                  Your account is protected with Google Authenticator. You'll need your phone to log in.
                </p>
              </div>
              <div style={{ marginBottom: 12 }}>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 6 }}>
                  Enter your current 6-digit code to disable 2FA
                </label>
                <input type="text" value={disableCode}
                  onChange={e => setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  maxLength="6" placeholder="000000"
                  style={{ ...inpStyle, textAlign: 'center', fontSize: 20, letterSpacing: '6px', maxWidth: 200 }}
                />
              </div>
              <button onClick={handle2FADisable} disabled={tfaLoading || disableCode.length !== 6} style={{
                padding: '10px 24px', borderRadius: 8, border: '1px solid rgba(239,68,68,0.4)',
                background: 'rgba(239,68,68,0.1)', color: '#f87171', fontSize: 13, fontWeight: 600,
                cursor: (tfaLoading || disableCode.length !== 6) ? 'not-allowed' : 'pointer',
              }}>
                {tfaLoading ? 'Disabling…' : '🔓 Disable 2FA'}
              </button>
            </div>
          )}
        </Section>
      </>
    );

    if (activeTab === 'activity') {
      const getActionDescription = (log) => {
        switch (log.action) {
          case 'login_success':
            return `Successfully logged in from IP ${log.ipAddress || 'unknown'} (${log.os || 'unknown'} / ${log.browser || 'unknown'})`;
          case 'login_failed':
            return `Failed login attempt. Reason: ${log.failReason || 'unknown'}`;
          case 'logout':
            return `Logged out from portal session`;
          case 'company_updated':
            return `Company details updated by administrator`;
          case 'company_plan_updated':
            return `Company subscription plan modified by Super Admin`;
          case 'company_payment_updated':
            return `Company billing payment status updated by Partner Admin`;
          case 'company_autopay_updated':
            return `Company AutoPay preference updated by Partner Admin`;
          case 'company_status_updated':
            return `Company administrative status modified by Super Admin`;
          case 'admin_updated':
            return `Administrator account profile details updated`;
          case 'password_changed':
            return `Account security password changed successfully`;
          case 'password_reset':
            return `Account password reset initiated`;
          case 'superadmin_impersonation_started':
            return `Super Admin started an impersonated support session`;
          case 'company_created':
            return `Company registered successfully in the security portal`;
          default:
            return log.action?.replace(/_/g, ' ') || 'Portal administrative activity';
        }
      };

      const adminLogs = standardAuditLogs.filter(log => {
        if (!log) return false;
        if (user?.role === 'department_admin') {
          const currentUserId = String(user?._id || user?.id || '');
          const logUserId = String(log.userId?._id || log.userId || '');
          const sameUser = currentUserId && logUserId === currentUserId;
          const sameEmail = user?.email && String(log.email || '').toLowerCase() === user.email.toLowerCase();
          return Boolean(sameUser || sameEmail);
        }
        if (user?.role === 'company_admin' && user?.email) {
          return !log.email || log.email.toLowerCase() === user.email.toLowerCase() || String(log.role || '').toLowerCase().includes('admin');
        }
        return true;
      });

      const itemsPerPage = 12;
      const totalPages = Math.ceil(adminLogs.length / itemsPerPage) || 1;
      const paginatedLogs = adminLogs.slice((activityPage - 1) * itemsPerPage, activityPage * itemsPerPage);

      return (
        <Section title="Portal Security Activity Log" icon="◷" borderColor="#3b82f6">
          <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
            Audit trail of security logins and administrative actions performed by {accountRoleLabel(user?.role)}:
          </p>
          {loadingAudit ? (
            <div style={{ textAlign: 'center', color: '#60a5fa', padding: 20 }}>Loading activity logs...</div>
          ) : adminLogs.length === 0 ? (
            <div style={{ textAlign: 'center', color: '#94a3b8', padding: 20 }}>No activity events recorded.</div>
          ) : (
            <div>
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid rgba(100,116,139,0.2)' }}>
                      {['Timestamp', 'Action Category', 'User Email', 'Details'].map(h => (
                        <th key={h} style={{ padding: '8px 10px', fontSize: 10, color: '#475569', fontWeight: 700, textTransform: 'uppercase', textAlign: 'left' }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedLogs.map((log, idx) => (
                      <tr key={log._id || log.id || idx} style={{ background: idx % 2 === 0 ? 'rgba(0,0,0,0.15)' : 'transparent' }}>
                        <td style={{ padding: '10px', fontSize: 12, color: '#94a3b8', whiteSpace: 'nowrap' }}>
                          {log.createdAt ? new Date(log.createdAt).toLocaleString() : log.ts ? new Date(log.ts).toLocaleString() : '—'}
                        </td>
                        <td style={{ padding: '10px', fontSize: 12, color: '#60a5fa', fontWeight: 600 }}>
                          {log.action?.replace(/_/g, ' ').toUpperCase() || 'ACTIVITY'}
                        </td>
                        <td style={{ padding: '10px', fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace' }}>
                          {log.email || '—'}
                        </td>
                        <td style={{ padding: '10px', fontSize: 12, color: '#cbd5e1' }}>
                          {getActionDescription(log)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination Controls */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 16,
                marginTop: 16,
                paddingTop: 16,
                borderTop: '1px solid rgba(100, 116, 139, 0.15)'
              }}>
                <button
                  onClick={() => setActivityPage(prev => Math.max(prev - 1, 1))}
                  disabled={activityPage === 1}
                  style={{
                    background: activityPage === 1 ? 'rgba(30, 41, 59, 0.5)' : 'rgba(59, 130, 246, 0.2)',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    borderRadius: 4,
                    color: activityPage === 1 ? '#64748b' : '#3b82f6',
                    cursor: activityPage === 1 ? 'not-allowed' : 'pointer',
                    fontSize: 12,
                    fontWeight: 'bold',
                    padding: '6px 12px',
                    transition: 'all 0.2s'
                  }}
                >
                  ◀ Previous
                </button>

                <span style={{ fontSize: 12, color: '#94a3b8' }}>
                  Page <strong style={{ color: '#fff' }}>{activityPage}</strong> of <strong style={{ color: '#fff' }}>{totalPages}</strong>
                </span>

                <button
                  onClick={() => setActivityPage(prev => Math.min(prev + 1, totalPages))}
                  disabled={activityPage === totalPages}
                  style={{
                    background: activityPage === totalPages ? 'rgba(30, 41, 59, 0.5)' : 'rgba(59, 130, 246, 0.2)',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    borderRadius: 4,
                    color: activityPage === totalPages ? '#64748b' : '#3b82f6',
                    cursor: activityPage === totalPages ? 'not-allowed' : 'pointer',
                    fontSize: 12,
                    fontWeight: 'bold',
                    padding: '6px 12px',
                    transition: 'all 0.2s'
                  }}
                >
                  Next ▶
                </button>
              </div>
            </div>
          )}
        </Section>
      );
    }

    if (activeTab === 'support') {
      const submitTicket = async (e) => {
        e.preventDefault();
        setSupportBusy(true); setSupportSuccess('');
        try {
          const res = await api.post('/company/support-tickets', {
            subject: supportForm.subject,
            message: supportForm.message,
            severity: supportForm.severity
          });
          const newTicket = res.data;
          setSupportTickets(prev => [newTicket, ...prev]);
          setSelectedTicket(newTicket);
          setSupportForm({ subject: '', message: '', severity: 'low' });
          setSupportSuccess('Ticket ' + newTicket.ticketId + ' created successfully.');
        } catch (err) {
          alert(err.response?.data?.message || 'Failed to submit ticket');
        } finally {
          setSupportBusy(false);
        }
      };

      const sendReply = async (e) => {
        e.preventDefault();
        if (!replyMessage.trim()) return;
        setReplyBusy(true);
        try {
          const res = await api.post(`/company/support-tickets/${selectedTicket._id}/messages`, {
            message: replyMessage
          });
          setSelectedTicket(res.data);
          setSupportTickets(prev => prev.map(t => t._id === res.data._id ? res.data : t));
          setReplyMessage('');
        } catch (err) {
          alert(err.response?.data?.message || 'Failed to send message');
        } finally {
          setReplyBusy(false);
        }
      };

      return (
        <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 20, alignItems: 'start' }}>
          <Section title="Tickets" icon="🎫" borderColor="#3b82f6">
            <button
              onClick={() => { setSelectedTicket(null); setSupportSuccess(''); }}
              style={{
                width: '100%', padding: '10px', borderRadius: 8, border: '1px dashed #3b82f6',
                background: selectedTicket ? 'transparent' : 'rgba(59, 130, 246, 0.1)',
                color: '#3b82f6', fontSize: 13, fontWeight: 700, cursor: 'pointer', marginBottom: 12
              }}
            >
              + Create New Ticket
            </button>
            {loadingSupport ? (
              <p style={{ color: '#94a3b8', fontSize: 13 }}>Loading tickets...</p>
            ) : supportTickets.length === 0 ? (
              <p style={{ color: '#94a3b8', fontSize: 13 }}>No tickets found.</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 400, overflowY: 'auto' }}>
                {supportTickets.map(t => {
                  const isSelected = selectedTicket?._id === t._id;
                  const severityColors = {
                    low: { bg: 'rgba(148,163,184,0.1)', text: '#94a3b8' },
                    medium: { bg: 'rgba(249,115,22,0.1)', text: '#f97316' },
                    high: { bg: 'rgba(239,68,68,0.1)', text: '#ef4444' },
                    payment: { bg: 'rgba(16,185,129,0.1)', text: '#10b981' }
                  };
                  const statusColors = {
                    'Open': '#eab308',
                    'In Progress': '#3b82f6',
                    'Resolved': '#10b981',
                    'Closed': '#64748b'
                  };
                  const sev = severityColors[t.severity] || severityColors.low;
                  return (
                    <div
                      key={t._id}
                      onClick={() => { setSelectedTicket(t); setSupportSuccess(''); }}
                      style={{
                        padding: 12, borderRadius: 8, cursor: 'pointer',
                        background: isSelected ? 'rgba(59,130,246,0.15)' : '#0f172a',
                        border: isSelected ? '1px solid #3b82f6' : '1px solid #1e293b',
                        transition: 'all 0.2s'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                        <span style={{ fontSize: 11, fontWeight: 'bold', color: '#94a3b8' }}>{t.ticketId}</span>
                        <span style={{ fontSize: 11, color: statusColors[t.status] || '#fff', fontWeight: 600 }}>{t.status}</span>
                      </div>
                      <div style={{ fontSize: 13, fontWeight: 600, color: '#f1f5f9', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginBottom: 8 }}>
                        {t.subject}
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: sev.bg, color: sev.text, textTransform: 'capitalize' }}>
                          {t.severity}
                        </span>
                        <span style={{ fontSize: 10, color: '#64748b' }}>
                          {new Date(t.createdAt).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </Section>

          {selectedTicket ? (
            <Section
              title={`Ticket: ${selectedTicket.ticketId}`}
              icon="💬"
              borderColor="#10b981"
              headerRight={
                <span style={{
                  fontSize: 12, padding: '3px 8px', borderRadius: 6,
                  background: selectedTicket.status === 'Resolved' ? 'rgba(16,185,129,0.15)' : selectedTicket.status === 'Closed' ? 'rgba(100,116,139,0.15)' : 'rgba(59,130,246,0.15)',
                  color: selectedTicket.status === 'Resolved' ? '#10b981' : selectedTicket.status === 'Closed' ? '#94a3b8' : '#3b82f6',
                  fontWeight: 600
                }}>
                  {selectedTicket.status}
                </span>
              }
            >
              <div style={{ borderBottom: '1px solid #1e293b', paddingBottom: 12, marginBottom: 12 }}>
                <div style={{ fontSize: 14, fontWeight: 'bold', color: '#fff', marginBottom: 6 }}>{selectedTicket.subject}</div>
                <p style={{ margin: 0, fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>
                  {selectedTicket.description}
                </p>
              </div>

              {/* Chat Messages */}
              <div style={{
                display: 'flex', flexDirection: 'column', gap: 12,
                maxHeight: 300, overflowY: 'auto', paddingRight: 8, marginBottom: 16
              }}>
                {selectedTicket.messages?.map((msg, index) => {
                  const isMe = msg.senderId === user?._id || msg.senderId === user?.id;
                  return (
                    <div
                      key={index}
                      style={{
                        alignSelf: isMe ? 'flex-end' : 'flex-start',
                        maxWidth: '80%',
                        background: isMe ? 'linear-gradient(135deg, #1d4ed8, #3b82f6)' : '#0f172a',
                        border: isMe ? 'none' : '1px solid #1e293b',
                        padding: '10px 14px', borderRadius: 12,
                        color: '#f8fafc', fontSize: 13, lineHeight: 1.4
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 4, fontSize: 10, color: isMe ? '#bfdbfe' : '#94a3b8', fontWeight: 600 }}>
                        <span>{msg.senderName} ({msg.senderRole === 'superadmin' ? 'Super Admin' : msg.senderRole === 'partner_admin' ? 'Partner Admin' : 'Admin'})</span>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                          {new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          {isMe && <span aria-label={msg.readAt ? 'Read' : 'Sent'} title={msg.readAt ? `Read ${new Date(msg.readAt).toLocaleString()}` : 'Sent, not read yet'} style={{ display: 'inline-flex', color: msg.readAt ? '#38bdf8' : '#bfdbfe' }}>
                            <svg width={msg.readAt ? 20 : 14} height="14" viewBox={msg.readAt ? '0 0 24 16' : '0 0 16 16'} fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M2 8l4 4L14 3" />{msg.readAt && <path d="M10 8l4 4L22 3" />}</svg>
                          </span>}
                        </span>
                      </div>
                      <div style={{ whiteSpace: 'pre-wrap' }}>{msg.message}</div>
                    </div>
                  );
                })}
              </div>

              {/* Reply Box */}
              {selectedTicket.status === 'Closed' ? (
                <div style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', padding: '10px 14px', borderRadius: 8, fontSize: 13, textAlign: 'center' }}>
                  This ticket has been closed. Please create a new ticket if the issue persists.
                </div>
              ) : (
                <form onSubmit={sendReply} style={{ display: 'flex', gap: 10 }}>
                  <textarea
                    required
                    placeholder="Type your response..."
                    value={replyMessage}
                    onChange={e => setReplyMessage(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        sendReply(e);
                      }
                    }}
                    rows={1}
                    style={{ ...inpStyle, flex: 1, marginBottom: 0, resize: 'vertical', fontFamily: 'inherit', lineHeight: '1.4', minHeight: '38px' }}
                  />
                  <button
                    type="submit"
                    disabled={replyBusy}
                    style={{
                      padding: '0 20px', borderRadius: 8, border: 'none',
                      background: 'linear-gradient(135deg, #10b981, #059669)',
                      color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer'
                    }}
                  >
                    {replyBusy ? 'Sending...' : 'Send'}
                  </button>
                </form>
              )}
            </Section>
          ) : (
            <Section title="Submit Technical Support Request" icon="✉️" borderColor="#3b82f6">
              {supportSuccess && <div style={{ background: 'rgba(16,185,129,0.15)', color: '#34d399', padding: '10px 14px', borderRadius: 8, marginBottom: 16, fontSize: 13 }}>{supportSuccess}</div>}
              <form onSubmit={submitTicket}>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', color: '#e2e8f0', fontSize: 12, marginBottom: 6, fontWeight: 600 }}>SUBJECT</label>
                  <input type="text" required placeholder="Brief description of the issue" value={supportForm.subject}
                    onChange={e => setSupportForm(prev => ({ ...prev, subject: e.target.value }))}
                    style={inpStyle} />
                </div>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', color: '#e2e8f0', fontSize: 12, marginBottom: 6, fontWeight: 600 }}>TICKET SEVERITY</label>
                  <select value={supportForm.severity}
                    onChange={e => setSupportForm(prev => ({ ...prev, severity: e.target.value }))}
                    style={{ ...inpStyle, background: '#0f172a' }}>
                    <option value="low">Low - General query</option>
                    <option value="medium">Medium - Agent connectivity glitch</option>
                    <option value="high">High - False positive alert mitigation</option>
                    <option value="payment">Payment related issues</option>
                  </select>
                </div>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', color: '#e2e8f0', fontSize: 12, marginBottom: 6, fontWeight: 600 }}>MESSAGE BODY</label>
                  <textarea required placeholder="Provide step-by-step details of the problem..." rows="5" value={supportForm.message}
                    onChange={e => setSupportForm(prev => ({ ...prev, message: e.target.value }))}
                    style={{ ...inpStyle, resize: 'vertical' }} />
                </div>
                <button type="submit" disabled={supportBusy} style={{
                  width: '100%', padding: 12, borderRadius: 8, border: 'none',
                  background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                  color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer'
                }}>
                  {supportBusy ? 'Submitting ticket...' : 'Submit Support Ticket'}
                </button>
              </form>
            </Section>
          )}
        </div>
      );
    }
  };

  return (
    <div style={partnerProfilePage}>
      <aside style={partnerProfileSidebar}>
        {user?.role === 'department_admin' && (
          <div style={{ padding: '8px 12px 10px', marginBottom: 2, borderBottom: '1px solid #1e3a5f' }}>
            <div style={{ color: '#7dd3fc', fontSize: 10, fontWeight: 900, letterSpacing: '.08em', textTransform: 'uppercase' }}>Department Admin</div>
            <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 850, marginTop: 4 }}>Account Settings</div>
          </div>
        )}
        {tabs.map(tab => (
          <button key={tab.id} type="button" onClick={() => {
            setActiveTab(tab.id);
            navigate(`${location.pathname}?section=${tab.id}`, { replace: true });
          }} style={{ ...profileNav, display: 'flex', alignItems: 'center', gap: 8, ...(activeTab === tab.id ? profileNavActive : {}) }}>
            <span style={{ fontSize: 16 }}>{tab.icon}</span>
            <span style={{ flex: 1, textAlign: 'left' }}>{tab.label}</span>
            {tab.id === 'notifications' && unreadNotifications > 0 && (
              <span style={{
                background: '#ef4444', color: '#fff',
                fontSize: 10, padding: '2px 6px', borderRadius: 10, fontWeight: 700
              }}>
                {unreadNotifications}
              </span>
            )}
          </button>
        ))}
      </aside>

      <main style={profileContentMain}>
        {renderContent()}
      </main>
    </div>
  );
}

function PartnerProfileMode({ user, partner, stats, dashboardRefreshKey = 0, pwForm, setPwForm, pwMsg, pwErr, pwBusy, changePassword, isImpersonating, onPartnerSaved, tfaStatus, tfaLoading, tfaQR, tfaSecret, tfaCode, setTfaCode, tfaErr, tfaMsg, disableCode, setDisableCode, handle2FASetup, handle2FAVerify, handle2FADisable, cancel2FASetup }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [activeSection, setActiveSection] = useState(() => sectionFromSearch(location.search));
  const [editing, setEditing] = useState('');
  const [localMessage, setLocalMessage] = useState('');
  const [validationErrors, setValidationErrors] = useState({});
  const [uploadedDocs, setUploadedDocs] = useState({});
  const [pendingKycFiles, setPendingKycFiles] = useState({});
  const [uploadingDoc, setUploadingDoc] = useState('');
  const [profileImagePreview, setProfileImagePreview] = useState('');
  const [partnerNotifications, setPartnerNotifications] = useState({ items: [], unread: 0 });
  const uploadInputs = useRef({});
  const avatarInput = useRef(null);
  const localProfileSyncRef = useRef('');
  const partnerData = stats?.partner || partner || {};
  const partnerStorageId = String(partnerData?._id || user?.partnerId || user?.email || 'partner');
  const docsStorageKey = `partner_kyc_docs_${partnerStorageId}`;
  const avatarStorageKey = `partner_avatar_${partnerStorageId}`;
  const [localProfile, setLocalProfile] = useState({
    fullName: partnerData?.ownerUserId?.name || user?.name || 'Partner Admin',
    designation: 'Partner Admin',
    email: partnerData?.ownerUserId?.email || user?.email || '',
    phone: partnerData?.ownerUserId?.phone || user?.phone || partnerData?.mobile || '',
    alternatePhone: '',
    language: 'English',
    timezone: '(GMT +05:30) Asia/Kolkata',
    companyName: partnerData?.name || 'Partner Company',
    gstNumber: partnerData?.profile?.gstNumber || '',
    panNumber: partnerData?.profile?.panNumber || '',
    bankAccount: partnerData?.profile?.bankAccount || '',
    accountHolderName: partnerData?.profile?.accountHolderName || '',
    bankName: partnerData?.profile?.bankName || '',
    accountNumber: partnerData?.profile?.accountNumber || partnerData?.profile?.bankAccount || '',
    confirmAccountNumber: partnerData?.profile?.accountNumber || partnerData?.profile?.bankAccount || '',
    ifscCode: partnerData?.profile?.ifscCode || '',
    branchName: partnerData?.profile?.branchName || '',
    partnerLinkedAccountId: partnerData?.partner_linked_account_id || '',
    notifications: true,
  });

  useEffect(() => {
    if (!partnerData?._id || editing) return;
    setLocalProfile(prev => ({
      ...prev,
      fullName: partnerData?.ownerUserId?.name || user?.name || prev.fullName,
      email: partnerData?.ownerUserId?.email || user?.email || prev.email,
      phone: partnerData?.ownerUserId?.phone || user?.phone || partnerData?.mobile || prev.phone,
      companyName: partnerData?.name || prev.companyName,
      gstNumber: partnerData?.profile?.gstNumber || '',
      panNumber: partnerData?.profile?.panNumber || '',
      bankAccount: partnerData?.profile?.bankAccount || '',
      accountHolderName: partnerData?.profile?.accountHolderName || '',
      bankName: partnerData?.profile?.bankName || '',
      accountNumber: partnerData?.profile?.accountNumber || partnerData?.profile?.bankAccount || '',
      confirmAccountNumber: partnerData?.profile?.accountNumber || partnerData?.profile?.bankAccount || '',
      ifscCode: partnerData?.profile?.ifscCode || '',
      branchName: partnerData?.profile?.branchName || '',
      partnerLinkedAccountId: partnerData?.partner_linked_account_id || '',
    }));
  }, [partnerData?._id, partnerData?.updatedAt, user?.name, user?.email, user?.phone, editing]);

  const companyCount = stats?.companies || 0;
  const activeCompanies = stats?.activeCompanies || 0;
  const agentCount = stats?.totalAgents || 0;
  const activeAgents = stats?.activeAgents || 0;
  const monthlyRevenue = stats?.monthlyRevenue || stats?.paidRevenue || partnerData?.plan?.amountPaid || 0;
  const pendingInvoices = stats?.pendingRevenue || partnerData?.plan?.quote?.amountInr || 0;
  const planName = partnerData?.plan?.type || 'Business Plan';
  const sections = [
    ['dashboard', '⌂', 'Dashboard'],
    ['agents', '◫', 'Agent'],
    ['subscription', '▤', 'Subscription & Payments'],
    ['requests', '▱', 'Buy Agent License'],
    ['profile', '♙', 'My Profile'],
    ['company', '▥', 'Company Information'],
    ['kyc', '▧', 'KYC Documents'],
    ['bank', '⌂', 'Bank & Payout Details'],
    ['users', '♧', 'Users & Permissions'],
    ['security', '⬡', 'Security'],
    ['notifications', '♢', 'Notifications'],
    ['activity', '◷', 'Activity Log'],
    ['support', '?', 'Support'],
  ];
  const isPartnerPlanPaid = (partnerData?.plan?.paymentStatus === 'paid' && partnerData?.plan?.isActive === true)
    || ['active', 'approved'].includes(partnerData?.status)
    || stats?.partial;
  const visibleSections = sections;

  useEffect(() => {
    try {
      const savedDocs = localStorage.getItem(docsStorageKey);
      const savedAvatar = localStorage.getItem(avatarStorageKey);
      if (savedDocs) localStorage.removeItem(docsStorageKey);
      const syncKey = `${avatarStorageKey}:${savedAvatar || ''}`;
      const shouldSyncLocalFiles = localProfileSyncRef.current !== syncKey;
      localProfileSyncRef.current = syncKey;
      const serverAvatarName = partnerData?.profile?.avatarFileName || '';
      const serverAvatarPreview = partnerData?.profile?.avatarDataUrl || '';
      const serverAvatarPath = partnerData?.profile?.avatarFilePath || '';
      const serverAvatarUrl = serverAvatarPath ? `${SOCKET_URL}/uploads/${serverAvatarPath}` : '';
      const serverDocs = kycDocsFromServer(partnerData?.profile?.kycDocuments || {});
      const nextDocs = {
        ...serverDocs,
        ...pendingKycFiles,
        ...(!serverAvatarName ? {} : { profileImage: serverAvatarName }),
      };
      setUploadedDocs(nextDocs);
      const avatarPreview = savedAvatar || serverAvatarPreview || serverAvatarUrl || '';
      setProfileImagePreview(avatarPreview);
      if (shouldSyncLocalFiles && savedAvatar && !serverAvatarPreview) {
        api.patch('/partner/profile', {
          avatarFileName: serverAvatarName || 'profile-image.png',
          avatarDataUrl: savedAvatar,
        }).then(({ data }) => onPartnerSaved?.(data)).catch(() => { });
      }
    } catch {
      localStorage.removeItem(docsStorageKey);
      localStorage.removeItem(avatarStorageKey);
    }
  }, [docsStorageKey, avatarStorageKey, pendingKycFiles, partnerData?.profile?.avatarFileName, partnerData?.profile?.avatarFilePath, partnerData?.profile?.avatarDataUrl, partnerData?.profile?.kycDocuments]);

  const loadPartnerNotifications = () => {
    api.get('/partner/notifications')
      .then(({ data }) => setPartnerNotifications({ items: data.items || [], unread: data.unread || 0 }))
      .catch(() => { });
  };

  useEffect(() => {
    if (!user?.partnerId) return undefined;
    loadPartnerNotifications();
    const socket = io(SOCKET_URL);
    socket.emit('join:partner', user.partnerId);
    socket.on('partner:notification', ({ notification }) => {
      if (!notification) return loadPartnerNotifications();
      setPartnerNotifications(prev => ({
        items: [notification, ...(prev.items || [])],
        unread: (prev.unread || 0) + 1,
      }));
    });
    socket.on('partner:update', loadPartnerNotifications);
    return connectSocket(socket);
  }, [user?.partnerId]);

  const markNotificationsRead = async () => {
    const { data } = await api.patch('/partner/notifications/read', {});
    setPartnerNotifications(prev => ({
      items: (prev.items || []).map(item => ({ ...item, read: true })),
      unread: data.unread || 0,
    }));
    window.dispatchEvent(new CustomEvent('partner-notifications:unread', { detail: { unread: data.unread || 0 } }));
    loadPartnerNotifications();
  };

  useEffect(() => {
    setActiveSection(sectionFromSearch(location.search));
  }, [location.search]);

  const selectSection = id => {
    setActiveSection(id);
    const params = new URLSearchParams(location.search);
    params.set('section', id);
    navigate({ pathname: location.pathname, search: `?${params.toString()}` }, { replace: false });
  };

  const showLocalMessage = message => {
    setLocalMessage(message);
    window.setTimeout(() => setLocalMessage(''), 3000);
  };

  const validateSection = section => {
    const errors = {};
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const phoneRe = /^[6-9]\d{9}$/;
    const gstRe = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]$/;
    const panRe = /^[A-Z]{5}[0-9]{4}[A-Z]$/;
    const ifscRe = /^[A-Z]{4}0[A-Z0-9]{6}$/;
    const serverDocs = partnerData?.profile?.kycDocuments || {};
    const hasDoc = doc => Boolean(
      uploadedDocs[doc]?.name ||
      (doc === 'GST Certificate' && serverDocs.gstCertificateName) ||
      (doc === 'PAN Card' && serverDocs.panCardName) ||
      (doc === 'Business Registration' && serverDocs.businessRegistrationName)
    );

    if (section === 'Profile') {
      if (!localProfile.fullName.trim()) errors.fullName = 'Full name is required.';
      if (!localProfile.email.trim() || !emailRe.test(localProfile.email.trim())) errors.email = 'Valid email is required.';
      if (localProfile.phone && !phoneRe.test(localProfile.phone.trim())) errors.phone = 'Enter a valid 10 digit mobile number.';
      if (localProfile.alternatePhone && !phoneRe.test(localProfile.alternatePhone.trim())) errors.alternatePhone = 'Enter a valid alternate mobile number.';
    }

    if (section === 'Company Information') {
      if (!localProfile.companyName.trim()) errors.companyName = 'Company name is required.';
      if (localProfile.gstNumber && !gstRe.test(localProfile.gstNumber.trim().toUpperCase())) errors.gstNumber = 'Enter a valid GST number.';
      if (localProfile.panNumber && !panRe.test(localProfile.panNumber.trim().toUpperCase())) errors.panNumber = 'Enter a valid PAN number.';
    }

    if (section === 'Bank & Payout Details') {
      if (!localProfile.accountHolderName.trim()) errors.accountHolderName = 'Account holder name is required.';
      if (!localProfile.bankName.trim()) errors.bankName = 'Bank name is required.';
      if (!/^\d{9,18}$/.test(localProfile.accountNumber.trim())) errors.accountNumber = 'Enter a valid account number.';
      if (localProfile.accountNumber !== localProfile.confirmAccountNumber) errors.confirmAccountNumber = 'Account numbers must match.';
      if (!ifscRe.test(localProfile.ifscCode.trim().toUpperCase())) errors.ifscCode = 'Enter a valid IFSC code.';
    }

    if (section === 'KYC Documents') {
      const missing = ['GST Certificate', 'PAN Card', 'Business Registration'].filter(doc => !hasDoc(doc));
      if (missing.length === 3) errors.documents = 'Upload at least one KYC document before saving.';
    }

    setValidationErrors(errors);
    if (Object.keys(errors).length) showLocalMessage(Object.values(errors)[0]);
    return Object.keys(errors).length === 0;
  };

  const saveLocal = async section => {
    try {
      if (['Profile', 'Bank & Payout Details', 'Company Information', 'KYC Documents'].includes(section) && !validateSection(section)) return;
      if (['Profile', 'Bank & Payout Details', 'Company Information', 'KYC Documents'].includes(section)) {
        const serverDocs = partnerData?.profile?.kycDocuments || {};
        const payload = {
          fullName: localProfile.fullName,
          email: localProfile.email,
          phone: localProfile.phone,
          name: localProfile.companyName,
        };
        if (section === 'Bank & Payout Details') {
          Object.assign(payload, {
            bankAccount: localProfile.accountNumber || localProfile.bankAccount,
            accountHolderName: localProfile.accountHolderName,
            bankName: localProfile.bankName,
            accountNumber: localProfile.accountNumber,
            ifscCode: localProfile.ifscCode,
            branchName: localProfile.branchName,
            partner_linked_account_id: localProfile.partnerLinkedAccountId,
          });
        }
        if (section === 'Company Information') {
          Object.assign(payload, {
            gstNumber: localProfile.gstNumber,
            panNumber: localProfile.panNumber,
          });
        }
        if (section === 'Profile' && uploadedDocs.profileImage) {
          payload.avatarFileName = uploadedDocs.profileImage;
          payload.avatarDataUrl = profileImagePreview;
        }
        if (section === 'KYC Documents') {
          let latestPartner = null;
          const nextDocs = { ...uploadedDocs };
          for (const docName of kycDocLabels) {
            const draft = pendingKycFiles[docName];
            if (!draft?.file) continue;
            setUploadingDoc(docName);
            const fd = new FormData();
            fd.append('docType', kycDocTypeMap[docName]);
            fd.append('file', draft.file);
            const { data } = await api.post('/partner/upload-doc', fd, {
              headers: { 'Content-Type': 'multipart/form-data' },
            });
            latestPartner = data.partner || latestPartner;
            nextDocs[docName] = {
              name: data.originalName || draft.file.name,
              type: draft.file.type,
              filePath: data.filePath,
              fileUrl: data.fileUrl,
            };
          }
          setUploadingDoc('');
          if (latestPartner) onPartnerSaved?.(latestPartner);
          setPendingKycFiles({});
          setUploadedDocs(nextDocs);
          localStorage.removeItem(docsStorageKey);
          payload.kycDocuments = {
            gstCertificateName: nextDocs['GST Certificate']?.name || serverDocs.gstCertificateName || '',
            gstCertificateType: nextDocs['GST Certificate']?.type || serverDocs.gstCertificateType || '',
            gstCertificateDataUrl: nextDocs['GST Certificate']?.previewUrl || serverDocs.gstCertificateDataUrl || '',
            gstCertificateFilePath: nextDocs['GST Certificate']?.filePath || serverDocs.gstCertificateFilePath || '',
            panCardName: nextDocs['PAN Card']?.name || serverDocs.panCardName || '',
            panCardType: nextDocs['PAN Card']?.type || serverDocs.panCardType || '',
            panCardDataUrl: nextDocs['PAN Card']?.previewUrl || serverDocs.panCardDataUrl || '',
            panCardFilePath: nextDocs['PAN Card']?.filePath || serverDocs.panCardFilePath || '',
            businessRegistrationName: nextDocs['Business Registration']?.name || serverDocs.businessRegistrationName || '',
            businessRegistrationType: nextDocs['Business Registration']?.type || serverDocs.businessRegistrationType || '',
            businessRegistrationDataUrl: nextDocs['Business Registration']?.previewUrl || serverDocs.businessRegistrationDataUrl || '',
            businessRegistrationFilePath: nextDocs['Business Registration']?.filePath || serverDocs.businessRegistrationFilePath || '',
          };
        }
        const { data } = await api.patch('/partner/profile', payload);
        onPartnerSaved?.(data);
      }
      setEditing('');
      if (section === 'KYC Documents') {
        const serverDocs = partnerData?.profile?.kycDocuments || {};
        const hasDoc = doc => Boolean(
          uploadedDocs[doc]?.name ||
          (doc === 'GST Certificate' && serverDocs.gstCertificateName) ||
          (doc === 'PAN Card' && serverDocs.panCardName) ||
          (doc === 'Business Registration' && serverDocs.businessRegistrationName)
        );
        const missing = ['GST Certificate', 'PAN Card', 'Business Registration'].filter(doc => !hasDoc(doc));
        setValidationErrors(prev => ({ ...prev, documents: missing.length ? `Pending documents: ${missing.join(', ')}.` : undefined }));
        showLocalMessage(missing.length ? `KYC details saved. Pending: ${missing.join(', ')}.` : 'KYC details saved. All documents uploaded.');
      } else {
        showLocalMessage(`${section} updated.`);
      }
    } catch (err) {
      setUploadingDoc('');
      showLocalMessage(err.response?.data?.message || `${section} update failed.`);
    }
  };

  const openUpload = docName => {
    uploadInputs.current[docName]?.click();
  };

  const readFileAsDataUrl = file => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });

  const persistAvatarFileName = async (fileName, preview = '') => {
    if (!fileName) return;
    const { data } = await api.patch('/partner/profile', { avatarFileName: fileName, avatarDataUrl: preview });
    onPartnerSaved?.(data);
  };

  const handleUpload = async (docName, file) => {
    if (!file) return;
    const allowed = ['application/pdf', 'image/png', 'image/jpeg'];
    if (!allowed.includes(file.type)) {
      showLocalMessage('Only PDF, PNG, or JPG files are allowed.');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      showLocalMessage('File size must be 5 MB or less.');
      return;
    }
    try {
      const previewUrl = await readFileAsDataUrl(file);
      const draftDoc = { name: file.name, type: file.type, previewUrl, file, draft: true };
      const nextDocs = {
        ...uploadedDocs,
        [docName]: draftDoc,
      };
      setUploadedDocs(nextDocs);
      setPendingKycFiles(prev => ({ ...prev, [docName]: draftDoc }));
      setValidationErrors(prev => ({ ...prev, documents: undefined }));
      showLocalMessage(`${docName} selected. Click Save KYC Details to upload.`);
    } catch (err) {
      showLocalMessage(err.response?.data?.message || `${docName} selection failed.`);
    }
  };

  const handleAvatarUpload = async file => {
    if (!file) return;
    if (!['image/png', 'image/jpeg'].includes(file.type)) {
      showLocalMessage('Profile image must be JPG or PNG.');
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      showLocalMessage('Profile image size must be 2 MB or less.');
      return;
    }
    try {
      const fd = new FormData();
      fd.append('file', file);
      const { data } = await api.post('/partner/upload-avatar', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setProfileImagePreview(data.fileUrl);
      setUploadedDocs(prev => {
        const next = { ...prev, profileImage: data.originalName || file.name, avatarFilePath: data.filePath, avatarUrl: data.fileUrl };
        try { localStorage.setItem(docsStorageKey, JSON.stringify(next)); } catch { }
        return next;
      });
      onPartnerSaved?.(data.partner);
      showLocalMessage(`✅ Profile image uploaded: ${file.name}`);
    } catch (err) {
      showLocalMessage(err.response?.data?.message || 'Profile image upload failed.');
    }
  };

  return (
    <div style={partnerProfilePage}>
      <aside style={partnerProfileSidebar}>
        {visibleSections.map(([id, icon, label]) => (
          <button key={id} type="button" onClick={() => selectSection(id)} style={activeSection === id ? profileNavActive : profileNav}>
            <span>{icon}</span>{label}
          </button>
        ))}
      </aside>

      <main style={activeSection === 'dashboard' ? profileDashboardMain : profileContentMain}>
        {localMessage && <div style={profileOk}>{localMessage}</div>}
        {activeSection === 'profile' && (
          <>
            <section style={profileHero}>
              <h2 style={profileSectionTitle}>Profile Information</h2>
              <div style={profileHeroBody}>
                <div style={profileAvatarWrap}>
                  <div style={profileAvatar}>
                    {profileImagePreview ? (
                      <img src={profileImagePreview} alt="Profile preview" style={profileAvatarImage} />
                    ) : initials(localProfile.fullName || partner?.name || 'A')}
                  </div>
                  <input ref={avatarInput} type="file" accept=".png,.jpg,.jpeg,image/png,image/jpeg" onChange={e => handleAvatarUpload(e.target.files?.[0])} style={{ display: 'none' }} />
                  <button type="button" onClick={() => avatarInput.current?.click()} style={profileCamera}>▣</button>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={profileNameRow}>
                    <strong>{localProfile.companyName}</strong>
                    <span style={activeBadge}>Active Partner</span>
                  </div>
                  <ProfileLine label="Partner ID" value={`PRT-${String(partnerData?._id || '0001').slice(-4).toUpperCase()}`} />
                  <ProfileLine label="Partner Since" value={fmtDate(partnerData?.createdAt || user?.createdAt)} />
                  <ProfileLine label="Email" value={localProfile.email} />
                  <ProfileLine label="Phone" value={localProfile.phone || '-'} />
                </div>
                <button type="button" onClick={() => setEditing('profile')} style={editProfileButton}>✎ Edit Profile</button>
              </div>
            </section>

            <div style={profileOneCol}>
              <section style={profileCard}>
                <div style={profileCardHeader}>
                  <h2 style={profileSectionTitle}>Personal Details</h2>
                  <button type="button" onClick={() => setEditing(editing === 'personal' ? '' : 'personal')} style={smallEditButton}>✎ Edit</button>
                </div>
                {editing === 'personal' || editing === 'profile' ? (
                  <EditableGrid profile={localProfile} setProfile={setLocalProfile} fields={['fullName', 'designation', 'email', 'phone', 'alternatePhone']} errors={validationErrors} />
                ) : (
                  <>
                    <ProfileLine label="Full Name" value={localProfile.fullName} />
                    <ProfileLine label="Designation" value={localProfile.designation} />
                    <ProfileLine label="Email Address" value={localProfile.email} />
                    <ProfileLine label="Phone Number" value={localProfile.phone} />
                    <ProfileLine label="Alternate Phone (Optional)" value={localProfile.alternatePhone || '-'} />
                  </>
                )}
                <label style={profileSelectLabel}>Language Preference<select value={localProfile.language} onChange={e => setLocalProfile(prev => ({ ...prev, language: e.target.value }))} style={profileSelect}><option>English</option><option>Hindi</option></select></label>
                <label style={profileSelectLabel}>Time Zone<select value={localProfile.timezone} onChange={e => setLocalProfile(prev => ({ ...prev, timezone: e.target.value }))} style={profileSelect}><option>(GMT +05:30) Asia/Kolkata</option><option>(GMT +00:00) UTC</option></select></label>
                {editing && <button type="button" onClick={() => saveLocal('Profile')} style={{ ...profilePrimaryButton, marginTop: 12 }}>Save Details</button>}
              </section>

            </div>
          </>
        )}

        {activeSection !== 'profile' && (
          <ProfileSectionPanel
            section={activeSection}
            profile={localProfile}
            setProfile={setLocalProfile}
            saveLocal={saveLocal}
            isImpersonating={isImpersonating}
            errors={validationErrors}
            uploadedDocs={uploadedDocs}
            uploadInputs={uploadInputs}
            openUpload={openUpload}
            handleUpload={handleUpload}
            uploadingDoc={uploadingDoc}
            user={user}
            onPartnerSaved={onPartnerSaved}
            onNavigateSection={selectSection}
            navigate={navigate}
            tfaStatus={tfaStatus}
            passwordCard={<PasswordCard pwForm={pwForm} setPwForm={setPwForm} pwMsg={pwMsg} pwErr={pwErr} pwBusy={pwBusy} changePassword={changePassword} isImpersonating={isImpersonating} />}
            twoFactorCard={<TwoFactorCard tfaStatus={tfaStatus} tfaLoading={tfaLoading} tfaQR={tfaQR} tfaSecret={tfaSecret} tfaCode={tfaCode} setTfaCode={setTfaCode} tfaErr={tfaErr} tfaMsg={tfaMsg} disableCode={disableCode} setDisableCode={setDisableCode} handle2FASetup={handle2FASetup} handle2FAVerify={handle2FAVerify} handle2FADisable={handle2FADisable} cancel2FASetup={cancel2FASetup} isImpersonating={isImpersonating} />}
            notifications={partnerNotifications}
            markNotificationsRead={markNotificationsRead}
            dashboardRefreshKey={dashboardRefreshKey}
            stats={{ ...stats, partner: partnerData, companyCount, activeCompanies, agentCount, activeAgents, monthlyRevenue, pendingInvoices, planName, planExpires: partnerData?.plan?.expiresAt }}
          />
        )}

      </main>
    </div>
  );
}

function ProfileLine({ label, value }) {
  return (
    <div style={profileLine}>
      <span>{label}</span>
      <b>{value || '-'}</b>
    </div>
  );
}

function ProfilePassword({ label, value, onChange, disabled }) {
  return (
    <label style={profilePasswordLabel}>
      {label}
      <input disabled={disabled} type="password" value={value} onChange={e => onChange(e.target.value)} placeholder={label} style={profileInput} />
    </label>
  );
}

function PasswordCard({ pwForm, setPwForm, pwMsg, pwErr, pwBusy, changePassword, isImpersonating }) {
  return (
    <section style={profileCard}>
      <h2 style={profileSectionTitle}>Change Password</h2>
      {isImpersonating && <div style={profileWarn}>Password changes are disabled during Super Admin partner login.</div>}
      {pwMsg && <div style={profileOk}>{pwMsg}</div>}
      {pwErr && <div style={profileWarn}>{pwErr}</div>}
      <form onSubmit={changePassword} style={{ display: 'grid', gap: 12 }}>
        <ProfilePassword label="Current Password" value={pwForm.currentPassword} onChange={value => setPwForm(prev => ({ ...prev, currentPassword: value }))} disabled={isImpersonating} />
        <ProfilePassword label="New Password" value={pwForm.newPassword} onChange={value => setPwForm(prev => ({ ...prev, newPassword: value }))} disabled={isImpersonating} />
        <ProfilePassword label="Confirm New Password" value={pwForm.confirm} onChange={value => setPwForm(prev => ({ ...prev, confirm: value }))} disabled={isImpersonating} />
        <button disabled={pwBusy || isImpersonating} style={profilePrimaryButton}>▢ Update Password</button>
      </form>
    </section>
  );
}

function TwoFactorCard({ tfaStatus, tfaLoading, tfaQR, tfaSecret, tfaCode, setTfaCode, tfaErr, tfaMsg, disableCode, setDisableCode, handle2FASetup, handle2FAVerify, handle2FADisable, cancel2FASetup, isImpersonating }) {
  const enabled = Boolean(tfaStatus?.enabled);
  return (
    <section style={twoFactorCard}>
      <h2 style={twoFactorTitle}>🔐 Two-Factor Authentication</h2>
      {isImpersonating && <div style={profileWarn}>2FA changes are disabled during Super Admin partner login.</div>}
      {tfaMsg && <div style={profileOk}>{tfaMsg}</div>}
      {tfaErr && <div style={profileWarn}>{tfaErr}</div>}

      {!enabled && !tfaQR && (
        <>
          <div style={twoFactorWarnBox}>
            <h3 style={twoFactorWarnTitle}>⚠️ 2FA Not Enabled</h3>
            <p style={twoFactorText}>Add Google Authenticator for an extra layer of security. Requires a code from your phone on every login.</p>
          </div>
          <button type="button" onClick={handle2FASetup} disabled={tfaLoading || isImpersonating} style={twoFactorPrimaryButton}>
            📱 {tfaLoading ? 'Setting up...' : 'Set Up Google Authenticator'}
          </button>
        </>
      )}

      {!enabled && tfaQR && (
        <div style={twoFactorSetupGrid}>
          <p style={twoFactorText}>Scan this QR code with <b style={{ color: '#e2e8f0' }}>Google Authenticator</b> or any TOTP app:</p>
          <img src={tfaQR} alt="2FA QR Code" style={twoFactorQr} />
          <div style={twoFactorKeyBox}>
            <span>Manual Entry Key</span>
            <b>{tfaSecret || '-'}</b>
          </div>
          <label style={twoFactorCodeLabel}>
            Enter 6-Digit Code From App
            <input
              value={tfaCode}
              onChange={event => setTfaCode?.(event.target.value.replace(/\D/g, '').slice(0, 6))}
              maxLength="6"
              placeholder="000000"
              style={twoFactorCodeInput}
            />
          </label>
          <div style={twoFactorActions}>
            <button type="button" onClick={handle2FAVerify} disabled={tfaLoading || String(tfaCode || '').length !== 6 || isImpersonating} style={twoFactorEnableButton}>
              ✅ {tfaLoading ? 'Enabling...' : 'Enable 2FA'}
            </button>
            <button type="button" onClick={cancel2FASetup} style={twoFactorCancelButton}>Cancel</button>
          </div>
        </div>
      )}

      {enabled && (
        <div style={twoFactorSetupGrid}>
          <div style={twoFactorOkBox}>
            <h3 style={twoFactorOkTitle}>🔐 2FA is Active</h3>
            <p style={twoFactorText}>Your account is protected with Google Authenticator.</p>
          </div>
          <label style={twoFactorCodeLabel}>
            Enter 6-Digit Code To Disable 2FA
            <input
              value={disableCode}
              onChange={event => setDisableCode?.(event.target.value.replace(/\D/g, '').slice(0, 6))}
              maxLength="6"
              placeholder="000000"
              style={twoFactorCodeInput}
            />
          </label>
          <button type="button" onClick={handle2FADisable} disabled={tfaLoading || String(disableCode || '').length !== 6 || isImpersonating} style={twoFactorDangerButton}>
            {tfaLoading ? 'Disabling...' : 'Disable 2FA'}
          </button>
        </div>
      )}
    </section>
  );
}

function EditableGrid({ profile, setProfile, fields, errors = {} }) {
  const labels = {
    fullName: 'Full Name',
    designation: 'Designation',
    email: 'Email Address',
    phone: 'Phone Number',
    alternatePhone: 'Alternate Phone',
    companyName: 'Company Name',
    gstNumber: 'GST Number',
    panNumber: 'PAN Number',
    bankAccount: 'Bank Account',
    accountHolderName: 'Account Holder Name',
    bankName: 'Bank Name',
    accountNumber: 'Account Number',
    confirmAccountNumber: 'Confirm Account Number',
    ifscCode: 'IFSC Code',
    branchName: 'Branch Name',
    partnerLinkedAccountId: 'Partner Linked Account ID',
  };
  const helperText = {
    partnerLinkedAccountId: 'Super Admin will add the Razorpay Route linked account ID, for example acc_xxxxxxxxxxxxxx. It is required only for automatic partner payout transfers.',
  };
  const disabledFields = new Set(['partnerLinkedAccountId']);

  return (
    <div style={{ display: 'grid', gap: 10 }}>
      {fields.map(field => (
        <label key={field} style={profilePasswordLabel}>
          {labels[field] || field}
          <input
            value={profile[field] || ''}
            onChange={e => setProfile(prev => ({ ...prev, [field]: e.target.value }))}
            placeholder={field === 'partnerLinkedAccountId' ? 'acc_xxxxxxxxxxxxxx' : labels[field] || field}
            disabled={disabledFields.has(field)}
            style={disabledFields.has(field) ? profileInputDisabled : errors[field] ? profileInputError : profileInput}
          />
          {helperText[field] && <span style={fieldHelp}>{helperText[field]}</span>}
          {errors[field] && <span style={fieldError}>{errors[field]}</span>}
        </label>
      ))}
    </div>
  );
}

function SupportTicketForm({ partner, profile }) {
  const ticketId = `TKT-${new Date().getFullYear()}-${String(partner?._id || Date.now()).slice(-6).toUpperCase()}`;
  const now = new Date().toLocaleString('en-IN');
  const [ticket, setTicket] = useState({
    category: 'Company Registration Issue',
    priority: 'Medium',
    subject: '',
    description: '',
    transactionId: '',
    paymentDate: '',
    amount: '',
    companyName: '',
    screenshot: '',
    screenshotName: '',
    screenshotDataUrl: '',
    invoice: '',
    documents: '',
    status: 'Open',
    createdDate: now,
    lastUpdatedDate: now,
  });

  const [tickets, setTickets] = useState([]);
  const [message, setMessage] = useState('');
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [replyMessage, setReplyMessage] = useState('');
  const [replyBusy, setReplyBusy] = useState(false);
  const [showCreate, setShowCreate] = useState(false);

  const showPaymentInfo = ['Payment Issue', 'Subscription Issue', 'Commission Issue', 'Payout Issue'].includes(ticket.category);
  const setField = (key, value) => setTicket(prev => ({ ...prev, [key]: value, lastUpdatedDate: new Date().toLocaleString('en-IN') }));

  const loadTickets = () => {
    api.get('/partner/support-tickets')
      .then(({ data }) => {
        const list = Array.isArray(data) ? data : [];
        setTickets(list);
        setSelectedTicket(prev => prev ? (list.find(t => t._id === prev._id) || prev) : null);
      })
      .catch(() => setTickets([]));
  };

  useEffect(() => {
    loadTickets();
    const socket = io(SOCKET_URL, socketOptions);
    if (partner?._id) {
      socket.emit('join:partner', partner._id);
    }
    const handleUpdate = () => {
      loadTickets();
    };
    socket.on('support:ticket_new', handleUpdate);
    socket.on('support:message_new', handleUpdate);
    socket.on('support:ticket_updated', handleUpdate);
    return connectSocket(socket);
  }, [partner?._id, selectedTicket?._id]);

  const submit = async e => {
    e.preventDefault();
    if (!ticket.subject.trim() || !ticket.description.trim()) {
      setMessage('Subject and description required.');
      return;
    }
    try {
      const { data } = await api.post('/partner/support-tickets', ticket);
      setMessage(`Ticket ${data.ticketId || ticketId} submitted.`);
      setTickets(prev => [data, ...prev]);
      setTicket(prev => ({
        ...prev,
        subject: '',
        description: '',
        transactionId: '',
        paymentDate: '',
        amount: '',
        companyName: '',
        screenshot: '',
        screenshotName: '',
        screenshotDataUrl: '',
        invoice: '',
        documents: '',
        lastUpdatedDate: new Date().toLocaleString('en-IN'),
      }));
      setShowCreate(false);
      loadTickets();
    } catch (err) {
      setMessage(err.response?.data?.message || 'Ticket submit failed.');
    }
  };

  const cancel = () => {
    setTicket(prev => ({
      ...prev,
      subject: '',
      description: '',
      transactionId: '',
      paymentDate: '',
      amount: '',
      companyName: '',
      screenshot: '',
      screenshotName: '',
      screenshotDataUrl: '',
      invoice: '',
      documents: '',
      lastUpdatedDate: new Date().toLocaleString('en-IN'),
    }));
    setMessage('');
    setShowCreate(false);
  };

  const sendReply = async (e) => {
    e.preventDefault();
    if (!replyMessage.trim() || !selectedTicket) return;
    setReplyBusy(true);
    try {
      const { data } = await api.post(`/partner/support-tickets/${selectedTicket._id}/messages`, {
        message: replyMessage
      });
      setReplyMessage('');
      setSelectedTicket(data);
      loadTickets();
    } catch (err) {
      Swal.fire('Error', err.response?.data?.message || 'Reply send failed', 'error');
    } finally {
      setReplyBusy(false);
    }
  };


  if (showCreate) {
    return (
      <form onSubmit={submit} style={supportForm}>
        <ApiNotice endpoint="GET/POST /partner/support-tickets" />
        <section style={supportSection}>
          <h3 style={supportSectionTitle}>Issue Information</h3>
          <div style={supportGrid}>
            <SupportSelect label="Issue Category *" value={ticket.category} onChange={value => setField('category', value)} options={[
              'Company Registration Issue',
              'Payment Issue',
              'Subscription Issue',
              'Commission Issue',
              'Payout Issue',
              'Technical Issue',
              'Account Access Issue',
              'Feature Request',
              'Other',
            ]} />
            <SupportSelect label="Priority Level *" value={ticket.priority} onChange={value => setField('priority', value)} options={['Low', 'Medium', 'High', 'Critical']} />
          </div>
        </section>

        <section style={supportSection}>
          <h3 style={supportSectionTitle}>Issue Details</h3>
          <SupportInput label="Subject *" value={ticket.subject} onChange={value => setField('subject', value)} />
          <SupportTextarea label="Description *" value={ticket.description} onChange={value => setField('description', value)} />
        </section>

        {showPaymentInfo && (
          <section style={supportSection}>
            <h3 style={supportSectionTitle}>Payment & Payout Information</h3>
            <div style={supportGrid}>
              <SupportInput label="Transaction ID" value={ticket.transactionId} onChange={value => setField('transactionId', value)} />
              <SupportInput label="Payment Date" type="date" value={ticket.paymentDate} onChange={value => setField('paymentDate', value)} />
              <SupportInput label="Amount" type="number" value={ticket.amount} onChange={value => setField('amount', value)} />
              <SupportInput label="Company Name Related to Payment" value={ticket.companyName} onChange={value => setField('companyName', value)} />
            </div>
          </section>
        )}

        {message && <div style={message.includes('submitted') ? profileOk : profileWarn}>{message}</div>}
        <div style={supportActions}>
          <button type="submit" style={profilePrimaryButton}>Submit Ticket</button>
          <button type="button" onClick={cancel} style={supportCancelButton}>Cancel</button>
        </div>
      </form>
    );
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr', gap: 20, alignItems: 'start', marginTop: 14 }}>
      <section style={{ ...profileCard, padding: 20 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <h3 style={{ ...profileSectionTitle, margin: 0 }}>Support Tickets</h3>
          <button
            type="button"
            onClick={() => { setShowCreate(true); setSelectedTicket(null); setMessage(''); }}
            style={{
              padding: '6px 12px', borderRadius: 6, border: 'none',
              background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
              color: '#fff', fontSize: 11, fontWeight: 700, cursor: 'pointer'
            }}
          >
            + New Ticket
          </button>
        </div>
        {tickets.length === 0 ? (
          <div style={{ color: '#cbd5e1', fontSize: 13, padding: 10 }}>No support tickets found.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 450, overflowY: 'auto' }}>
            {tickets.map(t => {
              const isSelected = selectedTicket?._id === t._id;
              const priorityColors = {
                Low: { bg: 'rgba(148,163,184,0.1)', text: '#cbd5e1' },
                Medium: { bg: 'rgba(249,115,22,0.1)', text: '#f97316' },
                High: { bg: 'rgba(239,68,68,0.1)', text: '#ef4444' },
                Critical: { bg: 'rgba(220,38,38,0.2)', text: '#f87171' }
              };
              const statusColors = {
                'Open': '#eab308',
                'In Progress': '#3b82f6',
                'Resolved': '#10b981',
                'Closed': '#64748b'
              };
              const prio = priorityColors[t.priority] || priorityColors.Medium;
              return (
                <div
                  key={t._id}
                  onClick={() => setSelectedTicket(t)}
                  style={{
                    padding: 12, borderRadius: 8, cursor: 'pointer',
                    background: isSelected ? 'rgba(59,130,246,0.15)' : '#07111f',
                    border: isSelected ? '1px solid #3b82f6' : '1px solid #1e3a5f',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: '#60a5fa', fontWeight: 'bold' }}>{t.ticketId}</span>
                    <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: prio.bg, color: prio.text, fontWeight: 700 }}>
                      {t.priority?.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 'bold', color: '#f8fafc', marginBottom: 4 }}>{t.subject}</div>
                  <div style={{ fontSize: 11, color: '#93c5fd', marginBottom: 6 }}>Category: {t.category}</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, color: '#94a3b8' }}>
                    <span>{new Date(t.createdAt).toLocaleDateString()}</span>
                    <span style={{ fontWeight: 700, color: statusColors[t.status] || '#cbd5e1' }}>{t.status}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {selectedTicket ? (
        <section style={{ ...profileCard, padding: 20 }}>
          <div style={{ borderBottom: '1px solid #1e3a5f', paddingBottom: 12, marginBottom: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>Ticket: {selectedTicket.ticketId}</h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 12, color: '#94a3b8' }}>Status:</span>
                <span style={{
                  fontSize: 11, fontWeight: 'bold',
                  color: {
                    'Open': '#eab308',
                    'In Progress': '#3b82f6',
                    'Resolved': '#10b981',
                    'Closed': '#64748b'
                  }[selectedTicket.status] || '#cbd5e1',
                  background: 'rgba(15,23,42,0.6)',
                  border: `1px solid ${{
                    'Open': '#eab308',
                    'In Progress': '#3b82f6',
                    'Resolved': '#10b981',
                    'Closed': '#64748b'
                  }[selectedTicket.status] || '#1e3a5f'}`,
                  borderRadius: 6, padding: '4px 10px', textTransform: 'uppercase'
                }}>
                  {selectedTicket.status}
                </span>
              </div>
            </div>
            <div style={{ fontSize: 14, fontWeight: 'bold', color: '#fff', marginBottom: 6 }}>{selectedTicket.subject}</div>
            <p style={{ margin: 0, fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>
              {selectedTicket.description}
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 250, overflowY: 'auto', marginBottom: 14, paddingRight: 4 }}>
            {(selectedTicket.messages || []).map((msg, idx) => {
              const isMe = msg.senderRole === 'partner_admin';
              return (
                <div
                  key={msg._id || idx}
                  style={{
                    alignSelf: isMe ? 'flex-end' : 'flex-start',
                    maxWidth: '85%',
                    background: isMe ? 'linear-gradient(135deg, #1e3a8a, #1d4ed8)' : 'rgba(30,41,59,0.4)',
                    border: isMe ? 'none' : '1px solid #1e3a5f',
                    padding: '10px 14px', borderRadius: 12,
                    color: '#f8fafc', fontSize: 13, lineHeight: 1.4
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 4, fontSize: 10, color: isMe ? '#bfdbfe' : '#94a3b8', fontWeight: 600 }}>
                    <span>{msg.senderName} ({msg.senderRole === 'superadmin' ? 'Super Admin' : msg.senderRole === 'company_admin' ? 'Company Admin' : 'Partner Admin'})</span>
                    <span>{new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                  <div style={{ whiteSpace: 'pre-wrap' }}>{msg.message}</div>
                </div>
              );
            })}
          </div>

          {selectedTicket.status === 'Closed' ? (
            <div style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', padding: '10px 14px', borderRadius: 8, fontSize: 12, textAlign: 'center' }}>
              This ticket has been closed.
            </div>
          ) : (
            <form onSubmit={sendReply} style={{ display: 'flex', gap: 10 }}>
              <textarea
                required
                placeholder="Type your response..."
                value={replyMessage}
                onChange={e => setReplyMessage(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendReply(e);
                  }
                }}
                rows={1}
                style={{
                  flex: 1, padding: '10px 14px', borderRadius: 8, border: '1px solid #1e3a5f',
                  background: '#07111f', color: '#f8fafc', fontSize: 13, outline: 'none',
                  resize: 'vertical', fontFamily: 'inherit', lineHeight: '1.4', minHeight: '38px'
                }}
              />
              <button
                type="submit"
                disabled={replyBusy}
                style={{
                  padding: '0 20px', borderRadius: 8, border: 'none',
                  background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                  color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer'
                }}
              >
                {replyBusy ? 'Sending...' : 'Send'}
              </button>
            </form>
          )}
        </section>
      ) : (
        <section style={{ ...profileCard, padding: 40, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#cbd5e1', fontSize: 13, border: '1px dashed #1e3a5f', width: '100%', boxSizing: 'border-box' }}>
          Select a ticket from the list to view conversation history.
        </section>
      )}
    </div>
  );
}

function ActivityLogPanel({ fallbackLines = [] }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);

  useEffect(() => {
    let mounted = true;
    api.get('/partner/activity', { timeout: 15000 })
      .then(({ data }) => {
        if (mounted) {
          setItems(Array.isArray(data) ? data : []);
          setPage(1);
        }
      })
      .catch(() => {
        if (mounted) setItems([]);
      })
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => { mounted = false; };
  }, []);

  const itemsPerPage = 12;
  const totalPages = Math.ceil(items.length / itemsPerPage) || 1;
  const paginatedItems = items.slice((page - 1) * itemsPerPage, page * itemsPerPage);

  return (
    <section style={profileCard}>
      <div style={profileCardHeader}>
        <h2 style={profileSectionTitle}>Activity Log</h2>
        {loading && <span style={fieldHelp}>Loading...</span>}
      </div>
      <ApiNotice endpoint="GET /partner/activity" />
      {items.length ? (
        <div>
          <div style={supportTableWrap}>
            <table style={supportTable}>
              <thead>
                <tr>
                  {['Activity', 'Details', 'Date'].map(header => <th key={header} style={supportTh}>{header}</th>)}
                </tr>
              </thead>
              <tbody>
                {paginatedItems.map((item, index) => (
                  <tr key={`${item.activity}-${index}`}>
                    <td style={supportTd}>{item.activity}</td>
                    <td style={supportTd}>{item.details}</td>
                    <td style={supportTd}>{item.date ? new Date(item.date).toLocaleString('en-IN') : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 16,
            marginTop: 16,
            paddingTop: 16,
            borderTop: '1px solid rgba(100, 116, 139, 0.15)'
          }}>
            <button
              onClick={() => setPage(prev => Math.max(prev - 1, 1))}
              disabled={page === 1}
              style={{
                background: page === 1 ? 'rgba(30, 41, 59, 0.5)' : 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: 4,
                color: page === 1 ? '#64748b' : '#3b82f6',
                cursor: page === 1 ? 'not-allowed' : 'pointer',
                fontSize: 12,
                fontWeight: 'bold',
                padding: '6px 12px',
                transition: 'all 0.2s'
              }}
            >
              ◀ Previous
            </button>

            <span style={{ fontSize: 12, color: '#94a3b8' }}>
              Page <strong style={{ color: '#fff' }}>{page}</strong> of <strong style={{ color: '#fff' }}>{totalPages}</strong>
            </span>

            <button
              onClick={() => setPage(prev => Math.min(prev + 1, totalPages))}
              disabled={page === totalPages}
              style={{
                background: page === totalPages ? 'rgba(30, 41, 59, 0.5)' : 'rgba(59, 130, 246, 0.2)',
                border: '1px solid rgba(59, 130, 246, 0.3)',
                borderRadius: 4,
                color: page === totalPages ? '#64748b' : '#3b82f6',
                cursor: page === totalPages ? 'not-allowed' : 'pointer',
                fontSize: 12,
                fontWeight: 'bold',
                padding: '6px 12px',
                transition: 'all 0.2s'
              }}
            >
              Next ▶
            </button>
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 4 }}>
          {fallbackLines.map(([label, value]) => <ProfileLine key={label} label={label} value={value} />)}
        </div>
      )}
    </section>
  );
}

function ApiNotice() {
  return null;
}

function BuyAgentLicensePanel({ user, stats, onPartnerSaved }) {
  const navigate = useNavigate();
  const partner = stats?.partner || {};
  const pricing = stats?.agentPricing || partner.agentPricing || {};
  const summary = stats?.agentLicenseSummary || partner.agentLicenseSummary || {};
  const purchases = stats?.agentLicenses || partner.agentLicensePurchases || [];
  const [agentQuantity, setAgentQuantity] = useState('10');
  const [planType, setPlanType] = useState('monthly');
  const [autoPay, setAutoPay] = useState(false);
  const [autoPayBusy, setAutoPayBusy] = useState(false);
  const [purchasePage, setPurchasePage] = useState(0);
  const autoPayAlreadyEnabled = Boolean(partner.agentLicenseAutoPay?.enabled);
  const autoPayFee = autoPay && !autoPayAlreadyEnabled ? 5 : 0;
  const priceMap = {
    monthly: Number(pricing.monthly || 0),
    six_monthly: Number(pricing.sixMonthly || pricing.monthly || 0),
    yearly: Number(pricing.yearly || pricing.monthly || 0),
  };
  const qty = Math.max(Number(agentQuantity || 0), 0);
  const pricePerAgent = priceMap[planType] || 0;
  const baseAmount = qty * pricePerAgent;
  const amount = baseAmount + autoPayFee;
  const nextExpiry = summary.lastExpiryAt ? new Date(summary.lastExpiryAt) : null;
  const expiryDays = nextExpiry ? Math.max(Math.ceil((nextExpiry.getTime() - Date.now()) / (24 * 60 * 60 * 1000)), 0) : 0;
  const purchasePageSize = 10;
  const purchaseRows = purchases.slice().reverse();
  const purchasePageCount = Math.max(Math.ceil(purchaseRows.length / purchasePageSize), 1);
  const currentPurchasePage = Math.min(purchasePage, purchasePageCount - 1);
  const visiblePurchases = purchaseRows.slice(currentPurchasePage * purchasePageSize, currentPurchasePage * purchasePageSize + purchasePageSize);

  useEffect(() => {
    setAutoPay(Boolean(partner.agentLicenseAutoPay?.enabled));
  }, [partner.agentLicenseAutoPay?.enabled]);

  useEffect(() => {
    setPurchasePage(0);
  }, [purchases.length]);

  const openCheckout = () => {
    if (qty <= 0) return Swal.fire({ icon: 'warning', title: 'Agent quantity required', text: 'Enter any custom quantity greater than 0.' });
    if (pricePerAgent <= 0) return Swal.fire({ icon: 'warning', title: 'Pricing Pending', text: 'Super Admin must configure agent pricing first.' });
    const payload = { agentQuantity: qty, planType, pricePerAgent, baseAmount, autoPayFeeInr: autoPayFee, amount, autoPay, email: user?.email, phone: user?.phone };
    try { sessionStorage.setItem('agent_license_checkout', JSON.stringify(payload)); } catch { }
    navigate('/agent-license-checkout', { state: { agentLicenseCheckout: payload } });
  };

  const enableAgentAutoPay = async () => {
    if (autoPay || autoPayBusy) return;
    setAutoPayBusy(true);
    try {
      const { data } = await api.post('/payment/partner-agent-license/autopay/create-order', {}, { timeout: 60000 });
      await openRazorpay({
        order: data.order,
        subscription: data.subscription,
        planLabel: 'Enable Agent License Auto Pay',
        email: user?.email,
        phone: user?.phone,
        onSuccess: async response => {
          try {
            const result = await api.post('/payment/partner-agent-license/autopay/confirm', response, { timeout: 60000 });
            if (result.data?.partner) onPartnerSaved?.(result.data.partner);
            setAutoPay(true);
            Swal.fire({ icon: 'success', title: 'Auto Pay Enabled', text: 'Agent license Auto Pay is enabled for all payments.', timer: 1800, showConfirmButton: false, background: '#0c1a2e', color: '#e0f2fe' });
          } catch (err) {
            Swal.fire({ icon: 'warning', title: 'Activation issue', text: err.response?.data?.message || 'Payment received but Auto Pay activation failed.', background: '#0c1a2e', color: '#e0f2fe' });
          }
        },
        onFailure: msg => Swal.fire({ icon: 'error', title: 'Payment Failed', text: msg || 'Payment could not be processed.', background: '#0c1a2e', color: '#e0f2fe' }),
      });
    } catch (err) {
      Swal.fire({ icon: 'error', title: 'Auto Pay Error', text: err.response?.data?.message || err.message, background: '#0c1a2e', color: '#e0f2fe' });
    } finally {
      setAutoPayBusy(false);
    }
  };

  const disablePurchaseAutoPay = async (item) => {
    const purchaseId = item?._id || item?.invoiceId || item?.paymentId;
    if (!purchaseId) return;
    const result = await Swal.fire({
      icon: 'question',
      title: 'Disable Auto Pay?',
      text: 'Auto Pay will be disabled for this agent license payment.',
      showCancelButton: true,
      confirmButtonText: 'Disable',
      background: '#0c1a2e',
      color: '#e0f2fe',
    });
    if (!result.isConfirmed) return;
    try {
      const { data } = await api.patch(`/partner/agent-license/autopay/${purchaseId}`, { enabled: false });
      if (data.partner) onPartnerSaved?.(data.partner);
      Swal.fire({ icon: 'success', title: 'Auto Pay Disabled', timer: 1600, showConfirmButton: false, background: '#0c1a2e', color: '#e0f2fe' });
    } catch (err) {
      Swal.fire({ icon: 'error', title: 'Unable to disable Auto Pay', text: err.response?.data?.message || err.message, background: '#0c1a2e', color: '#e0f2fe' });
    }
  };

  return (
    <section style={agentLicenseShell}>
      <div style={agentLicenseHeader}>
        <div>
          <h2 style={agentLicenseTitle}>Buy Agent License</h2>
          <div style={agentBreadcrumb}>Dashboard <span>›</span> License Management <span>›</span> Buy Agent License</div>
        </div>
      </div>
      <div style={agentMetricGrid}>
        <AgentMetric tone="#2563eb" icon="♙" label="Total Purchased Agents" value={summary.totalPurchased || 0} />
        <AgentMetric tone="#10b981" icon="✓" label="Available Licenses" value={summary.activeLicenses || 0} />
        <AgentMetric tone="#f59e0b" icon="▰" label="Consumed Licenses" value={summary.consumedLicenses || 0} />
        <AgentMetric tone="#8b5cf6" icon="◷" label="Remaining Licenses" value={summary.remainingLicenses || 0} />
      </div>

      <div style={agentPanel}>
        <div style={agentPurchaseHeader}>
          <h3 style={agentPanelTitle}>▰ Purchase Agent License</h3>
          <button type="button" onClick={enableAgentAutoPay} disabled={autoPay || autoPayBusy} style={autoPay ? agentAutoPayEnabled : agentAutoPayButton}>
            {autoPayBusy ? 'Opening Razorpay...' : autoPay ? 'Auto Pay: Enabled' : 'Enable Auto Pay'}
          </button>
        </div>
        <div style={agentPurchaseGrid}>
          <label style={agentField}>Agent Quantity <span>*</span>
            <input type="number" min="1" value={agentQuantity} onChange={e => setAgentQuantity(e.target.value)} style={agentInput} />
          </label>
          <label style={agentField}>Plan Type <span>*</span>
            <select value={planType} onChange={e => setPlanType(e.target.value)} style={agentInput}>
              <option value="monthly">Monthly</option>
              <option value="yearly">Yearly</option>
            </select>
          </label>
          <div style={agentField}>Price / Agent
            <div style={agentReadonlyAmount}>{fmtInr(pricePerAgent)}</div>
          </div>
          <div style={agentAmountBox}>
            <span>Total Amount</span>
            <b>{fmtInr(amount)}</b>
          </div>
          <button type="button" onClick={openCheckout} style={agentProceedButton}>Proceed to Checkout →</button>
        </div>
        <div style={agentInfoLine}>ⓘ Partners purchase agent download permissions. Registered companies can consume these licenses from the partner allocation pool.</div>
      </div>

      <div style={agentPanel}>
        <div style={agentPanelHeader}>
          <h3 style={agentPanelTitle}>▧ Purchase History</h3>
          <button type="button" style={agentGhostButton}>View All</button>
        </div>
        <div style={agentTableWrap}>
          <table style={{ ...agentTable, minWidth: '100%' }}>
            <thead><tr>{['Invoice ID', 'Payment ID', 'Qty', 'Plan', 'Amount', 'Buy Date', 'Expiry Date', 'Status', 'Payment Status', 'Auto Pay'].map(h => <th key={h} style={agentTableHead}>{h}</th>)}</tr></thead>
            <tbody>
              {purchases.length ? visiblePurchases.map(item => (
                <tr key={item._id || item.invoiceId || item.paymentId}>
                  <td style={agentTableCell}>{item.invoiceId || '-'}</td>
                  <td style={agentTableCell}>{item.paymentId || '-'}</td>
                  <td style={agentTableCell}>{item.agentQuantity || 0}</td>
                  <td style={agentTableCell}>{titleCase(String(item.planType || 'monthly').replace('_', ' '))}</td>
                  <td style={agentTableCell}>{fmtInr(item.amountInr || 0)}</td>
                  <td style={agentTableCell}>{fmtDate(item.buyDate)}</td>
                  <td style={agentTableCell}>{fmtDate(item.expiryDate)}</td>
                  <td style={agentTableCell}><span style={item.status === 'active' ? agentStatusActive : agentStatusExpired}>{titleCase(item.status || 'inactive')}</span></td>
                  <td style={agentTableCell}><span style={agentPaidBadge}>Paid</span></td>
                  <td style={agentTableCell}>
                    <div style={agentAutoPayCell}>
                      <span style={item.autoPay ? agentStatusActive : agentStatusExpired}>{item.autoPay ? 'Enabled' : 'Disabled'}</span>
                      {item.autoPay ? <button type="button" onClick={() => disablePurchaseAutoPay(item)} style={agentDisableAutoPayButton}>Disable</button> : null}
                    </div>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan="10" style={{ ...agentTableCell, textAlign: 'center', color: '#94a3b8' }}>No agent license purchases yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {purchases.length > purchasePageSize && (
          <div style={agentTablePager}>
            <button type="button" disabled={currentPurchasePage === 0} onClick={() => setPurchasePage(prev => Math.max(prev - 1, 0))} style={agentTablePagerButton(currentPurchasePage === 0)}>Prev</button>
            <button type="button" disabled={currentPurchasePage >= purchasePageCount - 1} onClick={() => setPurchasePage(prev => Math.min(prev + 1, purchasePageCount - 1))} style={agentTablePagerButton(currentPurchasePage >= purchasePageCount - 1)}>Next</button>
          </div>
        )}
      </div>
    </section>
  );
}

function AgentMetric({ tone, icon, label, value }) {
  return (
    <div style={{ ...agentMetricCard, borderColor: `${tone}55`, background: `linear-gradient(135deg, ${tone}1f, rgba(7,17,31,.92))` }}>
      <span style={{ ...agentMetricIcon, background: `${tone}22`, color: tone }}>{icon}</span>
      <div style={agentMetricText}>
        <small style={{ color: tone }}>{label}</small>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function CompanyLicenseAllocationPanel() {
  const [companies, setCompanies] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api.get('/partner/companies')
      .then(({ data }) => setCompanies(data || []))
      .catch(() => setCompanies([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={agentAllocationCard}>
      <div style={agentAllocationHeader}>
        <span style={agentAllocationIcon}>▦</span>
        <div>
          <h3 style={agentAllocationTitle}>Company License Allocation</h3>
          <p style={agentAllocationSubtitle}>License allocation and status by company</p>
        </div>
      </div>
      <div style={agentAllocationTableWrap}>
        <table style={agentTable}>
          <thead><tr>{['Company Name', 'Company ID', 'Total Agent', 'Active', 'Inactive'].map(h => <th key={h} style={agentTableHead}>{h}</th>)}</tr></thead>
          <tbody>
            {loading ? (
              <tr><td colSpan="5" style={{ ...agentTableCell, textAlign: 'center', color: '#94a3b8' }}>Loading companies...</td></tr>
            ) : companies.length ? companies.map(company => {
              const companyId = String(company._id || '').slice(-8).toUpperCase();
              const totalAgents = Number(company.totalAgents || 0);
              const activeAgents = Number(company.activeAgents || 0);
              const inactiveAgents = Math.max(Number(company.inactiveAgents || 0), totalAgents - activeAgents);
              return (
                <tr key={company._id}>
                  <td style={agentTableCell}><b>{company.name}</b></td>
                  <td style={agentTableCell}>{companyId || '-'}</td>
                  <td style={agentTableCell}>{totalAgents}</td>
                  <td style={agentTableCell}><span style={agentStatusActive}>{activeAgents}</span></td>
                  <td style={agentTableCell}><span style={agentStatusExpired}>{inactiveAgents}</span></td>
                </tr>
              );
            }) : (
              <tr><td colSpan="5" style={{ ...agentTableCell, textAlign: 'center', color: '#94a3b8' }}>No registered companies yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {!loading && <div style={agentAllocationFooter}>ⓘ Showing {companies.length} of {companies.length} compan{companies.length === 1 ? 'y' : 'ies'}</div>}
    </div>
  );
}

function AgentSectionPanel({ stats }) {
  const partner = stats?.partner || {};
  const summary = stats?.agentLicenseSummary || partner.agentLicenseSummary || {};
  return (
    <section style={agentTabShell}>
      <div style={agentTabMetricGrid}>
        <AgentTabMetric tone="#2563eb" icon="♙" label="Total Purchased Agents" value={summary.totalPurchased || 0} sub="Total agents purchased" />
        <AgentTabMetric tone="#10b981" icon="✓" label="Available Licenses" value={summary.activeLicenses || 0} sub="Licenses available to use" />
        <AgentTabMetric tone="#f59e0b" icon="▰" label="Consumed Licenses" value={summary.consumedLicenses || 0} sub="Licenses already used" />
        <AgentTabMetric tone="#8b5cf6" icon="◷" label="Remaining Licenses" value={summary.remainingLicenses || 0} sub="Licenses remaining" />
      </div>
      <CompanyLicenseAllocationPanel />
    </section>
  );
}

function AgentTabMetric({ tone, icon, label, value, sub }) {
  return (
    <div style={{ ...agentTabMetricCard, borderColor: `${tone}66`, background: `linear-gradient(135deg, ${tone}20, rgba(7,17,31,.94))` }}>
      <span style={{ ...agentTabMetricIcon, background: `${tone}22`, color: tone }}>{icon}</span>
      <div style={agentTabMetricBody}>
        <small style={{ color: tone }}>{label}</small>
        <strong style={agentTabMetricValue}>{value}</strong>
        <p style={agentTabMetricSub}>{sub}</p>
      </div>
    </div>
  );
}

function SupportInput({ label, value, onChange, type = 'text' }) {
  return (
    <label style={profilePasswordLabel}>
      {label}
      <input type={type} value={value} onChange={e => onChange(e.target.value)} style={profileInput} />
    </label>
  );
}

function SupportTextarea({ label, value, onChange }) {
  return (
    <label style={profilePasswordLabel}>
      {label}
      <textarea value={value} onChange={e => onChange(e.target.value)} rows={5} style={supportTextarea} />
    </label>
  );
}

function SupportSelect({ label, value, onChange, options }) {
  return (
    <label style={profilePasswordLabel}>
      {label}
      <select value={value} onChange={e => onChange(e.target.value)} style={profileInput}>
        {options.map(option => <option key={option} value={option}>{option}</option>)}
      </select>
    </label>
  );
}

function SupportFile({ label, value, onChange, accept }) {
  const handleFile = file => {
    if (!file) return onChange('', '');
    const reader = new FileReader();
    reader.onload = () => onChange(file.name, String(reader.result || ''));
    reader.readAsDataURL(file);
  };
  return (
    <label style={profilePasswordLabel}>
      {label}
      <input type="file" accept={accept} onChange={e => handleFile(e.target.files?.[0])} style={supportFileInput} />
      <span style={fieldHelp}>{value || 'No file selected'}</span>
    </label>
  );
}

function ProfileSectionPanel({ section, profile, setProfile, saveLocal, errors = {}, uploadedDocs = {}, uploadInputs, openUpload, handleUpload, uploadingDoc = '', user, onPartnerSaved, onNavigateSection, navigate, tfaStatus, passwordCard, twoFactorCard, notifications, markNotificationsRead, stats, dashboardRefreshKey = 0 }) {
  const [notifFilter, setNotifFilter] = useState('all');
  const partner = stats?.partner || {};
  const resource = stats?.resourceRequest || partner?.resourceRequest || {};
  const plan = partner?.plan || {};
  const capabilities = stats?.capabilities || partner?.capabilities || {};
  const inactiveAgents = Math.max((stats?.agentCount || 0) - (stats?.activeAgents || 0), 0);
  const kycStatus = partner?.profile?.kycStatus || 'not_submitted';
  const payoutReady = Boolean(partner?.partner_linked_account_id || partner?.profile?.accountNumber || partner?.profile?.bankAccount);
  const config = {
    dashboard: {
      title: 'Welcome, Partner Admin',
      custom: (
        <>
          <DashboardWelcomeBanner partner={partner} profile={profile} user={user} stats={stats} />
          <DashboardSectionInfo stats={stats} partner={partner} profile={profile} tfaStatus={tfaStatus} navigate={onNavigateSection} />
        </>
      ),
      lines: [
        ['Total Companies', stats?.companyCount || 0],
        ['Active Companies', stats?.activeCompanies || 0],
        ['Total Agents', stats?.agentCount || 0],
        ['Monthly Revenue', fmtInr(stats?.monthlyRevenue || 0)],
      ],
      action: 'Open Dashboard',
      href: '/',
    },
    agents: {
      title: 'Agent',
      custom: <AgentSectionPanel stats={stats} />,
      lines: [
        ['Total Agents', stats?.agentCount || 0],
        ['Active Agents', stats?.activeAgents || 0],
        ['Inactive Agents', inactiveAgents],
        ['Offline Agents', stats?.offlineAgents || 0],
      ],
      href: '/partner-agents',
    },
    subscription: {
      title: 'Subscription & Payments',
      custom: <><ApiNotice endpoint="GET /partner/dashboard" /><div style={embeddedDashboard}><PartnerDashboardPage key={`sub-${dashboardRefreshKey}`} embedded viewOverride="subscription" /></div></>,
      lines: [['Plan', stats?.planName || 'Business Plan'], ['Valid Till', fmtDate(stats?.planExpires)], ['Monthly Revenue', fmtInr(stats?.monthlyRevenue || 0)], ['Pending Amount', fmtInr(stats?.pendingInvoices || 0)]],
      action: 'Open Subscription',
      href: '/partner-subscription',
    },
    requests: {
      title: 'Buy Agent License',
      custom: <>
        <BuyAgentLicensePanel user={user} stats={stats} onPartnerSaved={onPartnerSaved} />
      </>,
      lines: [['Open Requests', 0], ['Pending Approval', 0], ['Last Request', '-']],
      action: null,
      href: null,
    },
    company: {
      title: 'Company Information',
      fields: ['companyName', 'gstNumber', 'panNumber'],
      lines: [
        ['Company Name', profile.companyName],
        ['Slug', partner.slug || '-'],
        ['GST Number', profile.gstNumber || '-'],
        ['PAN Number', profile.panNumber || '-'],
        ['Status', titleCase(partner.status || 'approved')],
        ['Create Company', capabilities.createCompany ? 'Allowed' : 'Waiting for Super Admin Approval'],
      ],
    },
    kyc: {
      title: 'KYC Documents',
      lines: [
        ['KYC Status', titleCase(kycStatus)],
        ['GST Certificate', kycDisplayName(uploadedDocs['GST Certificate']?.name || partner?.profile?.kycDocuments?.gstCertificateName, partner?.profile?.gstVerified)],
        ['PAN Card', kycDisplayName(uploadedDocs['PAN Card']?.name || partner?.profile?.kycDocuments?.panCardName, partner?.profile?.panVerified)],
        ['Business Registration', kycDisplayName(uploadedDocs['Business Registration']?.name || partner?.profile?.kycDocuments?.businessRegistrationName, partner?.profile?.businessVerified)],
      ],
      action: 'Save KYC Details',
    },
    bank: {
      title: 'Bank & Payout Details',
      api: 'PATCH /partner/profile',
      fields: ['accountHolderName', 'bankName', 'accountNumber', 'confirmAccountNumber', 'ifscCode', 'branchName', 'partnerLinkedAccountId'],
      lines: [
        ['Account Holder Name', profile.accountHolderName || '-'],
        ['Bank Name', profile.bankName || '-'],
        ['Account Number', maskAccount(profile.accountNumber || profile.bankAccount)],
        ['IFSC Code', profile.ifscCode || '-'],
        ['Branch Name', profile.branchName || '-'],
        ['Partner Linked Account ID', profile.partnerLinkedAccountId || '-'],
        ['Payout Status', payoutReady ? 'Ready' : 'Pending Setup'],
        ['Razorpay', partner?.profile?.razorpayKeyId ? 'Connected' : 'Not Connected'],
      ],
    },
    users: {
      title: 'Users & Permissions',
      lines: [
        ['Partner Admin', profile.fullName],
        ['Admin Email', profile.email],
        ['Role', profile.designation],
        ['Managed Users', stats?.users || 0],
        ['Access Level', partner.status === 'suspended' ? 'Suspended' : 'Full Partner Access'],
      ],
    },
    notifications: {
      title: 'Notifications',
      lines: [
        ['Email Notifications', profile.notifications ? 'Enabled' : 'Disabled'],
        ['Billing Alerts', plan.paymentStatus === 'unpaid' ? 'Pending Payment Alert Active' : 'Enabled'],
        ['Security Alerts', 'Enabled'],
        ['Resource Request Alerts', resource.status && resource.status !== 'none' ? titleCase(resource.status) : 'No Active Request'],
      ],
      action: profile.notifications ? 'Disable Notifications' : 'Enable Notifications',
    },
    security: {
      title: 'Password & 2FA',
      custom: (
        <div style={{ display: 'grid', gap: 16 }}>
          <section style={profileCard}>
            <h2 style={profileSectionTitle}>Password & 2FA</h2>
            <p style={profileSectionHint}>Manage your account password and two-factor authentication settings.</p>
          </section>
          {passwordCard}
          {twoFactorCard}
        </div>
      ),
    },
    activity: {
      title: 'Activity Log',
      custom: <ActivityLogPanel fallbackLines={[
        ['Partner Created', fmtDate(partner.createdAt)],
        ['Last Partner Update', partner.updatedAt ? new Date(partner.updatedAt).toLocaleString('en-IN') : '-'],
        ['Resource Requested', fmtDate(resource.requestedAt)],
        ['Resource Reviewed', fmtDate(resource.reviewedAt)],
        ['Plan Quoted', fmtDate(plan.quote?.quotedAt)],
      ]} />,
      lines: [
        ['Partner Created', fmtDate(partner.createdAt)],
        ['Last Partner Update', partner.updatedAt ? new Date(partner.updatedAt).toLocaleString('en-IN') : '-'],
        ['Resource Requested', fmtDate(resource.requestedAt)],
        ['Resource Reviewed', fmtDate(resource.reviewedAt)],
        ['Plan Quoted', fmtDate(plan.quote?.quotedAt)],
      ],
    },
    support: {
      title: 'Support',
      custom: <SupportTicketForm partner={partner} profile={profile} />,
    },
  }[section];

  if (!config) return null;
  if (config.custom) return config.custom;
  if (section === 'notifications') {
    const paymentAmount = Number(partner?.plan?.quote?.amountInr || 0);
    const agreementPdf = partner?.agreementFileName || '';
    const rawItems = Array.isArray(notifications) ? notifications : (Array.isArray(notifications?.items) ? notifications.items : []);
    const displayItems = rawItems.filter(item => {
      if (!item) return false;
      const src = String(item.source || '').toLowerCase();
      const type = String(item.type || '').toLowerCase();
      if (notifFilter === 'unread') return !item.read;
      if (notifFilter === 'soc_manager') return src === 'soc_manager' || type.includes('soc');
      if (notifFilter === 'superadmin') return src === 'superadmin' || type.includes('super');
      if (notifFilter === 'partner') return src === 'partner' || type.includes('partner');
      return true;
    });

    const handleNotificationClick = async (item, e) => {
      if (e) {
        e.preventDefault();
        e.stopPropagation();
      }
      if (!item) return;

      if (!item.read) {
        try {
          await api.patch('/partner/notifications/read', { ids: [item._id] });
        } catch { }
        if (markNotificationsRead) markNotificationsRead();
      }

      let target = item.targetUrl || item.url || item.link || item.meta?.targetUrl || item.meta?.url || item.meta?.link || item.meta?.href;

      if (!target) {
        const type = String(item.type || '').toLowerCase();
        const title = String(item.title || '').toLowerCase();
        const msg = String(item.message || '').toLowerCase();

        if (type.includes('resource') || type.includes('request') || type.includes('license') || title.includes('resource') || title.includes('request') || msg.includes('resource') || msg.includes('request')) {
          target = 'requests';
        } else if (type.includes('subscription') || type.includes('payment') || type.includes('quote') || type.includes('plan') || title.includes('plan') || title.includes('subscri') || title.includes('quote') || msg.includes('payment')) {
          target = 'subscription';
        } else if (type.includes('settings') || type.includes('profile') || type.includes('approved') || type.includes('rejected') || title.includes('profile') || title.includes('settings') || title.includes('detail') || msg.includes('details') || msg.includes('updated by super admin')) {
          target = 'profile';
        } else if (type.includes('company') || title.includes('company') || msg.includes('company')) {
          target = '/partner/companies';
        } else if (type.includes('user') || type.includes('manager') || title.includes('user') || msg.includes('user')) {
          target = '/partner/users';
        } else if (type.includes('security') || title.includes('security') || msg.includes('security')) {
          target = 'security';
        } else if (type.includes('alert') || type.includes('ticket') || type.includes('incident') || title.includes('alert')) {
          target = '/alerts';
        } else {
          target = 'profile';
        }
      }

      if (['requests', 'subscription', 'security', 'profile', 'company', 'kyc', 'users', 'activity', 'support'].includes(target)) {
        if (onNavigateSection) {
          onNavigateSection(target);
          return;
        }
      }

      if (target.includes('section=')) {
        const sectionId = new URLSearchParams(target.split('?')[1] || '').get('section');
        if (sectionId && onNavigateSection) {
          onNavigateSection(sectionId);
          return;
        }
      }

      if (navigate) {
        navigate(target);
      } else {
        window.location.href = target;
      }
    };

    return (
      <section style={profileCard}>
        <div style={profileCardHeader}>
          <h2 style={profileSectionTitle}>Notifications Feed</h2>
          <button type="button" onClick={markNotificationsRead} style={smallEditButton}>Mark All Read</button>
        </div>
        <div style={{ display: 'grid', gap: 4, marginBottom: 14 }}>
          <ProfileLine label="Payment Amount" value={paymentAmount ? fmtInr(paymentAmount) : 'Pending'} />
          <div style={profileLine}>
            <span>Agreement PDF</span>
            <b style={pdfFileNameChip} title={agreementPdf || 'Not uploaded'}>{agreementPdf || 'Not uploaded'}</b>
          </div>
        </div>
        <div style={{
          display: 'flex', flexDirection: 'column', gap: 10,
          maxHeight: 450, overflowY: 'auto', paddingRight: 8,
          scrollbarWidth: 'thin', scrollbarColor: '#3b82f6 #0f172a'
        }}>
          {displayItems.length ? displayItems.map(item => (
            <div
              key={item._id || item.createdAt}
              onClick={(e) => handleNotificationClick(item, e)}
              style={{
                ...(item.read ? notificationCardRead : notificationCardUnread),
                cursor: 'pointer',
                transition: 'all .2s ease',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '14px 16px',
                borderRadius: '10px'
              }}
              onMouseEnter={e => e.currentTarget.style.borderColor = '#3b82f6'}
              onMouseLeave={e => e.currentTarget.style.borderColor = item.read ? '#1e3a5f' : '#2563eb'}
            >
              <div style={{ minWidth: 0, flex: 1, paddingRight: 14 }}>
                <strong style={{ color: '#f1f5f9', fontSize: 13, display: 'block', marginBottom: 4 }}>{item.title}</strong>
                <p style={{ margin: '0 0 6px 0', color: '#94a3b8', fontSize: 12, lineHeight: 1.4 }}>{item.message || '-'}</p>
                <small style={{ color: '#64748b', fontSize: 11 }}>{item.createdAt ? new Date(item.createdAt).toLocaleString('en-IN') : ''}</small>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
                {!item.read && <span style={unreadDot}>New</span>}
                <button
                  type="button"
                  onClick={(e) => handleNotificationClick(item, e)}
                  style={{
                    padding: '7px 14px',
                    borderRadius: '6px',
                    border: '1px solid #3b82f6',
                    background: 'rgba(59, 130, 246, 0.2)',
                    color: '#60a5fa',
                    fontSize: '12px',
                    fontWeight: 800,
                    cursor: 'pointer',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '4px',
                    transition: 'all .15s ease'
                  }}
                  onMouseEnter={e => {
                    e.currentTarget.style.background = '#2563eb';
                    e.currentTarget.style.color = '#ffffff';
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.background = 'rgba(59, 130, 246, 0.2)';
                    e.currentTarget.style.color = '#60a5fa';
                  }}
                >
                  View →
                </button>
              </div>
            </div>
          )) : (
            <div style={profileOk}>No notifications yet.</div>
          )}
        </div>
      </section>
    );
  }

  const hasFields = !!config.fields;
  const handleAction = () => {
    if (config.href) {
      window.location.href = config.href;
      return;
    }
    if (section === 'notifications') {
      setProfile(prev => ({ ...prev, notifications: !prev.notifications }));
      saveLocal(config.title);
      return;
    }
    saveLocal(config.title);
  };

  return (
    <section style={profileCard}>
      <div style={profileCardHeader}>
        <h2 style={profileSectionTitle}>{config.title}</h2>
        {config.action && <button type="button" onClick={handleAction} style={smallEditButton}>{config.action}</button>}
      </div>
      {config.api && <ApiNotice endpoint={config.api} />}
      {hasFields ? (
        <>
          <EditableGrid profile={profile} setProfile={setProfile} fields={config.fields} errors={errors} />
          <button type="button" onClick={() => saveLocal(config.title)} style={{ ...profilePrimaryButton, marginTop: 14 }}>Save Changes</button>
        </>
      ) : (
        <div style={{ display: 'grid', gap: 4 }}>
          {config.lines.map(([label, value]) => <ProfileLine key={label} label={label} value={value} />)}
        </div>
      )}
      {section === 'kyc' && (() => {
        const kycPathMap = {
          'GST Certificate': 'gstCertificate',
          'PAN Card': 'panCard',
          'Business Registration': 'businessRegistration',
        };
        const serverDocs = partner?.profile?.kycDocuments || {};
        const getFileUrl = (item) => {
          if (uploadedDocs[item]?.fileUrl) return uploadedDocs[item].fileUrl;
          const key = `${kycPathMap[item]}FilePath`;
          if (serverDocs[key]) {
            const base = (import.meta.env.VITE_API_URL || 'http://localhost:5000/api').replace(/\/api\/?$/, '');
            return `${base}/uploads/${serverDocs[key]}`;
          }
          return uploadedDocs[item]?.previewUrl || '';
        };
        return (
          <>
            {errors.documents && <div style={{ ...profileWarn, marginTop: 14 }}>{errors.documents}</div>}
            <div style={docCardGrid}>
              {kycDocLabels.map(item => {
                const doc = uploadedDocs[item];
                const isUploading = uploadingDoc === item;
                const fileName = doc?.name || (
                  item === 'GST Certificate' ? serverDocs.gstCertificateName
                    : item === 'PAN Card' ? serverDocs.panCardName
                      : serverDocs.businessRegistrationName
                ) || '';
                const verified = item === 'GST Certificate'
                  ? partner?.profile?.gstVerified
                  : item === 'PAN Card'
                    ? partner?.profile?.panVerified
                    : partner?.profile?.businessVerified;
                const fileUrl = getFileUrl(item);
                return (
                  <div
                    key={`${item}-card`}
                    role="button"
                    tabIndex={0}
                    aria-busy={isUploading}
                    onClick={() => { if (!isUploading) openUpload(item); }}
                    onKeyDown={event => {
                      if (!isUploading && (event.key === 'Enter' || event.key === ' ')) {
                        event.preventDefault();
                        openUpload(item);
                      }
                    }}
                    style={{ ...docMiniCardButton, opacity: isUploading ? .76 : 1, cursor: isUploading ? 'wait' : 'pointer' }}>
                    {isUploading ? (
                      <span style={docUploadSpinner} />
                    ) : doc?.previewUrl ? (
                      <img src={doc.previewUrl} alt={`${item} preview`} style={docMiniImage} />
                    ) : (
                      <span style={docMiniIcon}>▧</span>
                    )}
                    <div style={docMiniText}>
                      <strong style={docMiniTitle}>{item}</strong>
                      <small style={docMiniMeta}>{isUploading ? 'Uploading...' : fileName ? displayFileName(fileName) : verified ? 'Verified' : 'Not uploaded'}</small>
                      {!isUploading && fileUrl && (
                        <button
                          type="button"
                          onClick={event => { event.stopPropagation(); window.open(fileUrl, '_blank'); }}
                          style={{ marginTop: 6, padding: '3px 10px', fontSize: 11, borderRadius: 5, border: '1px solid rgba(99,102,241,0.5)', background: 'rgba(99,102,241,0.1)', color: '#a78bfa', cursor: 'pointer', fontWeight: 600 }}>
                          🔗 Open
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
            {kycDocLabels.map(item => (
              <input
                key={`${item}-input`}
                ref={node => { uploadInputs.current[item] = node; }}
                type="file"
                accept=".pdf,.png,.jpg,.jpeg,application/pdf,image/png,image/jpeg"
                onChange={e => { handleUpload(item, e.target.files?.[0]); e.target.value = ''; }}
                style={{ display: 'none' }}
              />
            ))}
          </>
        );
      })()}
      {section === 'notifications' && (
        <label style={toggleRow}>
          <span>Email Notifications</span>
          <input type="checkbox" checked={profile.notifications} onChange={e => setProfile(prev => ({ ...prev, notifications: e.target.checked }))} />
        </label>
      )}
    </section>
  );
}

function SummaryTile({ icon, tone, label, value, sub }) {
  return (
    <div style={summaryTile}>
      <span style={{ ...summaryIcon, background: `${tone}14`, color: tone }}>{icon}</span>
      <div>
        <small>{label}</small>
        <strong>{value}</strong>
        <p>{sub}</p>
      </div>
    </div>
  );
}

function DashboardWelcomeBanner({ partner, profile, user, stats }) {
  const adminName = profile?.fullName || user?.name || user?.email || 'Partner Admin';
  const companyName = profile?.companyName || partner?.name || stats?.partner?.name || 'your company';
  return (
    <section style={dashboardWelcomeBanner}>
      <div>
        <small style={dashboardWelcomeEyebrow}>Partner Dashboard</small>
        <h1 style={dashboardWelcomeTitle}>Welcome, {adminName}</h1>
        <p style={dashboardWelcomeText}>You are managing {companyName}. Use this dashboard to review licenses, payments, KYC, users, activity, and support updates.</p>
      </div>
      <div style={dashboardWelcomeBadge}>{companyName}</div>
    </section>
  );
}

function DashboardSectionInfo({ stats, partner, profile, tfaStatus, navigate }) {
  const capabilities = stats?.capabilities || partner?.capabilities || {};
  const kycStatus = partner?.profile?.kycStatus || 'not_submitted';
  const bankReady = Boolean(partner?.partner_linked_account_id || partner?.profile?.accountNumber || partner?.profile?.bankAccount);
  const agentSummary = stats?.agentLicenseSummary || partner?.agentLicenseSummary || {};
  const inactiveAgents = Math.max((stats?.agentCount || 0) - (stats?.activeAgents || 0), 0);
  const planActive = Boolean(partner?.plan?.isActive || stats?.planExpires);
  const agentLicenseEnabled = Number(agentSummary.totalPurchased || 0) > 0;
  const kycEnabled = ['approved', 'verified'].includes(String(kycStatus || '').toLowerCase());
  const notificationsEnabled = Boolean(profile?.notifications);
  const twoFaEnabled = Boolean(tfaStatus?.enabled);
  const usersEnabled = Boolean(capabilities.createCompany || stats?.users);
  const cards = [
    { id: 'requests', icon: '▥', tone: '#60a5fa', title: 'Buy Agent License', status: agentLicenseEnabled ? 'Enabled' : 'Disabled', value: `${agentSummary.remainingLicenses || 0} remaining`, sub: `${agentSummary.totalPurchased || 0} total purchased` },
    { id: 'subscription', icon: '▤', tone: '#16a34a', title: 'Subscription & Payments', status: planActive ? 'Enabled' : 'Disabled', value: stats?.planName || 'Business Plan', sub: planActive ? `Valid till ${fmtDate(stats?.planExpires || partner?.plan?.expiresAt)}` : 'No active subscription' },
    { id: 'profile', icon: '♙', tone: '#38bdf8', title: 'My Profile', status: profile?.email ? 'Enabled' : 'Disabled', value: profile?.fullName || partner?.name || 'Partner Admin', sub: profile?.email || partner?.adminEmail || '-' },
    { id: 'company', icon: '▥', tone: '#f59e0b', title: 'Company Information', status: profile?.companyName ? 'Enabled' : 'Disabled', value: profile?.companyName || partner?.name || '-', sub: `${stats?.companyCount || 0} companies` },
    { id: 'kyc', icon: '▧', tone: '#a78bfa', title: 'KYC Documents', status: kycEnabled ? 'Enabled' : 'Disabled', value: titleCase(kycStatus), sub: kycEnabled ? 'Verified' : 'Action required' },
    { id: 'bank', icon: '⌂', tone: '#22c55e', title: 'Bank & Payout Details', status: bankReady ? 'Enabled' : 'Disabled', value: bankReady ? 'Submitted' : 'Pending', sub: bankReady ? 'Payout ready' : 'Add bank details' },
    { id: 'users', icon: '♧', tone: '#06b6d4', title: 'Users & Permissions', status: usersEnabled ? 'Enabled' : 'Disabled', value: capabilities.createCompany ? 'Allowed' : 'Limited', sub: 'Manage team access' },
    { id: 'notifications', icon: '◇', tone: '#f97316', title: 'Notifications', status: notificationsEnabled ? 'Enabled' : 'Disabled', value: notificationsEnabled ? 'Enabled' : 'Disabled', sub: 'Alerts and updates' },
    { id: 'security', icon: '⬡', tone: '#ef4444', title: 'Security', status: twoFaEnabled ? 'Enabled' : 'Disabled', value: twoFaEnabled ? '2FA Enabled' : '2FA Disabled', sub: 'Password & 2FA' },
    { id: 'activity', icon: '◷', tone: '#84cc16', title: 'Activity Log', status: 'Enabled', value: partner?.updatedAt ? new Date(partner.updatedAt).toLocaleString('en-IN') : '-', sub: 'Recent account activity' },
    { id: 'support', icon: '?', tone: '#cbd5e1', title: 'Support', status: 'Enabled', value: 'Create tickets', sub: 'Help and issue tracking' },
  ];

  return (
    <section style={dashboardInfoPanel}>
      <h2 style={profileSectionTitle}>Dashboard Information</h2>
      <div style={dashboardInfoGrid}>
        {cards.map(card => {
          const enabled = card.status === 'Enabled';
          return (
            <div
              key={card.title}
              role="button"
              tabIndex={0}
              onClick={() => navigate?.(card.id)}
              onKeyDown={event => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  navigate?.(card.id);
                }
              }}
              style={{ ...dashboardInfoCard, cursor: 'pointer' }}>
              <div style={{ minWidth: 0 }}>
                <small style={dashboardInfoLabel}>{card.title}</small>
                <span style={enabled ? dashboardStatusEnabled : dashboardStatusDisabled}>{card.status}</span>
                <strong style={dashboardInfoValue}>{card.value}</strong>
                <p style={dashboardInfoSub}>{card.sub}</p>
              </div>
              <span style={{ ...dashboardInfoIcon, background: `${card.tone}18`, color: card.tone }}>{card.icon}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function initials(value = '') {
  return String(value).trim().split(/\s+/).slice(0, 2).map(part => part[0]?.toUpperCase()).join('') || 'A';
}

function maskAccount(value = '') {
  const account = String(value || '');
  if (!account) return '-';
  if (account.length <= 4) return account;
  return `${'•'.repeat(Math.max(account.length - 4, 0))}${account.slice(-4)}`;
}

const partnerProfilePage = { minHeight: '100%', margin: -32, padding: 24, display: 'grid', gridTemplateColumns: '240px minmax(0, 1fr)', gap: 18, background: 'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)', color: '#e2e8f0' };
const profileContentMain = { display: 'grid', gap: 18, minWidth: 0 };
const profileDashboardMain = { display: 'block', minWidth: 0, position: 'relative', zIndex: 3, overflow: 'visible' };
const partnerProfileSidebar = { background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 8, padding: 12, display: 'grid', gap: 6, alignContent: 'start', boxShadow: '0 10px 24px rgba(0,0,0,.24)' };
const profileNav = { height: 42, border: 'none', borderRadius: 7, background: 'transparent', color: '#c6d4e5', display: 'flex', alignItems: 'center', gap: 12, padding: '0 12px', fontSize: 13, fontWeight: 850, cursor: 'pointer', textAlign: 'left' };
const profileNavActive = { ...profileNav, background: 'linear-gradient(90deg,#4259ff,#6847ea)', color: '#fff' };
const profileHero = { background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 8, padding: 20, boxShadow: '0 10px 24px rgba(0,0,0,.24)' };
const profileHeroBody = { display: 'flex', gap: 24, alignItems: 'center' };
const profileAvatarWrap = { position: 'relative', width: 86, height: 86, flexShrink: 0 };
const profileAvatar = { width: 86, height: 86, borderRadius: '50%', background: '#0f2754', color: '#fff', display: 'grid', placeItems: 'center', fontSize: 34, fontWeight: 950, overflow: 'hidden' };
const profileAvatarImage = { width: '100%', height: '100%', objectFit: 'cover', display: 'block' };
const profileCamera = { position: 'absolute', right: 0, bottom: 3, width: 26, height: 26, borderRadius: 8, background: '#07111f', color: '#60a5fa', border: '1px solid #1e3a5f', display: 'grid', placeItems: 'center', fontSize: 12 };
const profileSectionTitle = { margin: '0 0 16px', color: '#e0f2fe', fontSize: 16, fontWeight: 950 };
const profileSectionHint = { margin: '-8px 0 16px', color: '#94a3b8', fontSize: 12, fontWeight: 750 };
const twoFactorCard = { background: 'linear-gradient(180deg, rgba(30,34,54,.96), rgba(23,27,45,.98))', border: '1px solid #1e3a5f', borderTop: '3px solid #00d98e', borderRadius: 8, padding: 28, boxShadow: '0 10px 24px rgba(0,0,0,.24)' };
const twoFactorTitle = { margin: '0 0 26px', color: '#f1f5f9', fontSize: 20, fontWeight: 950, display: 'flex', alignItems: 'center', gap: 10 };
const twoFactorWarnBox = { border: '1px solid rgba(239,68,68,.35)', borderRadius: 12, background: 'rgba(87,23,53,.34)', padding: '22px 24px', marginBottom: 20 };
const twoFactorWarnTitle = { margin: '0 0 10px', color: '#f8fafc', fontSize: 18, fontWeight: 950 };
const twoFactorText = { margin: 0, color: '#a5a7c8', fontSize: 16, lineHeight: 1.65, fontWeight: 650 };
const twoFactorPrimaryButton = { width: '100%', minHeight: 52, border: 0, borderRadius: 10, background: 'linear-gradient(135deg,#00d176,#0ea5c8)', color: '#f8fafc', fontSize: 16, fontWeight: 950, cursor: 'pointer' };
const twoFactorSetupGrid = { display: 'grid', gap: 18 };
const twoFactorQr = { width: 210, height: 210, borderRadius: 12, background: '#fff', padding: 10, objectFit: 'contain' };
const twoFactorKeyBox = { borderRadius: 10, background: 'rgba(45,49,73,.74)', padding: '16px 20px', display: 'grid', gap: 8 };
const twoFactorCodeLabel = { display: 'grid', gap: 10, color: '#7f83aa', textTransform: 'uppercase', letterSpacing: 1.5, fontSize: 12, fontWeight: 950 };
const twoFactorCodeInput = { height: 52, border: '1px solid #444862', borderRadius: 9, background: 'rgba(39,43,63,.86)', color: '#e5e7eb', padding: '0 20px', fontSize: 20, letterSpacing: 3, outline: 'none' };
const twoFactorActions = { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 };
const twoFactorEnableButton = { minHeight: 52, border: 0, borderRadius: 10, background: '#00d176', color: '#fff', fontSize: 16, fontWeight: 950, cursor: 'pointer' };
const twoFactorCancelButton = { minHeight: 52, border: '1px solid #33384f', borderRadius: 10, background: 'transparent', color: '#a5a7c8', fontSize: 16, fontWeight: 950, cursor: 'pointer' };
const twoFactorOkBox = { border: '1px solid rgba(16,185,129,.35)', borderRadius: 12, background: 'rgba(16,185,129,.12)', padding: '20px 22px' };
const twoFactorOkTitle = { margin: '0 0 8px', color: '#34d399', fontSize: 18, fontWeight: 950 };
const twoFactorDangerButton = { minHeight: 48, border: '1px solid rgba(239,68,68,.45)', borderRadius: 9, background: 'rgba(239,68,68,.12)', color: '#fca5a5', padding: '0 18px', fontSize: 14, fontWeight: 950, cursor: 'pointer' };
const profileNameRow = { display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8, fontSize: 17 };
const activeBadge = { background: '#dcfce7', color: '#16a34a', borderRadius: 5, padding: '5px 8px', fontSize: 11, fontWeight: 950 };
const editProfileButton = { alignSelf: 'flex-start', height: 36, border: '1px solid #1e3a5f', borderRadius: 5, background: '#07111f', color: '#93c5fd', padding: '0 12px', fontSize: 12, fontWeight: 900, cursor: 'pointer' };
const profileTwoCol = { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 };
const profileOneCol = { display: 'grid', gridTemplateColumns: '1fr', gap: 18 };
const profileCard = { background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 8, padding: 20, boxShadow: '0 10px 24px rgba(0,0,0,.24)' };
const profileCardHeader = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 };
const smallEditButton = { height: 32, border: '1px solid #1e3a5f', borderRadius: 5, background: '#07111f', color: '#93c5fd', padding: '0 10px', fontSize: 12, fontWeight: 900 };
const profileLine = { display: 'grid', gridTemplateColumns: '190px 1fr', gap: 16, minHeight: 30, alignItems: 'center', color: '#94a3b8', fontSize: 13 };
const profileTableHead = { textAlign: 'left', padding: '10px 12px', color: '#93c5fd', background: '#07111f', borderBottom: '1px solid #1e3a5f', fontSize: 11, fontWeight: 950 };
const profileTableCell = { padding: '10px 12px', color: '#e2e8f0', borderBottom: '1px solid #1e3a5f', fontSize: 12, verticalAlign: 'top' };
const pdfFileNameChip = { display: 'block', maxWidth: '100%', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#cbd5e1' };
const profileSelectLabel = { display: 'grid', gridTemplateColumns: '190px 1fr', gap: 16, alignItems: 'center', color: '#94a3b8', fontSize: 13, marginTop: 10 };
const profileSelect = { height: 38, border: '1px solid #1e3a5f', borderRadius: 6, background: '#07111f', color: '#e2e8f0', padding: '0 10px' };
const profilePasswordLabel = { display: 'grid', gap: 7, color: '#93c5fd', fontSize: 12, fontWeight: 850 };
const profileInput = { height: 40, border: '1px solid #1e3a5f', borderRadius: 6, background: '#07111f', color: '#e2e8f0', padding: '0 12px' };
const profileInputError = { ...profileInput, border: '1px solid #ef4444', boxShadow: '0 0 0 1px rgba(239,68,68,.18)' };
const profileInputDisabled = { ...profileInput, color: '#94a3b8', background: '#0f172a', cursor: 'not-allowed', opacity: .78 };
const fieldHelp = { color: '#94a3b8', fontSize: 11, fontWeight: 700, lineHeight: 1.45 };
const fieldError = { color: '#fca5a5', fontSize: 11, fontWeight: 800 };
const apiNotice = { display: 'flex', alignItems: 'center', gap: 10, border: '1px solid #14532d', borderRadius: 6, background: '#052e2b', color: '#86efac', padding: '8px 10px', fontSize: 12, fontWeight: 900, margin: '0 0 12px' };
const profilePrimaryButton = { justifySelf: 'start', height: 38, border: 'none', borderRadius: 5, background: 'linear-gradient(90deg,#4259ff,#6847ea)', color: '#fff', padding: '0 14px', fontSize: 12, fontWeight: 950, cursor: 'pointer' };
const profileWarn = { background: '#171b22', border: '1px solid #7c5b1d', color: '#f59e0b', borderRadius: 6, padding: 9, fontSize: 12, fontWeight: 850 };
const profileOk = { background: '#052e2b', border: '1px solid #047857', color: '#34d399', borderRadius: 6, padding: 9, fontSize: 12, fontWeight: 850 };
const supportForm = { display: 'grid', gap: 16 };
const supportSection = { display: 'grid', gap: 12, border: '1px solid #1e3a5f', borderRadius: 8, background: '#07111f', padding: 16 };
const supportSectionTitle = { margin: 0, color: '#e0f2fe', fontSize: 14, fontWeight: 950 };
const supportGrid = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 12 };
const supportInfoGrid = { display: 'grid', gap: 4 };
const supportTextarea = { ...profileInput, minHeight: 110, resize: 'vertical', padding: '10px 12px', lineHeight: 1.5 };
const supportFileInput = { ...profileInput, height: 'auto', padding: '9px 12px' };
const supportActions = { display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' };
const supportCancelButton = { height: 38, border: '1px solid #1e3a5f', borderRadius: 5, background: '#07111f', color: '#93c5fd', padding: '0 14px', fontSize: 12, fontWeight: 950, cursor: 'pointer' };
const supportTableWrap = { overflowX: 'auto', border: '1px solid #1e3a5f', borderRadius: 8 };
const supportTable = { width: '100%', borderCollapse: 'collapse', minWidth: 760 };
const supportTh = { textAlign: 'left', padding: '12px 14px', color: '#93c5fd', background: '#0c1a2e', borderBottom: '1px solid #1e3a5f', fontSize: 12, fontWeight: 950 };
const supportTd = { padding: '12px 14px', color: '#e2e8f0', borderBottom: '1px solid #1e3a5f', fontSize: 12, verticalAlign: 'middle' };
const profileSummary = { background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 8, padding: 20, boxShadow: '0 10px 24px rgba(0,0,0,.24)' };
const profileSummaryGrid = { display: 'grid', gridTemplateColumns: 'repeat(5, minmax(140px, 1fr))', gap: 16 };
const summaryTile = { border: '1px solid #1e3a5f', borderRadius: 8, padding: 16, display: 'flex', alignItems: 'center', gap: 14, background: '#07111f' };
const summaryIcon = { width: 42, height: 42, borderRadius: 8, display: 'grid', placeItems: 'center', fontWeight: 950 };
const dashboardWelcomeBanner = { background: 'linear-gradient(135deg, rgba(37,99,235,.22), rgba(124,58,237,.18)), #0c1a2e', border: '1px solid #2563eb', borderRadius: 10, padding: 22, marginBottom: 18, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 18, boxShadow: '0 12px 30px rgba(0,0,0,.25)' };
const dashboardWelcomeEyebrow = { color: '#93c5fd', fontSize: 12, fontWeight: 950, textTransform: 'uppercase', letterSpacing: .6 };
const dashboardWelcomeTitle = { margin: '7px 0 8px', color: '#e0f2fe', fontSize: 24, fontWeight: 950 };
const dashboardWelcomeText = { margin: 0, color: '#cbd5e1', fontSize: 13, fontWeight: 750, lineHeight: 1.6, maxWidth: 720 };
const dashboardWelcomeBadge = { border: '1px solid rgba(147,197,253,.45)', borderRadius: 999, background: 'rgba(7,17,31,.55)', color: '#bfdbfe', padding: '10px 14px', fontSize: 12, fontWeight: 950, whiteSpace: 'nowrap' };
const dashboardInfoPanel = { background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 8, padding: 20, marginBottom: 18, boxShadow: '0 10px 24px rgba(0,0,0,.24)' };
const dashboardInfoGrid = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 };
const dashboardInfoCard = { minHeight: 118, border: '1px solid #1e3a5f', borderRadius: 8, background: '#07111f', padding: 18, display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 52px', gap: 14, alignItems: 'center' };
const dashboardInfoIcon = { width: 36, height: 36, borderRadius: 8, display: 'grid', placeItems: 'center', fontWeight: 950 };
const dashboardInfoLabel = { display: 'block', color: '#93c5fd', fontSize: 11, fontWeight: 950, marginBottom: 5 };
const dashboardStatusEnabled = { display: 'inline-flex', width: 'fit-content', borderRadius: 999, background: 'rgba(34,197,94,.16)', color: '#4ade80', padding: '3px 8px', fontSize: 10, fontWeight: 950, marginBottom: 8 };
const dashboardStatusDisabled = { ...dashboardStatusEnabled, background: 'rgba(239,68,68,.16)', color: '#f87171' };
const dashboardInfoValue = { display: 'block', color: '#e2e8f0', fontSize: 20, fontWeight: 950, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' };
const dashboardInfoSub = { margin: '4px 0 0', color: '#94a3b8', fontSize: 11, fontWeight: 750, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' };
const docCardGrid = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 12, marginTop: 18 };
const docMiniCard = { minHeight: 64, border: '1px solid #1e3a5f', borderRadius: 8, background: '#07111f', padding: 12, display: 'grid', gridTemplateColumns: '34px minmax(0, 1fr)', gap: 10, alignItems: 'center', color: '#e2e8f0' };
const docMiniCardButton = { ...docMiniCard, width: '100%', textAlign: 'left', cursor: 'pointer' };
const docMiniIcon = { width: 34, height: 34, borderRadius: 7, background: 'rgba(96,165,250,.12)', color: '#60a5fa', display: 'grid', placeItems: 'center', fontWeight: 950 };
const docUploadSpinner = { width: 22, height: 22, margin: 6, borderRadius: '50%', border: '3px solid rgba(96,165,250,.25)', borderTopColor: '#60a5fa', animation: 'kyc-upload-spin .8s linear infinite' };
const docMiniImage = { width: 34, height: 34, borderRadius: 7, objectFit: 'cover', border: '1px solid #1e3a5f', display: 'block' };
const docMiniText = { minWidth: 0, display: 'grid', gap: 5 };
const docMiniTitle = { display: 'block', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' };
const docMiniMeta = { display: 'block', color: '#cbd5e1', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' };
const notificationCardUnread = { border: '1px solid #2563eb', borderRadius: 8, background: 'rgba(37,99,235,.12)', padding: 14, display: 'flex', justifyContent: 'space-between', gap: 12, color: '#e2e8f0' };
const notificationCardRead = { ...notificationCardUnread, border: '1px solid #1e3a5f', background: '#07111f', opacity: .82 };
const unreadDot = { alignSelf: 'flex-start', borderRadius: 999, background: '#ef4444', color: '#fff', padding: '3px 8px', fontSize: 10, fontWeight: 950 };
const toggleRow = { marginTop: 18, height: 44, border: '1px solid #1e3a5f', borderRadius: 7, padding: '0 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: '#e2e8f0', fontWeight: 900 };
const embeddedDashboard = { margin: 0 };
const agentLicenseShell = { border: '1px solid #21477a', borderRadius: 10, padding: 16, background: 'radial-gradient(circle at top left, rgba(37,99,235,.18), transparent 32%), linear-gradient(180deg,#061429 0%,#071a36 100%)', boxShadow: '0 18px 45px rgba(0,0,0,.32)', color: '#dbeafe', display: 'grid', gap: 14 };
const agentTabShell = { border: '1px solid #21477a', borderRadius: 10, padding: 18, background: 'radial-gradient(circle at top left, rgba(37,99,235,.14), transparent 30%), linear-gradient(180deg,#061429 0%,#071a36 100%)', boxShadow: '0 18px 45px rgba(0,0,0,.32)', color: '#dbeafe', display: 'grid', gap: 18 };
const agentTabMetricGrid = { display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 14 };
const agentTabMetricCard = { minHeight: 112, border: '1px solid #1d3d69', borderRadius: 10, padding: 16, display: 'grid', gridTemplateColumns: '46px minmax(0,1fr)', gap: 14, alignItems: 'center', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.04)' };
const agentTabMetricIcon = { width: 42, height: 42, borderRadius: '50%', display: 'grid', placeItems: 'center', fontSize: 18, fontWeight: 950 };
const agentTabMetricBody = { minWidth: 0, display: 'grid', gap: 5 };
const agentTabMetricValue = { color: '#e2e8f0', fontSize: 24, lineHeight: 1, fontWeight: 950 };
const agentTabMetricSub = { margin: 0, color: '#94a3b8', fontSize: 11, fontWeight: 750 };
const agentLicenseHeader = { display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' };
const agentLicenseTitle = { margin: 0, color: '#f1f5f9', fontSize: 24, lineHeight: 1.1, fontWeight: 950 };
const agentBreadcrumb = { marginTop: 8, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', color: '#93a8c8', fontSize: 12, fontWeight: 800 };
const agentGhostButton = { minHeight: 34, border: '1px solid #1d3d69', borderRadius: 7, background: 'rgba(7,17,31,.68)', color: '#dbeafe', padding: '0 13px', fontSize: 12, fontWeight: 950, cursor: 'pointer' };
const agentPayButton = { minHeight: 38, border: 'none', borderRadius: 7, background: 'linear-gradient(90deg,#1d7cff,#7c22ff)', color: '#fff', padding: '0 15px', fontSize: 12, fontWeight: 950, cursor: 'pointer', boxShadow: '0 12px 24px rgba(37,99,235,.22)' };
const agentMetricGrid = { display: 'grid', gridTemplateColumns: 'repeat(4, minmax(170px, 1fr))', gap: 12 };
const agentMetricCard = { minHeight: 86, border: '1px solid #1d3d69', borderRadius: 8, padding: 14, display: 'grid', gridTemplateColumns: '42px minmax(0,1fr)', gap: 12, alignItems: 'center', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.04)' };
const agentMetricIcon = { width: 38, height: 38, borderRadius: '50%', display: 'grid', placeItems: 'center', fontSize: 18, fontWeight: 950 };
const agentMetricText = { minWidth: 0, display: 'grid', gap: 5 };
const agentPanel = { border: '1px solid #21477a', borderRadius: 8, background: 'linear-gradient(180deg, rgba(9,27,57,.94), rgba(7,20,43,.96))', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.04)', overflow: 'hidden' };
const agentPanelHeader = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, padding: '12px 14px 0', flexWrap: 'wrap' };
const agentPanelTitle = { margin: 0, padding: '12px 14px', color: '#e2e8f0', fontSize: 15, fontWeight: 950 };
const agentPurchaseHeader = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', padding: '0 0 4px' };
const agentAutoPayButton = { marginRight: 14, minHeight: 34, border: '1px solid #1d3d69', borderRadius: 7, background: '#07111f', color: '#bfdbfe', padding: '0 13px', fontSize: 12, fontWeight: 950, cursor: 'pointer' };
const agentAutoPayEnabled = { ...agentAutoPayButton, border: '1px solid #10b981', background: 'rgba(16,185,129,.16)', color: '#6ee7b7' };
const agentPurchaseGrid = { display: 'grid', gridTemplateColumns: '1.2fr 1fr .9fr .9fr auto', gap: 12, alignItems: 'end', padding: '0 14px 12px' };
const agentField = { display: 'grid', gap: 7, color: '#93a8c8', fontSize: 12, fontWeight: 900 };
const agentInput = { height: 38, border: '1px solid #1d3d69', borderRadius: 6, background: '#07162e', color: '#e2e8f0', padding: '0 11px', outline: 'none', fontWeight: 800 };
const agentInputDisabled = { ...agentInput, color: '#94a3b8', background: '#07111f', cursor: 'not-allowed' };
const agentReadonlyAmount = { height: 38, border: '1px solid #1d3d69', borderRadius: 6, background: '#07111f', color: '#22c55e', padding: '0 11px', display: 'flex', alignItems: 'center', fontWeight: 950 };
const agentAmountBox = { minHeight: 38, display: 'grid', alignContent: 'center', gap: 4, color: '#93a8c8', fontSize: 12, fontWeight: 900 };
const agentAmountNote = { color: '#22c55e', fontSize: 10, fontWeight: 900 };
const agentProceedButton = { minHeight: 40, border: 'none', borderRadius: 7, background: 'linear-gradient(90deg,#1685ff,#8224f7)', color: '#fff', padding: '0 18px', fontSize: 12, fontWeight: 950, cursor: 'pointer', whiteSpace: 'nowrap' };
const agentInfoLine = { margin: '0 14px 12px', border: '1px solid #143d73', borderRadius: 7, background: 'rgba(37,99,235,.12)', color: '#93c5fd', padding: '10px 12px', fontSize: 12, fontWeight: 800 };
const agentCheckoutBox = { margin: '0 14px 14px', border: '1px solid #2563eb', borderRadius: 8, background: 'linear-gradient(180deg, rgba(37,99,235,.14), rgba(7,17,31,.9))', padding: 14, display: 'grid', gap: 12 };
const agentCheckoutTitle = { margin: 0, color: '#e0f2fe', fontSize: 15, fontWeight: 950 };
const agentCheckoutSub = { margin: '4px 0 0', color: '#93c5fd', fontSize: 12, fontWeight: 800 };
const agentCheckoutGrid = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 8 };
const agentCheckoutActions = { display: 'flex', justifyContent: 'flex-end', gap: 10, flexWrap: 'wrap' };
const agentCheckoutBack = { minHeight: 40, border: '1px solid #1d3d69', borderRadius: 7, background: '#07111f', color: '#bfdbfe', padding: '0 16px', fontSize: 12, fontWeight: 950, cursor: 'pointer' };
const agentTableWrap = { overflowX: 'auto', borderTop: '1px solid rgba(33,71,122,.7)' };
const agentTable = { width: '100%', minWidth: 840, borderCollapse: 'collapse', fontSize: 12 };
const agentTableHead = { textAlign: 'left', padding: '10px 14px', color: '#93c5fd', background: 'rgba(7,17,31,.66)', borderBottom: '1px solid #1e3a5f', fontSize: 11, fontWeight: 950, whiteSpace: 'nowrap' };
const agentTableCell = { padding: '10px 14px', color: '#dbeafe', borderBottom: '1px solid rgba(30,58,95,.72)', fontSize: 12, verticalAlign: 'middle' };
const agentTablePager = { display: 'flex', justifyContent: 'flex-end', gap: 10, padding: '14px 18px', background: '#07111f', borderTop: '1px solid rgba(30,58,95,.72)' };
const agentTablePagerButton = disabled => ({ minWidth: 74, height: 34, borderRadius: 8, border: '1px solid #1d3d69', background: '#07111f', color: disabled ? '#475569' : '#93c5fd', fontSize: 13, fontWeight: 850, cursor: disabled ? 'not-allowed' : 'pointer' });
const agentAllocationCard = { border: '1px solid #1d3d69', borderRadius: 10, background: 'linear-gradient(180deg, rgba(7,17,31,.78), rgba(7,20,43,.96))', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.04)', overflow: 'hidden' };
const agentAllocationHeader = { display: 'flex', alignItems: 'center', gap: 14, padding: 20 };
const agentAllocationIcon = { width: 38, height: 38, borderRadius: 8, background: 'rgba(37,99,235,.22)', color: '#60a5fa', display: 'grid', placeItems: 'center', fontSize: 18, fontWeight: 950 };
const agentAllocationTitle = { margin: 0, color: '#e2e8f0', fontSize: 17, fontWeight: 950 };
const agentAllocationSubtitle = { margin: '5px 0 0', color: '#94a3b8', fontSize: 12, fontWeight: 750 };
const agentAllocationTableWrap = { margin: '0 14px', overflow: 'hidden', border: '1px solid #1d3d69', borderRadius: 8 };
const agentAllocationFooter = { padding: '14px 16px 18px', textAlign: 'center', color: '#94a3b8', fontSize: 12, fontWeight: 800 };
const agentAllocationInput = { width: 120, height: 34, border: '1px solid #1d3d69', borderRadius: 6, background: '#07162e', color: '#e2e8f0', padding: '0 10px', fontWeight: 850 };
const agentSaveButton = { height: 32, minWidth: 70, border: 'none', borderRadius: 6, background: 'linear-gradient(90deg,#2563eb,#7c3aed)', color: '#fff', fontSize: 12, fontWeight: 950, cursor: 'pointer' };
const agentViewButton = { height: 26, minWidth: 54, border: '1px solid #1d4ed8', borderRadius: 5, background: 'rgba(37,99,235,.16)', color: '#bfdbfe', fontSize: 11, fontWeight: 900, cursor: 'pointer' };
const agentStatusActive = { display: 'inline-flex', alignItems: 'center', borderRadius: 5, background: 'rgba(34,197,94,.16)', color: '#4ade80', padding: '4px 10px', fontSize: 11, fontWeight: 950 };
const agentStatusExpired = { display: 'inline-flex', alignItems: 'center', borderRadius: 5, background: 'rgba(239,68,68,.16)', color: '#f87171', padding: '4px 10px', fontSize: 11, fontWeight: 950 };
const agentPaidBadge = { display: 'inline-flex', alignItems: 'center', borderRadius: 5, background: 'rgba(34,197,94,.16)', color: '#4ade80', padding: '4px 10px', fontSize: 11, fontWeight: 950 };
const agentAutoPayCell = { display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' };
const agentDisableAutoPayButton = { border: '1px solid #ef4444', borderRadius: 5, background: 'rgba(239,68,68,.12)', color: '#fecaca', padding: '4px 8px', fontSize: 11, fontWeight: 900, cursor: 'pointer' };
