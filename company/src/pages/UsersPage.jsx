import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { validateEmail } from '../utils/validate';
import PaginationControls from '../components/PaginationControls';
import './UsersPage.css';

const PAGE_SIZE = 6;

const ROLE_STYLE = {
  company_admin:    { bg:'rgba(46, 16, 101, 0.7)', color:'#c4b5fd', border:'#7c3aed', label:'Company Admin' },
  department_admin: { bg:'rgba(6, 78, 59, 0.7)', color:'#34d399', border:'#059669', label:'Dept Admin' },
  analyst:          { bg:'rgba(30, 58, 95, 0.7)', color:'#93c5fd', border:'#2563eb', label:'Analyst' },
  superadmin:       { bg:'rgba(120, 53, 15, 0.7)', color:'#fcd34d', border:'#d97706', label:'Superadmin' },
  partner_admin:    { bg:'rgba(26, 14, 69, 0.7)', color:'#a78bfa', border:'#6d28d9', label:'Partner Admin' },
  soc_manager:      { bg:'rgba(22, 78, 99, 0.7)', color:'#67e8f9', border:'#0891b2', label:'SOC Manager' },
  l1_analyst:       { bg:'rgba(30, 58, 95, 0.7)', color:'#93c5fd', border:'#2563eb', label:'L1 Analyst' },
  l2_analyst:       { bg:'rgba(49, 46, 129, 0.7)', color:'#c4b5fd', border:'#4f46e5', label:'L2 Analyst' },
  l3_analyst:       { bg:'rgba(76, 29, 149, 0.7)', color:'#e9d5ff', border:'#7c3aed', label:'L3 Analyst' },
  l4_analyst:       { bg:'rgba(88, 28, 135, 0.7)', color:'#f5d0fe', border:'#a855f7', label:'L4 Threat Intelligence Analyst' },
};

const ANALYST_INVITE_ROLES = [
  ['l1_analyst', 'L1 Analyst (Triage & Alert Monitoring)'],
  ['l2_analyst', 'L2 Analyst (Incident Investigation)'],
  ['l3_analyst', 'L3 Analyst (Threat Hunting & Forensics)'],
  ['l4_analyst', 'L4 Analyst (Threat Intelligence Incidents Only)'],
];

const ANALYST_ROLES = ['analyst', ...ANALYST_INVITE_ROLES.map(([role]) => role)];
const PARTNER_STAFF_ROLES = ['soc_manager', ...ANALYST_ROLES];
const staffStatus = user => {
  if (['suspended', 'invited', 'expired'].includes(user.accountStatus)) {
    return user.accountStatus.charAt(0).toUpperCase() + user.accountStatus.slice(1);
  }
  return user.isActive === false || user.accountStatus === 'disabled' ? 'Disabled' : 'Active';
};

const ANALYST_ACCESS = [
  { icon:'📊', label:'SOC Operations Command',  desc:'Real-time alert monitoring & workforce metrics' },
  { icon:'🔔', label:'Scoped Alert & Ticket Queue', desc:'Filtered strictly by authorized company scope' },
  { icon:'🛡️', label:'Security Command Scope',  desc:'Incident command & analyst tier assignments' },
];

const panel = { background:'linear-gradient(135deg, rgba(10, 24, 45, 0.9) 0%, rgba(6, 17, 32, 0.9) 100%)', backdropFilter:'blur(12px)', border:'1px solid #1e3a5f', borderRadius:14, padding:26, boxShadow:'0 16px 40px rgba(0,0,0,0.5)' };
const input = { width:'100%', height:46, padding:'10px 14px', borderRadius:8, boxSizing:'border-box', background:'#040d1a', color:'#f8fafc', fontSize:13, outline:'none', border:'1px solid #1e3a5f', transition:'all .2s' };
const button = { height:46, padding:'0 24px', borderRadius:8, border:'none', fontSize:13, fontWeight:900, background:'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)', color:'#fff', cursor:'pointer', whiteSpace:'nowrap', display:'inline-flex', alignItems:'center', gap:8, boxShadow:'0 4px 16px rgba(37,99,235,0.4)', transition:'all .2s' };

export default function UsersPage() {
  const { user: me, isAdmin } = useAuth();
  const [searchParams] = useSearchParams();
  const isPartnerAdmin = me?.role === 'partner_admin';
  const isSocManager = me?.role === 'soc_manager';
  const autoOpenInvite = searchParams.get('invite') === 'analyst';
  const canInvite = autoOpenInvite ? (isPartnerAdmin || isSocManager) : (isAdmin || isPartnerAdmin || isSocManager);

  const [users,   setUsers]   = useState([]);
  const [loading, setLoading] = useState(true);
  const [apiErr,  setApiErr]  = useState('');
  const [updatingId, setUpdatingId] = useState(null);
  const [page, setPage] = useState(1);
  const [companies, setCompanies] = useState([]);
  const [departments, setDepartments] = useState([]);
  const [selectedCompanyId, setSelectedCompanyId] = useState('');
  const [selectedDepartmentId, setSelectedDepartmentId] = useState('');

  // Invite form
  const [invEmail,    setInvEmail]    = useState('');
  const [invRole,     setInvRole]     = useState(isSocManager ? 'l1_analyst' : 'soc_manager');
  const [invEmailErr, setInvEmailErr] = useState('');
  const [invBusy,     setInvBusy]     = useState(false);
  const [invMsg,      setInvMsg]      = useState('');
  const [invErr,      setInvErr]      = useState('');
  const [invites, setInvites] = useState([]);
  const [invitesLoading, setInvitesLoading] = useState(false);

  const invitePanelRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setUsers([]);
    setApiErr('');
    setPage(1);
    api.get(isPartnerAdmin ? '/partner/staff' : autoOpenInvite || isSocManager ? '/soc/staff' : '/users', { skipCache: true })
      .then(({ data }) => { if (!cancelled) setUsers(Array.isArray(data) ? data : []); })
      .catch(err => { if (!cancelled) setApiErr(err.response?.data?.message || 'Failed to load staff'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [autoOpenInvite, isSocManager, isPartnerAdmin, me?.partnerId]);

  const loadInvites = () => {
    setInvitesLoading(true);
    api.get('/soc/invitations')
      .then(({ data }) => setInvites(Array.isArray(data) ? data : []))
      .catch(() => setInvites([]))
      .finally(() => setInvitesLoading(false));
  };

  useEffect(() => {
    if (autoOpenInvite) loadInvites();
  }, [autoOpenInvite]);

  useEffect(() => {
    if (!autoOpenInvite) return;
    api.get('/soc/companies')
      .then(({ data }) => {
        const list = Array.isArray(data) ? data : [];
        setCompanies(list);
        setSelectedCompanyId(prev => prev || list[0]?._id || '');
      })
      .catch(() => setCompanies([]));
  }, [autoOpenInvite]);

  useEffect(() => {
    setDepartments([]);
    setSelectedDepartmentId('');
    const companyId = (isPartnerAdmin || isSocManager) ? selectedCompanyId : (selectedCompanyId || me?.companyId);
    if (!companyId) return;
    api.get(`/department?companyId=${companyId}`)
      .then(({ data }) => setDepartments(Array.isArray(data) ? data : []))
      .catch(() => setDepartments([]));
  }, [isPartnerAdmin, isSocManager, selectedCompanyId, me?.companyId]);

  useEffect(() => {
    if (autoOpenInvite && invitePanelRef.current) {
      setTimeout(() => {
        invitePanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        invitePanelRef.current?.querySelector('input')?.focus();
      }, 300);
    }
  }, [autoOpenInvite, loading]);

  const sendInvite = async () => {
    const emailErr = validateEmail(invEmail);
    if (emailErr) { setInvEmailErr(emailErr); return; }
    setInvEmailErr('');
    setInvBusy(true); setInvMsg(''); setInvErr('');
    try {
      await api.post('/soc/invitations', {
        email: invEmail.trim().toLowerCase(),
        role: isSocManager ? invRole : 'soc_manager',
        companyIds: [selectedCompanyId || me?.companyId],
        departmentIds: selectedDepartmentId ? [selectedDepartmentId] : [],
      });
      setInvMsg(`✅ Invitation sent to ${invEmail}`);
      setInvEmail('');
      loadInvites();
    } catch (err) {
      setInvErr(err.response?.data?.message || 'Failed to send invite');
    } finally { setInvBusy(false); }
  };

  const toggleActive = async (u) => {
    setUpdatingId(u._id);
    const isActive = staffStatus(u) === 'Active';
    try {
      if (['soc_manager','l1_analyst','l2_analyst','l3_analyst','l4_analyst'].includes(u.role)) {
        const { data } = await api.patch(`/soc/staff/${u._id}/status`, { status:isActive ? 'disabled' : 'active' });
        setUsers(prev => prev.map(x => x._id === u._id ? { ...x, ...data.user } : x));
      } else {
        const { data } = await api.patch(`/users/${u._id}`, { isActive: !isActive, accountStatus: isActive ? 'disabled' : 'active' });
        setUsers(prev => prev.map(x => x._id === data._id ? data : x));
      }
    } catch (err) {
      alert(err.response?.data?.message || 'Update failed');
    } finally {
      setUpdatingId(null);
    }
  };

  const partnerStaff = users.filter(u => PARTNER_STAFF_ROLES.includes(u.role));
  const totalPages = Math.max(1, Math.ceil(partnerStaff.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pagedStaff = partnerStaff.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);
  const testers = isPartnerAdmin ? partnerStaff : autoOpenInvite
    ? users.filter(u => ['soc_manager'].includes(u.role))
    : users.filter(u => ['partner_admin', 'company_admin', 'department_admin', 'soc_manager'].includes(u.role));
  const activeTesters = testers.filter(u => u.isActive !== false);
  const visibleTeamMembers = [...activeTesters].sort((a, b) => {
    if (String(a._id) === String(me?._id || me?.id)) return -1;
    if (String(b._id) === String(me?._id || me?.id)) return 1;
    return 0;
  });

  const workforce = isPartnerAdmin ? partnerStaff : users;
  const socManagerCount = workforce.filter(u => u.role === 'soc_manager').length;
  const analystCount = workforce.filter(u => ANALYST_ROLES.includes(u.role)).length;
  const activeStaffCount = workforce.filter(u => staffStatus(u) === 'Active').length;

  return (
    <div>
      {/* ── Page Header ── */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20, flexWrap:'wrap', gap:12 }}>
        <div>
          <h2 style={{ fontSize:24, color:'#f8fafc', margin:0, fontWeight:900, letterSpacing:-0.5 }}>👥 {isPartnerAdmin ? 'Analyst' : 'Team & SOC Workforce Command'}</h2>
          <div style={{ color:'#38bdf8', fontSize:13, marginTop:3 }}>{isPartnerAdmin ? 'SOC Managers and Analysts belonging to your partner account' : 'Superadmin & Partner level account management, invitations, and role delegation'}</div>
        </div>
      </div>

      {/* ── Top Metric Cards Grid ── */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(160px, 1fr))', gap:14, marginBottom:22 }}>
        <div style={{ ...panel, padding:14 }}>
          <small style={{ color:'#64748b', fontSize:10, fontWeight:800, textTransform:'uppercase' }}>Total Workforce</small>
          <div style={{ color:'#67e8f9', fontSize:22, fontWeight:900, marginTop:4 }}>{loading || apiErr ? '—' : workforce.length} {isPartnerAdmin ? 'Members' : 'Users'}</div>
        </div>

        <div style={{ ...panel, padding:14 }}>
          <small style={{ color:'#64748b', fontSize:10, fontWeight:800, textTransform:'uppercase' }}>SOC Managers</small>
          <div style={{ color:'#38bdf8', fontSize:22, fontWeight:900, marginTop:4 }}>{loading || apiErr ? '—' : socManagerCount} Managers</div>
        </div>

        <div style={{ ...panel, padding:14 }}>
          <small style={{ color:'#64748b', fontSize:10, fontWeight:800, textTransform:'uppercase' }}>Analysts</small>
          <div style={{ color:'#c4b5fd', fontSize:22, fontWeight:900, marginTop:4 }}>{loading || apiErr ? '—' : analystCount} Analysts</div>
        </div>

        <div style={{ ...panel, padding:14 }}>
          <small style={{ color:'#64748b', fontSize:10, fontWeight:800, textTransform:'uppercase' }}>{isPartnerAdmin ? 'Active Members' : 'Pending Invites'}</small>
          <div style={{ color:'#facc15', fontSize:22, fontWeight:900, marginTop:4 }}>{isPartnerAdmin ? `${loading || apiErr ? '—' : activeStaffCount} Active` : `${invites.length} Sent`}</div>
        </div>
      </div>

      {apiErr && (
        <div style={{ background:'rgba(127, 29, 29, 0.4)', border:'1px solid #7f1d1d', color:'#fca5a5', padding:'12px 16px', borderRadius:8, marginBottom:18, fontSize:13 }}>
          ⚠️ {apiErr}
        </div>
      )}

      {/* ── Superadmin Level Executive Invitation Panel — only on ?invite=analyst ── */}
      {canInvite && autoOpenInvite && (
        <div ref={invitePanelRef} style={{ ...panel, border:'1px solid #3b82f6', marginBottom:30, boxShadow:'0 0 32px rgba(37,99,235,0.25)' }}>
          
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:14 }}>
            <h3 style={{ fontSize:18, color:'#60a5fa', margin:0, fontWeight:900, display:'flex', alignItems:'center', gap:10 }}>
              ✉ {isSocManager ? 'Invite Tiered Analyst (L1 / L2 / L3)' : 'Invite SOC Manager (Partner Level Scope)'}
            </h3>
            <span style={{ background:'rgba(37,99,235,0.2)', border:'1px solid #2563eb', color:'#38bdf8', borderRadius:999, padding:'5px 14px', fontSize:11, fontWeight:800 }}>
              {isSocManager ? 'SOC Manager Scope' : 'Partner Level Scope'}
            </span>
          </div>

          <p style={{ fontSize:13, color:'#94a3b8', marginBottom:20 }}>
            {isSocManager
              ? 'Apni assigned company ke liye L1, L2 ya L3 Analyst ko secure email invitation bhejo.'
              : 'Partner-level permission: Invite SOC Managers scoped strictly to your partner companies.'}
          </p>

          {/* Access Feature List */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(200px, 1fr))', gap:14, marginBottom:22 }}>
            {ANALYST_ACCESS.map(({ icon, label, desc }) => (
              <div key={label} style={{ background:'#040d1a', border:'1px solid #1e3a5f', borderRadius:10, padding:14 }}>
                <div style={{ fontSize:20, marginBottom:6 }}>{icon}</div>
                <div style={{ fontSize:13, color:'#f8fafc', fontWeight:800 }}>{label}</div>
                <div style={{ fontSize:11, color:'#64748b', marginTop:3 }}>{desc}</div>
              </div>
            ))}
          </div>

          {invMsg && <div style={{ background:'rgba(6, 78, 59, 0.7)', border:'1px solid #059669', color:'#34d399', padding:'12px 16px', borderRadius:8, marginBottom:18, fontSize:13, fontWeight:700 }}>{invMsg}</div>}
          {invErr && <div style={{ background:'rgba(127, 29, 29, 0.7)', border:'1px solid #991b1b', color:'#fca5a5', padding:'12px 16px', borderRadius:8, marginBottom:18, fontSize:13, fontWeight:700 }}>{invErr}</div>}

          {/* Form Inputs Grid */}
          <div style={{ display:'flex', gap:14, alignItems:'end', flexWrap:'wrap' }}>
            <div style={{ flex:1, minWidth:240 }}>
              <label style={{ display:'block', color:'#7dd3fc', fontSize:11, marginBottom:6, fontWeight:800, textTransform:'uppercase' }}>Official Email Address *</label>
              <input
                type="email"
                placeholder="socmanager@partnercompany.com"
                value={invEmail}
                onChange={e => { setInvEmail(e.target.value); setInvEmailErr(''); }}
                onKeyDown={e => e.key === 'Enter' && sendInvite()}
                style={{
                  ...input,
                  border: `1px solid ${invEmailErr ? '#f87171' : '#1e3a5f'}`,
                }}/>
              {invEmailErr && <div style={{ fontSize:11, color:'#f87171', marginTop:4 }}>{invEmailErr}</div>}
            </div>

            {(isPartnerAdmin || isSocManager || companies.length > 1) && (
              <div style={{ flex:1, minWidth:220 }}>
                <label style={{ display:'block', color:'#7dd3fc', fontSize:11, marginBottom:6, fontWeight:800, textTransform:'uppercase' }}>Partner Company Scope *</label>
                <select
                  value={selectedCompanyId}
                  onChange={e => setSelectedCompanyId(e.target.value)}
                  style={input}
                >
                  <option value="">Select Partner Company</option>
                  {companies.map(company => <option key={company._id} value={company._id}>{company.name}</option>)}
                </select>
              </div>
            )}

            <div style={{ flex:1, minWidth:200 }}>
              <label style={{ display:'block', color:'#7dd3fc', fontSize:11, marginBottom:6, fontWeight:800, textTransform:'uppercase' }}>Department Scope</label>
              <select
                value={selectedDepartmentId}
                onChange={e => setSelectedDepartmentId(e.target.value)}
                disabled={!selectedCompanyId}
                style={{
                  ...input,
                  opacity: !selectedCompanyId ? .6 : 1,
                }}
              >
                <option value="">All departments</option>
                {selectedCompanyId && departments.length === 0 && <option value="" disabled>No departments found</option>}
                {departments.map(dept => <option key={dept._id} value={dept._id}>{dept.name}</option>)}
              </select>
            </div>

            <div style={{ height:46, display:'flex', alignItems:'center', padding:'0 14px', borderRadius:8, fontSize:12, fontWeight:800, background:'#164e63', color:'#67e8f9', border:'1px solid #0891b2', whiteSpace:'nowrap' }}>
              {isSocManager ? (
                <select value={invRole} onChange={e => setInvRole(e.target.value)} style={{ background:'transparent', border:0, color:'#fff', outline:'none', fontWeight:800 }}>
                  {ANALYST_INVITE_ROLES.map(([role,label]) => <option key={role} value={role} style={{ color:'#111827' }}>{label}</option>)}
                </select>
              ) : 'SOC Manager'}
            </div>

            <button
              onClick={sendInvite}
              disabled={invBusy || !invEmail || !selectedCompanyId}
              style={{
                ...button,
                opacity: (invBusy || !invEmail || !selectedCompanyId) ? .5 : 1,
                cursor: (invBusy || !invEmail || !selectedCompanyId) ? 'not-allowed' : 'pointer'
              }}
            >
              {invBusy ? 'Sending…' : 'Send Invitation →'}
            </button>
          </div>

          <p style={{ fontSize:11, color:'#64748b', marginTop:14, margin:0 }}>
            🔒 Secure invitation link generated · Access strictly restricted to authorized company scope.
          </p>

          {/* Invitation List */}
          <div style={{ marginTop:24, border:'1px solid #1e3a5f', borderRadius:12, background:'#040d1a', overflow:'hidden' }}>
            <div style={{ padding:'16px 20px', borderBottom:'1px solid #1e3a5f', background:'#071527', color:'#e2e8f0', fontSize:13, fontWeight:800, display:'flex', justifyContent:'space-between', alignItems:'center' }}>
              <span>✉ {isSocManager ? 'Analyst Invitation List' : 'SOC Manager Invitation List'}</span>
              <span style={{ background:'#1e3a5f', color:'#38bdf8', borderRadius:999, padding:'3px 12px', fontSize:11, fontWeight:800 }}>{invites.length} Sent</span>
            </div>
            {invitesLoading ? (
              <p style={{ color:'#64748b', fontSize:13, padding:20, margin:0 }}>Loading invitations...</p>
            ) : invites.filter(invite => isSocManager ? ['l1_analyst','l2_analyst','l3_analyst','l4_analyst'].includes(invite.role) : invite.role === 'soc_manager').length === 0 ? (
              <p style={{ color:'#64748b', fontSize:13, padding:20, margin:0 }}>No {isSocManager ? 'analyst' : 'SOC Manager'} invitations sent yet.</p>
            ) : (
              <div style={{ display:'grid', gap:10, padding:14 }}>
                {invites.filter(invite => isSocManager ? ['l1_analyst','l2_analyst','l3_analyst','l4_analyst'].includes(invite.role) : invite.role === 'soc_manager').map(invite => {
                  const companyName = invite.company || 'Partner scope company';
                  return (
                    <div key={invite._id} style={{ border:'1px solid #1e3a5f', borderRadius:10, background:'#08172b', padding:'14px 18px', display:'flex', justifyContent:'space-between', alignItems:'center', flexWrap:'wrap', gap:10 }}>
                      <div style={{ display:'flex', alignItems:'center', gap:12 }}>
                        <div style={{ width:38, height:38, borderRadius:10, background:'linear-gradient(135deg, #164e63 0%, #0891b2 100%)', color:'#fff', display:'grid', placeItems:'center', fontWeight:900, fontSize:15 }}>
                          {String(invite.email || 'A').charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <b style={{ color:'#f8fafc', fontSize:14 }}>{invite.email}</b>
                          <small style={{ display:'block', color:'#64748b', fontSize:11, marginTop:2 }}>Company Scope: {companyName}</small>
                        </div>
                      </div>
                      <div style={{ display:'flex', gap:10, alignItems:'center' }}>
                        <span style={{ background:'rgba(22, 78, 99, 0.7)', color:'#67e8f9', border:'1px solid #0891b2', borderRadius:999, padding:'4px 12px', fontSize:11, fontWeight:800 }}>
                          {ROLE_STYLE[invite.role]?.label || invite.role}
                        </span>
                        <span style={{ background: invite.status === 'accepted' ? 'rgba(6, 78, 59, 0.7)' : 'rgba(120, 53, 15, 0.7)', color: invite.status === 'accepted' ? '#34d399' : '#fde047', border: `1px solid ${invite.status === 'accepted' ? '#059669' : '#d97706'}`, borderRadius:999, padding:'4px 12px', fontSize:11, fontWeight:800 }}>
                          {invite.status?.toUpperCase() || 'PENDING'}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {isPartnerAdmin ? (
        <section className="partner-staff-panel" aria-labelledby="partner-staff-title">
          <div className="partner-staff-heading">
            <h3 id="partner-staff-title">SOC Managers &amp; Analysts</h3>
            {!loading && !apiErr && <span>{partnerStaff.length} members</span>}
          </div>
          <div className="partner-staff-scroll" role="region" aria-label="Partner staff table" tabIndex={0}>
            <table className="partner-staff-table" aria-labelledby="partner-staff-title" aria-busy={loading}>
              <thead>
                <tr>
                  {['Name', 'Email', 'Role', 'Status', 'Action'].map(label => <th key={label} scope="col">{label}</th>)}
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={5} className="partner-staff-empty">Loading SOC Managers and Analysts…</td></tr>
                ) : apiErr ? (
                  <tr><td colSpan={5} className="partner-staff-empty">Staff list is unavailable. Please reload to retry.</td></tr>
                ) : partnerStaff.length === 0 ? (
                  <tr><td colSpan={5} className="partner-staff-empty">No SOC Managers or Analysts found for your partner account.</td></tr>
                ) : pagedStaff.map(member => {
                  const status = staffStatus(member);
                  const roleStyle = ROLE_STYLE[member.role];
                  const busy = updatingId === member._id;
                  return (
                    <tr key={member._id}>
                      <th scope="row">{member.name || '—'}</th>
                      <td className="partner-staff-email">{member.email || '—'}</td>
                      <td><span className="partner-staff-badge" style={{ background:roleStyle.bg, color:roleStyle.color, borderColor:roleStyle.border }}>{roleStyle.label}</span></td>
                      <td><span className={`partner-staff-badge partner-staff-status-${status.toLowerCase()}`}>{status}</span></td>
                      <td>
                        {['Active', 'Disabled', 'Suspended'].includes(status) ? (
                          <button
                            type="button"
                            className={`partner-staff-action${status === 'Active' ? ' partner-staff-action-disable' : ''}`}
                            disabled={updatingId !== null}
                            aria-label={`${status === 'Active' ? 'Disable' : 'Enable'} ${member.name || member.email}`}
                            onClick={() => toggleActive(member)}
                          >
                            {busy ? 'Updating…' : status === 'Active' ? 'Disable' : 'Enable'}
                          </button>
                        ) : '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {!loading && !apiErr && partnerStaff.length > 0 && (
            <div className="partner-staff-pagination">
              <PaginationControls page={currentPage} total={partnerStaff.length} pageSize={PAGE_SIZE} onPageChange={setPage} />
            </div>
          )}
        </section>
      ) : (
      <div style={panel}>
        <h3 style={{ margin:'0 0 18px', color:'#f8fafc', fontSize:16, fontWeight:900 }}>
          Active Team Members
        </h3>
        {loading ? (
          <div style={{ color:'#94a3b8', padding:24, fontSize:13 }}>Loading team members…</div>
        ) : activeTesters.length === 0 ? (
          <div style={{ color:'#94a3b8', padding:24, fontSize:13 }}>No active team members found.</div>
        ) : (
          <div style={{ display:'grid', gap:12 }}>
            {visibleTeamMembers.map(u => {
              const isCurrentAccount = String(u._id) === String(me?._id || me?.id);
              return (
              <div key={u._id} style={{ border:'1px solid #1e3a5f', borderRadius:10, background:'#08172b', padding:'16px 20px', display:'flex', justifyContent:'space-between', alignItems:'center', flexWrap:'wrap', gap:12 }}>
                <div style={{ display:'flex', alignItems:'center', gap:14 }}>
                  <div style={{ width:42, height:42, borderRadius:10, background:'linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%)', color:'#fff', display:'grid', placeItems:'center', fontWeight:900, fontSize:16 }}>
                    {(u.name || u.email).charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div style={{ display:'flex', alignItems:'center', flexWrap:'wrap', gap:8 }}>
                      <b style={{ color:'#f8fafc', fontSize:15 }}>{u.name}</b>
                      {isCurrentAccount && isPartnerAdmin && (
                        <span style={{ background:'rgba(109, 40, 217, 0.28)', color:'#c4b5fd', border:'1px solid #7c3aed', borderRadius:999, padding:'3px 9px', fontSize:10, fontWeight:900 }}>
                          CURRENT PARTNER ADMIN ACCOUNT
                        </span>
                      )}
                    </div>
                    <small style={{ display:'block', color:'#64748b', fontSize:12, marginTop:2 }}>{u.email}</small>
                  </div>
                </div>

                <div style={{ display:'flex', gap:12, alignItems:'center' }}>
                  <span style={{ background: ROLE_STYLE[u.role]?.bg || '#1e3a5f', color: ROLE_STYLE[u.role]?.color || '#93c5fd', border: `1px solid ${ROLE_STYLE[u.role]?.border || '#2563eb'}`, borderRadius:999, padding:'5px 14px', fontSize:11, fontWeight:800 }}>
                    {ROLE_STYLE[u.role]?.label || u.role}
                  </span>
                  {!isCurrentAccount && (
                    <button onClick={() => toggleActive(u)} style={{ background:'rgba(127, 29, 29, 0.7)', border:'1px solid #991b1b', color:'#fca5a5', borderRadius:8, padding:'7px 14px', fontSize:12, fontWeight:800, cursor:'pointer' }}>
                      Disable
                    </button>
                  )}
                </div>
              </div>
              );
            })}
          </div>
        )}
      </div>
      )}
    </div>
  );
}
