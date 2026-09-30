import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../api/axios';

const ROLE_STYLE = {
  superadmin:       { bg:'#78350f', color:'#fcd34d',  label:'Superadmin' },
  partner_admin:    { bg:'#581c87', color:'#f0abfc',  label:'Partner Admin' },
  company_admin:    { bg:'#2e1065', color:'#a78bfa',  label:'Company Admin' },
  department_admin: { bg:'#064e3b', color:'#34d399',  label:'Dept Admin' },
  soc_manager:      { bg:'#164e63', color:'#67e8f9',  label:'SOC Manager' },
  l1_analyst:       { bg:'#1e3a5f', color:'#93c5fd',  label:'L1 Analyst' },
  l2_analyst:       { bg:'#312e81', color:'#c4b5fd',  label:'L2 Analyst' },
  l3_analyst:       { bg:'#4c1d95', color:'#e9d5ff',  label:'L3 Analyst' },
  l4_analyst:       { bg:'#581c87', color:'#f5d0fe',  label:'L4 Threat Intelligence Analyst' },
};

const ROLE_ORDER = ['superadmin', 'partner_admin', 'company_admin', 'department_admin', 'soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'];

export default function UsersPage() {
  const [searchParams] = useSearchParams();
  const isAnalystView = searchParams.get('role') === 'analyst';
  const [users,     setUsers]     = useState([]);
  const [companies, setCompanies] = useState([]);
  const [depts,     setDepts]     = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [loadError, setLoadError] = useState('');
  const [search,    setSearch]    = useState('');
  const [roleFilter, setRoleFilter] = useState('all');

  // Invite form
  const [showInvite, setShowInvite] = useState(false);
  const [inv, setInv] = useState({ email:'', name:'', role:'soc_manager', companyId:'', departmentIds:[] });
  const [invBusy, setInvBusy] = useState(false);
  const [invMsg,  setInvMsg]  = useState('');
  const [invErr,  setInvErr]  = useState('');

  useEffect(() => {
    let current = true;
    setLoading(true);
    setLoadError('');

    api.get('/superadmin/users', { params: isAnalystView ? { role:'analyst' } : {} })
      .then(({ data }) => {
        if (!current) return;
        const receivedUsers = Array.isArray(data) ? data : [];
        setUsers(isAnalystView
          ? receivedUsers.filter(user => user.superadminManaged === true && [
              'soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst',
            ].includes(user.role))
          : receivedUsers);
      })
      .catch(err => {
        if (current) setLoadError(err.response?.data?.message || 'Failed to load SOC accounts');
      })
      .finally(() => { if (current) setLoading(false); });

    // Company options are only needed by the invite form; a failure here must
    // not prevent already-loaded SOC accounts from rendering.
    api.get('/superadmin/companies')
      .then(({ data }) => { if (current) setCompanies(Array.isArray(data) ? data : []); })
      .catch(() => { if (current) setCompanies([]); });

    return () => { current = false; };
  }, [isAnalystView]);

  // Load depts when company changes
  useEffect(() => {
    if (!inv.companyId) { setDepts([]); return; }
    api.get(`/superadmin/companies/${inv.companyId}/departments`)
      .then(r => setDepts(r.data || []))
      .catch(() => setDepts([]));
  }, [inv.companyId]);

  const toggle = async (u) => {
    const { data } = await api.patch(`/superadmin/users/${u._id}`, { isActive: !u.isActive });
    setUsers(prev => prev.map(x => x._id === data._id ? data : x));
  };

  const sendInvite = async (e) => {
    e.preventDefault();
    if (!inv.email || !inv.companyId) { setInvErr('Email and company are required'); return; }
    setInvBusy(true); setInvMsg(''); setInvErr('');
    try {
      await api.post('/soc/invitations', {
        email: inv.email.trim().toLowerCase(),
        role: inv.role,
        companyIds: [inv.companyId],
        departmentIds: inv.departmentIds.length ? inv.departmentIds : undefined,
      });
      setInvMsg(`Invite sent to ${inv.email}`);
      setInv({ email:'', role:'soc_manager', companyId:'', departmentIds:[] });
    } catch (err) {
      setInvErr(err.response?.data?.message || 'Failed to send invite');
    } finally { setInvBusy(false); }
  };

  const roleCounts = users.reduce((acc, u) => {
    acc[u.role || 'unknown'] = (acc[u.role || 'unknown'] || 0) + 1;
    return acc;
  }, {});
  const activeUsers = users.filter(u => u.isActive).length;
  const disabledUsers = users.length - activeUsers;
  const socManagerCount = users.filter(u => u.role === 'soc_manager').length;
  const analystCount = users.filter(u => ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(u.role)).length;
  const tenantCount = new Set(users.map(u => u.tenantId?._id || u.tenantId).filter(Boolean)).size;
  const companyUserCount = users.filter(u => u.companyId).length;

  const filtered = users.filter(u => {
    const matchesRole = roleFilter === 'all' || u.role === roleFilter;
    const q = search.trim().toLowerCase();
    const matchesSearch = !q ||
      u.name?.toLowerCase().includes(q) ||
      u.email?.toLowerCase().includes(q) ||
      u.companyId?.name?.toLowerCase().includes(q) ||
      u.tenantId?.name?.toLowerCase().includes(q) ||
      u.partnerId?.name?.toLowerCase().includes(q) ||
      u.role?.toLowerCase().includes(q);
    return matchesRole && matchesSearch;
  });

  const S = {
    inp: {
      padding:'7px 10px', borderRadius:6, border:'1px solid #312e81',
      background:'#1a1730', color:'#e2e8f0', fontSize:13, outline:'none',
    },
  };

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:16, marginBottom:22, flexWrap:'wrap' }}>
        <div>
          <h2 style={{ fontSize:22, color:'#e9d5ff', margin:'0 0 5px' }}>
            {isAnalystView ? 'Super Admin SOC Team' : 'SOC Identity Command & Users'}
          </h2>
          <div style={{ fontSize:12, color:'#8b5cf6' }}>
            {isAnalystView
              ? 'SOC Managers and L1–L4 Analysts managed by Super Admin'
              : 'Platform identity control across tenants, partners, companies, SOC Managers and Analysts'}
          </div>
        </div>
        <div style={{ display:'flex', gap:10, alignItems:'center' }}>
          <input
            type="text" placeholder="Search users, tenant, partner, company…"
            value={search} onChange={e => setSearch(e.target.value)}
            style={{ ...S.inp, width:280, boxSizing:'border-box' }}/>
          <button onClick={() => setShowInvite(v => !v)} style={{
            fontSize:13, padding:'7px 16px', borderRadius:6, border:'none',
            background: showInvite ? '#2e1065' : '#7c3aed', color:'#fff', cursor:'pointer', fontWeight:700,
          }}>
            {showInvite ? 'Cancel' : '+ Invite Staff'}
          </button>
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(150px, 1fr))', gap:12, marginBottom:18 }}>
        {isAnalystView ? (
          <>
            <Metric label="Total SOC Accounts" value={users.length} color="#a78bfa" />
            <Metric label="SOC Managers" value={socManagerCount} color="#22d3ee" />
            <Metric label="Analysts (L1–L4)" value={analystCount} color="#60a5fa" />
            <Metric label="Active Accounts" value={activeUsers} color="#34d399" />
            <Metric label="Disabled Accounts" value={disabledUsers} color="#f87171" />
          </>
        ) : (
          <>
            <Metric label="Total Users" value={users.length} color="#a78bfa" />
            <Metric label="Active Users" value={activeUsers} color="#34d399" />
            <Metric label="Disabled Users" value={disabledUsers} color="#f87171" />
            <Metric label="Tenant Scope" value={tenantCount} color="#22d3ee" />
            <Metric label="Company Users" value={companyUserCount} color="#60a5fa" />
          </>
        )}
      </div>

      <div style={{
        background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10,
        padding:14, marginBottom:18,
      }}>
        <div style={{ display:'flex', justifyContent:'space-between', gap:12, flexWrap:'wrap', alignItems:'center' }}>
          <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
            <button onClick={() => setRoleFilter('all')} style={filterBtn(roleFilter === 'all')}>
              All <span style={{ opacity:.75 }}>{users.length}</span>
            </button>
            {(isAnalystView
              ? ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst']
              : ROLE_ORDER
            ).map(role => (
              <button key={role} onClick={() => setRoleFilter(role)} style={filterBtn(roleFilter === role)}>
                {ROLE_STYLE[role]?.label || role} <span style={{ opacity:.75 }}>{roleCounts[role] || 0}</span>
              </button>
            ))}
          </div>
          <div style={{ color:'#8b5cf6', fontSize:12 }}>
            Showing {filtered.length} of {users.length}
          </div>
        </div>
      </div>

      {/* Invite panel */}
      {showInvite && (
        <form onSubmit={sendInvite} style={{
          background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10,
          padding:'20px 22px', marginBottom:22,
        }}>
          <h3 style={{ fontSize:14, color:'#a78bfa', marginBottom:14 }}>Invite SOC Team Member</h3>

          {invMsg && <div style={{ background:'#064e3b', color:'#34d399', padding:'7px 12px', borderRadius:6, marginBottom:12, fontSize:13 }}>{invMsg}</div>}
          {invErr && <div style={{ background:'#1c0a0a', color:'#fca5a5', padding:'7px 12px', borderRadius:6, marginBottom:12, fontSize:13 }}>{invErr}</div>}

          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr 1fr', gap:12, marginBottom:14 }}>
            {/* Email */}
            <div>
              <label style={{ display:'block', color:'#7c3aed', fontSize:11, marginBottom:3 }}>Email (Read-only on profile) *</label>
              <input type="email" required value={inv.email} placeholder="user@company.com"
                onChange={e => setInv(v => ({ ...v, email:e.target.value }))}
                style={{ ...S.inp, width:'100%', boxSizing:'border-box' }}/>
            </div>

            {/* Role Selector */}
            <div>
              <label style={{ display:'block', color:'#7c3aed', fontSize:11, marginBottom:3 }}>Role *</label>
              <div style={{ ...S.inp, color:'#67e8f9', fontWeight:700, cursor:'default' }}>
                SOC Manager
              </div>
            </div>

            {/* Company */}
            <div>
              <label style={{ display:'block', color:'#7c3aed', fontSize:11, marginBottom:3 }}>Company Scope *</label>
              <select required value={inv.companyId}
                onChange={e => setInv(v => ({ ...v, companyId:e.target.value, departmentIds:[] }))}
                style={{ ...S.inp, width:'100%', boxSizing:'border-box', cursor:'pointer' }}>
                <option value="">Select company</option>
                {companies.map(c => <option key={c._id} value={c._id}>{c.name}</option>)}
              </select>
            </div>

            {/* Departments */}
            <div>
              <label style={{ display:'block', color:'#7c3aed', fontSize:11, marginBottom:3 }}>Department Scope</label>
              {depts.length > 0 ? (
                <div style={{ background:'#0f172a', border:'1px solid #312e81', borderRadius:6, padding:'6px', maxHeight:120, overflowY:'auto' }}>
                  {depts.map(d => (
                    <label key={d._id} style={{ display:'flex', alignItems:'center', gap:6, padding:'2px 4px', fontSize:11, color:'#e2e8f0' }}>
                      <input type="checkbox" checked={inv.departmentIds.includes(d._id)} onChange={e => setInv(prev => ({
                        ...prev, departmentIds: e.target.checked ? [...prev.departmentIds, d._id] : prev.departmentIds.filter(id => id !== d._id)
                      }))} /> {d.name}
                    </label>
                  ))}
                </div>
              ) : (
                <small style={{ color:'#64748b' }}>All Departments</small>
              )}
            </div>
          </div>

          <button type="submit" disabled={invBusy || !inv.email || !inv.companyId} style={{
            padding:'8px 20px', borderRadius:6, border:'none',
            background: (invBusy || !inv.email || !inv.companyId) ? '#2e1065' : '#7c3aed',
            color:'#fff', fontSize:13, cursor:'pointer', fontWeight:700
          }}>
            {invBusy ? 'Sending…' : 'Send Invitation'}
          </button>
        </form>
      )}

      {/* User list */}
      {loadError && (
        <div style={{ background:'#1c0a0a', color:'#fca5a5', padding:'9px 12px', borderRadius:6, marginBottom:12, fontSize:13 }}>
          {loadError}
        </div>
      )}
      {loading
        ? <p style={{ color:'#4c1d95', fontSize:13 }}>Loading users…</p>
        : filtered.map(u => (
          <div key={u._id} style={{
            background:'#1e1b4b', border:'1px solid #312e81', borderRadius:8,
            padding:'11px 14px', marginBottom:8,
            display:'flex', justifyContent:'space-between', alignItems:'center', gap:12,
          }}>
            <div style={{ flex:1 }}>
              <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                <div style={{
                  width:28, height:28, borderRadius:8, background:'#0f172a',
                  border:'1px solid #312e81', display:'grid', placeItems:'center',
                  color:'#c4b5fd', fontSize:12, fontWeight:800,
                }}>
                  {(u.name || u.email || '?').slice(0, 1).toUpperCase()}
                </div>
                <div>
                  <div style={{ fontSize:13, color:'#e2e8f0', fontWeight:600 }}>{u.name}</div>
                  <div style={{ fontSize:11, color:'#8b5cf6' }}>{u.email}</div>
                </div>
              </div>
              <div style={{ fontSize:11, color:'#4c1d95', display:'flex', gap:10, flexWrap:'wrap' }}>
                {u.tenantId?.name && <span>🏷 {u.tenantId.name}</span>}
                {u.partnerId?.name && <span>🤝 {u.partnerId.name}</span>}
                {u.companyId?.name && <span>🏢 {u.companyId.name}</span>}
                {u.departmentId?.name && <span>📁 {u.departmentId.name}</span>}
              </div>
            </div>
            <div style={{ display:'flex', gap:8, alignItems:'center' }}>
              <span style={{ fontSize:10, padding:'2px 8px', borderRadius:10,
                             background: (u && u.role && ROLE_STYLE[u.role]?.bg) || '#2e1065',
                             color:      (u && u.role && ROLE_STYLE[u.role]?.color) || '#c4b5fd' }}>
                {(u && u.role && ROLE_STYLE[u.role]?.label) || (u?.role || 'N/A')}
              </span>
              <span style={{ fontSize:10, padding:'2px 8px', borderRadius:10,
                             background: u.isActive ? '#064e3b' : '#7f1d1d',
                             color:      u.isActive ? '#34d399' : '#fca5a5' }}>
                {u.isActive ? 'active' : 'disabled'}
              </span>
              {(u && u.role !== 'superadmin') && (
                <button onClick={() => toggle(u)} style={{
                  fontSize:11, padding:'3px 10px', borderRadius:4, border:'none', cursor:'pointer',
                  background: u.isActive ? '#7f1d1d' : '#064e3b',
                  color:      u.isActive ? '#fca5a5' : '#34d399',
                }}>
                  {u.isActive ? 'Disable' : 'Enable'}
                </button>
              )}
            </div>
          </div>
        ))
      }

      {!loading && filtered.length === 0 && (
        <div style={{
          background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10,
          padding:24, color:'#8b5cf6', textAlign:'center', fontSize:13,
        }}>
          No users found for this filter.
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, color }) {
  return (
    <div style={{ background:'#2e1065', border:`1px solid ${color}33`, borderRadius:10, padding:'14px 16px' }}>
      <div style={{ color, fontSize:26, fontWeight:700 }}>{value}</div>
      <div style={{ color:'#8b5cf6', fontSize:11, marginTop:2 }}>{label}</div>
    </div>
  );
}

function filterBtn(active) {
  return {
    border:'1px solid #312e81',
    background: active ? '#7c3aed' : '#0f172a',
    color: active ? '#fff' : '#c4b5fd',
    borderRadius:999,
    padding:'6px 11px',
    cursor:'pointer',
    fontSize:12,
  };
}
