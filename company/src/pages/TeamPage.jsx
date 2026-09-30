import { useEffect, useState } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';

const ROLE_META = {
  company_admin:    { label: 'Company Admin', color: '#c084fc', bg: 'rgba(168, 85, 247, 0.15)', border: 'rgba(168, 85, 247, 0.3)', gradient: 'linear-gradient(135deg, #9333ea, #6b21a8)', icon: '👑' },
  soc_manager:      { label: 'SOC Manager',   color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.15)', border: 'rgba(56, 189, 248, 0.3)', gradient: 'linear-gradient(135deg, #0284c7, #075985)', icon: '💬' },
  department_admin: { label: 'Dept Admin',    color: '#34d399', bg: 'rgba(52, 211, 153, 0.15)', border: 'rgba(52, 211, 153, 0.3)', gradient: 'linear-gradient(135deg, #059669, #064e3b)', icon: '📁' },
  analyst:          { label: 'Analyst',       color: '#fbbf24', bg: 'rgba(251, 191, 36, 0.15)', border: 'rgba(251, 191, 36, 0.3)', gradient: 'linear-gradient(135deg, #d97706, #78350f)', icon: '🛡️' },
};

export default function TeamPage() {
  const { user: me, isCompanyAdmin, isDeptAdmin } = useAuth();
  const [users,       setUsers]       = useState([]);
  const [depts,       setDepts]       = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [showForm,    setShowForm]    = useState(false);
  const [searchTerm,  setSearchTerm]  = useState('');
  const [form, setForm] = useState({ email: '', role: 'department_admin', departmentId: '' });
  const [busy, setBusy]   = useState(false);
  const [msg,  setMsg]    = useState('');
  const [err,  setErr]    = useState('');

  useEffect(() => {
    Promise.all([
      api.get('/users').then(r => setUsers(r.data)),
      api.get('/department').then(r => setDepts(r.data)),
    ]).finally(() => setLoading(false));
  }, []);

  const invite = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(''); setErr('');
    try {
      await api.post('/users/invite', form);
      setMsg(`Invitation successfully sent to ${form.email}`);
      setForm({ email: '', role: 'department_admin', departmentId: '' });
      setShowForm(false);
      api.get('/users').then(r => setUsers(r.data));
    } catch (err) {
      setErr(err.response?.data?.message || 'Failed to send invite');
    } finally { setBusy(false); }
  };

  const changeRole = async (userId, role) => {
    const { data } = await api.patch(`/users/${userId}`, { role });
    setUsers(prev => prev.map(u => u._id === data._id ? data : u));
  };

  const toggleActive = async (u) => {
    const { data } = await api.patch(`/users/${u._id}`, { isActive: !u.isActive });
    setUsers(prev => prev.map(x => x._id === data._id ? data : x));
  };

  // Company admins manage administrative roles. Department admins get a
  // read-only roster of users assigned to their own department by the API.
  const teamUsers = users.filter(u => isDeptAdmin
    ? ['department_admin', 'analyst', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(u.role)
    : ['company_admin', 'soc_manager', 'department_admin'].includes(u.role));

  const filteredUsers = teamUsers.filter(u =>
    (u.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (u.email || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  const counts = {
    total: teamUsers.length,
    admins: teamUsers.filter(u => u.role === 'company_admin').length,
    soc: teamUsers.filter(u => u.role === 'soc_manager').length,
    depts: teamUsers.filter(u => u.role === 'department_admin').length,
    analysts: teamUsers.filter(u => ['analyst', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(u.role)).length,
  };

  const getInitials = (name = '') => {
    const parts = name.trim().split(' ');
    if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    return name.substring(0, 2).toUpperCase() || 'U';
  };

  return (
    <div style={{ maxWidth: 1200, margin: '0 auto', paddingBottom: 40, fontFamily: 'Inter, system-ui, sans-serif' }}>
      {/* ── Page Header ────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h2 style={{ fontSize: 24, color: '#f8fafc', fontWeight: 800, margin: 0, letterSpacing: '-0.5px', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span>👥 Team Management</span>
            <span style={{ fontSize: 12, background: 'rgba(37, 99, 235, 0.2)', color: '#60a5fa', padding: '3px 10px', borderRadius: 20, border: '1px solid rgba(96, 165, 250, 0.3)', fontWeight: 600 }}>
              {teamUsers.length} Members
            </span>
          </h2>
          <p style={{ color: '#64748b', fontSize: 13, margin: '4px 0 0 0' }}>
            {isDeptAdmin
              ? 'View administrators and analysts assigned to your department.'
              : 'Manage organization administrators, SOC managers, department leads, and security team roles.'}
          </p>
        </div>

        {isCompanyAdmin && (
          <button
            onClick={() => setShowForm(v => !v)}
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '10px 20px', borderRadius: 10, border: 'none',
              background: showForm ? '#334155' : 'linear-gradient(135deg, #2563eb, #3b82f6)',
              color: '#ffffff', fontSize: 13, fontWeight: 700, cursor: 'pointer',
              boxShadow: showForm ? 'none' : '0 4px 14px rgba(37, 99, 235, 0.4)',
              transition: 'all 0.2s ease',
            }}
          >
            <span>{showForm ? '✕ Cancel' : '+ Invite Team Member'}</span>
          </button>
        )}
      </div>

      {/* ── Notification Feedback ───────────────────────────────────── */}
      {msg && (
        <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid rgba(16, 185, 129, 0.4)', color: '#34d399', padding: '12px 16px', borderRadius: 10, marginBottom: 20, fontSize: 13, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>✅ {msg}</span>
          <button onClick={() => setMsg('')} style={{ background: 'none', border: 'none', color: '#34d399', cursor: 'pointer' }}>✕</button>
        </div>
      )}
      {err && (
        <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid rgba(239, 68, 68, 0.4)', color: '#f87171', padding: '12px 16px', borderRadius: 10, marginBottom: 20, fontSize: 13, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>⚠️ {err}</span>
          <button onClick={() => setErr('')} style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer' }}>✕</button>
        </div>
      )}

      {/* ── Stat Summary Cards Grid ─────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 24 }}>
        {[
          { title: 'Total Members', count: counts.total, icon: '👥', color: '#60a5fa', bg: 'rgba(37, 99, 235, 0.1)', border: 'rgba(59, 130, 246, 0.25)' },
          { title: isDeptAdmin ? 'Analysts' : 'Company Admins', count: isDeptAdmin ? counts.analysts : counts.admins, icon: isDeptAdmin ? '🛡️' : '👑', color: '#c084fc', bg: 'rgba(168, 85, 247, 0.1)', border: 'rgba(168, 85, 247, 0.25)' },
          { title: isDeptAdmin ? 'Department Scope' : 'SOC Managers', count: isDeptAdmin ? 1 : counts.soc, icon: isDeptAdmin ? '🏢' : '💬', color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.1)', border: 'rgba(56, 189, 248, 0.25)' },
          { title: 'Dept Admins', count: counts.depts, icon: '📁', color: '#34d399', bg: 'rgba(52, 211, 153, 0.1)', border: 'rgba(52, 211, 153, 0.25)' },
        ].map((card, idx) => (
          <div key={idx} style={{
            background: '#0b1528', border: `1px solid ${card.border}`, borderRadius: 14,
            padding: '16px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.2)', backdropFilter: 'blur(10px)',
          }}>
            <div>
              <div style={{ fontSize: 12, color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{card.title}</div>
              <div style={{ fontSize: 26, color: '#f8fafc', fontWeight: 800, marginTop: 4 }}>{card.count}</div>
            </div>
            <div style={{
              width: 44, height: 44, borderRadius: 12, background: card.bg,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 20, border: `1px solid ${card.border}`,
            }}>
              {card.icon}
            </div>
          </div>
        ))}
      </div>

      {/* ── Invite Member Floating Form ──────────────────────────────── */}
      {showForm && isCompanyAdmin && (
        <form onSubmit={invite} style={{
          background: 'linear-gradient(145deg, #0b172a, #07101e)', border: '1px solid #1e3a5f',
          borderRadius: 16, padding: '24px 28px', marginBottom: 28, boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20, borderBottom: '1px solid rgba(255,255,255,0.06)', paddingBottom: 12 }}>
            <span style={{ fontSize: 18 }}>📧</span>
            <h3 style={{ fontSize: 16, color: '#e0f2fe', fontWeight: 700, margin: 0 }}>Invite New Team Member</h3>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16, marginBottom: 20 }}>
            <div>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Email Address *</label>
              <input
                type="email"
                required
                placeholder="colleague@company.com"
                value={form.email}
                onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
                style={{
                  width: '100%', padding: '10px 14px', borderRadius: 8, boxSizing: 'border-box',
                  background: '#060d19', border: '1px solid #1e3a5f', color: '#f8fafc', fontSize: 13, outline: 'none',
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Assign Role *</label>
              <select
                value={form.role}
                onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
                style={{
                  width: '100%', padding: '10px 14px', borderRadius: 8, boxSizing: 'border-box',
                  background: '#060d19', border: '1px solid #1e3a5f', color: '#38bdf8', fontSize: 13, fontWeight: 600, outline: 'none',
                }}
              >
                <option value="department_admin">Department Admin</option>
                <option value="soc_manager">SOC Manager</option>
              </select>
            </div>

            <div>
              <label style={{ display: 'block', color: '#94a3b8', fontSize: 12, fontWeight: 600, marginBottom: 6 }}>Department (Optional)</label>
              <select
                value={form.departmentId}
                onChange={e => setForm(f => ({ ...f, departmentId: e.target.value }))}
                style={{
                  width: '100%', padding: '10px 14px', borderRadius: 8, boxSizing: 'border-box',
                  background: '#060d19', border: '1px solid #1e3a5f', color: '#34d399', fontSize: 13, outline: 'none',
                }}
              >
                <option value="">All Departments</option>
                {depts.map(d => <option key={d._id} value={d._id}>{d.name}</option>)}
              </select>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
            <span style={{ fontSize: 12, color: '#64748b' }}>An activation invitation link will be sent via email.</span>
            <button
              type="submit"
              disabled={busy || !form.email}
              style={{
                padding: '10px 24px', borderRadius: 8, border: 'none',
                background: busy ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #1d4ed8)',
                color: '#ffffff', fontSize: 13, fontWeight: 700, cursor: busy ? 'not-allowed' : 'pointer',
                boxShadow: '0 4px 14px rgba(37, 99, 235, 0.3)',
              }}
            >
              {busy ? 'Sending Invitation…' : 'Send Invitation'}
            </button>
          </div>
        </form>
      )}

      {/* ── Search Bar & Filter ─────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
        <div style={{ position: 'relative', minWidth: 280, flex: 1, maxWidth: 400 }}>
          <input
            type="text"
            placeholder="Search by name or email..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            style={{
              width: '100%', padding: '10px 16px 10px 38px', borderRadius: 10, boxSizing: 'border-box',
              background: '#0b1528', border: '1px solid #1e3a5f', color: '#f8fafc', fontSize: 13, outline: 'none',
            }}
          />
          <span style={{ position: 'absolute', left: 12, top: 10, color: '#475569', fontSize: 14 }}>🔍</span>
        </div>
      </div>

      {/* ── Member Cards Section ───────────────────────────────────── */}
      {loading ? (
        <div style={{ padding: '40px 0', textAlign: 'center', color: '#64748b', fontSize: 14 }}>Loading team members...</div>
      ) : filteredUsers.length === 0 ? (
        <div style={{ background: '#0b1528', border: '1px solid #1e3a5f', borderRadius: 14, padding: 40, textAlign: 'center', color: '#64748b' }}>
          No team members found matching "{searchTerm}"
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filteredUsers.map(u => {
            const roleMeta = ROLE_META[u.role] || ROLE_META.analyst;
            const isSelf = u._id === me?._id;
            const canManage = isCompanyAdmin && !isSelf && u.role !== 'company_admin';

            return (
              <div
                key={u._id}
                style={{
                  background: 'linear-gradient(145deg, #0b1528, #07101e)',
                  border: `1px solid ${isSelf ? 'rgba(59, 130, 246, 0.4)' : '#1e3a5f'}`,
                  borderRadius: 14, padding: '14px 20px',
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16,
                  flexWrap: 'wrap', transition: 'all 0.2s ease',
                  boxShadow: '0 4px 12px rgba(0, 0, 0, 0.15)',
                }}
              >
                {/* User Details */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 14, minWidth: 260 }}>
                  <div
                    style={{
                      width: 44, height: 44, borderRadius: '50%', background: roleMeta.gradient,
                      color: '#ffffff', fontWeight: 800, fontSize: 15,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      boxShadow: '0 2px 8px rgba(0,0,0,0.3)', border: '2px solid rgba(255,255,255,0.1)',
                      flexShrink: 0,
                    }}
                  >
                    {getInitials(u.name || u.email)}
                  </div>

                  <div>
                    <div style={{ fontSize: 14, color: '#f8fafc', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span>{u.name || 'Team Member'}</span>
                      {isSelf && (
                        <span style={{ fontSize: 10, background: 'rgba(37, 99, 235, 0.25)', color: '#60a5fa', padding: '2px 8px', borderRadius: 12, border: '1px solid rgba(96, 165, 250, 0.3)', fontWeight: 600 }}>
                          You
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 12, color: '#64748b', marginTop: 2, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>✉️ {u.email}</span>
                    </div>
                  </div>
                </div>

                {/* Role & Actions */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                  {/* Role Selector or Badge */}
                  {canManage ? (
                    <select
                      value={u.role}
                      onChange={e => changeRole(u._id, e.target.value)}
                      style={{
                        fontSize: 12, fontWeight: 700, padding: '6px 12px', borderRadius: 8,
                        background: roleMeta.bg, color: roleMeta.color, border: `1px solid ${roleMeta.border}`,
                        cursor: 'pointer', outline: 'none',
                      }}
                    >
                      <option value="soc_manager" style={{ background: '#0f172a', color: '#38bdf8' }}>SOC Manager</option>
                      <option value="department_admin" style={{ background: '#0f172a', color: '#34d399' }}>Dept Admin</option>
                    </select>
                  ) : (
                    <div
                      style={{
                        fontSize: 12, fontWeight: 700, padding: '6px 12px', borderRadius: 8,
                        background: roleMeta.bg, color: roleMeta.color, border: `1px solid ${roleMeta.border}`,
                        display: 'flex', alignItems: 'center', gap: 6,
                      }}
                    >
                      <span>{roleMeta.icon}</span>
                      <span>{roleMeta.label}</span>
                    </div>
                  )}

                  {/* Active / Disabled Status Badge */}
                  <div
                    style={{
                      fontSize: 11, fontWeight: 700, padding: '5px 12px', borderRadius: 20,
                      background: u.isActive ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                      color: u.isActive ? '#34d399' : '#f87171',
                      border: `1px solid ${u.isActive ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                      display: 'flex', alignItems: 'center', gap: 6,
                    }}
                  >
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: u.isActive ? '#10b981' : '#ef4444', boxShadow: `0 0 6px ${u.isActive ? '#10b981' : '#ef4444'}` }} />
                    <span>{u.isActive ? 'Active' : 'Disabled'}</span>
                  </div>

                  {/* Enable / Disable Button */}
                  {canManage && (
                    <button
                      onClick={() => toggleActive(u)}
                      style={{
                        fontSize: 12, fontWeight: 600, padding: '6px 14px', borderRadius: 8,
                        border: 'none', cursor: 'pointer', transition: 'all 0.2s ease',
                        background: u.isActive ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                        color: u.isActive ? '#f87171' : '#34d399',
                        outline: `1px solid ${u.isActive ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
                      }}
                    >
                      {u.isActive ? 'Disable' : 'Enable'}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
