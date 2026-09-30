import { useEffect, useState } from 'react';
import api from '../api/axios';
import {
  validateDeptName, validateEmail, validatePassword,
} from '../utils/validate';

const cardStyle = {
  background:'linear-gradient(135deg, rgba(12,26,46,.96), rgba(8,18,34,.96))',
  border:'1px solid rgba(30,58,95,.85)',
  borderRadius:12,
  boxShadow:'0 14px 34px rgba(0,0,0,.18)',
};

function StatPill({ icon, label, value, color = '#60a5fa', onAdd, adding = false }) {
  return (
    <div style={{
      display:'flex', alignItems:'center', gap:8, padding:'8px 10px',
      borderRadius:8, background:`${color}12`, border:`1px solid ${color}35`,
      minWidth:118,
    }}>
      <span style={{ fontSize:15 }}>{icon}</span>
      <div style={{ flex:1 }}>
        <div style={{ fontSize:15, fontWeight:800, color:'#e2e8f0', lineHeight:1 }}>{value}</div>
        <div style={{ fontSize:10, color, marginTop:3 }}>{label}</div>
      </div>
      {onAdd && (
        <button type="button" onClick={onAdd} disabled={adding} aria-label={`Add ${label} allocation`} style={{
          border:`1px solid ${color}66`, background:`${color}18`, color,
          borderRadius:6, padding:'3px 7px', fontSize:10, fontWeight:800,
          cursor:adding ? 'wait' : 'pointer', whiteSpace:'nowrap', opacity:adding ? .65 : 1,
        }}>{adding ? 'Adding…' : '+ Add'}</button>
      )}
    </div>
  );
}

function AllocationEditor({ dept, onSaved }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    assignedSystemCount: '0',
    assignedPhoneCount: '0',
    assignedServerCount: '0',
  });
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const save = async (e) => {
    e.preventDefault();
    const addCounts = {
      assignedSystemCount: Number(form.assignedSystemCount) || 0,
      assignedPhoneCount: Number(form.assignedPhoneCount) || 0,
      assignedServerCount: Number(form.assignedServerCount) || 0,
    };
    if (Object.values(addCounts).some(v => v < 0 || !Number.isInteger(v))) {
      setErr('Counts must be whole numbers 0 or more.');
      return;
    }
    if (Object.values(addCounts).every(v => v === 0)) {
      setErr('Enter at least 1 system, phone, or server to add.');
      return;
    }

    const payload = {
      assignedSystemCount: (Number(dept.assignedSystemCount) || 0) + addCounts.assignedSystemCount,
      assignedPhoneCount: (Number(dept.assignedPhoneCount) || 0) + addCounts.assignedPhoneCount,
      assignedServerCount: (Number(dept.assignedServerCount) || 0) + addCounts.assignedServerCount,
    };

    setBusy(true); setErr('');
    try {
      const { data } = await api.patch(`/department/${dept._id}`, payload);
      onSaved(data);
      setForm({ assignedSystemCount: '0', assignedPhoneCount: '0', assignedServerCount: '0' });
      setOpen(false);
    } catch (err) {
      const message = err.response?.data?.message || 'Failed to update allocation';
      setErr(message);
    } finally { setBusy(false); }
  };

  const limitReached = /exceed purchased limit|limit reached|purchase an additional license/i.test(err);

  if (!open) {
    return (
      <button onClick={() => {
        setForm({ assignedSystemCount: '0', assignedPhoneCount: '0', assignedServerCount: '0' });
        setOpen(true);
      }} style={{
        fontSize:11, padding:'7px 12px', borderRadius:6, border:'1px solid #14b8a666',
        background:'#14b8a614', color:'#5eead4', cursor:'pointer', fontWeight:700,
      }}>Add more systerm</button>
    );
  }

  return (
    <form onSubmit={save} style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(90px, 1fr)) auto auto', gap:8, alignItems:'end', marginTop:12, padding:12, borderRadius:8, background:'#060e1a', border:'1px solid #1e3a5f' }}>
      {[
        ['assignedSystemCount', 'Add systems'],
        ['assignedPhoneCount', 'Add phones'],
        ['assignedServerCount', 'Add servers'],
      ].map(([key, label]) => (
        <label key={key} style={{ fontSize:10, color:'#60a5fa' }}>
          {label}
          <input
            type="number"
            min="0"
            step="1"
            value={form[key]}
            onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
            style={{
              display:'block', width:'100%', marginTop:3, padding:'6px 8px',
              borderRadius:6, boxSizing:'border-box', background:'#081426',
              color:'#e2e8f0', border:'1px solid #1e3a5f', fontSize:12,
            }}
          />
        </label>
      ))}
      <button type="submit" disabled={busy} style={{
        fontSize:11, padding:'6px 12px', borderRadius:4, border:'none',
        background: busy ? '#1e3a5f' : '#2563eb', color:'#fff', cursor:'pointer',
      }}>{busy ? 'Saving...' : 'Save'}</button>
      <button type="button" onClick={() => { setOpen(false); setErr(''); }} style={{
        fontSize:11, padding:'6px 10px', borderRadius:4, border:'1px solid #1e3a5f',
        background:'none', color:'#60a5fa', cursor:'pointer',
      }}>Cancel</button>
      {err && (
        <div style={{
          gridColumn:'1 / -1',
          fontSize:11,
          color:'#fca5a5',
          background:'#1c0a0a',
          border:'1px solid #7f1d1d',
          borderRadius:6,
          padding:'8px 10px',
        }}>
          {err}
          {limitReached && (
            <a href="/payments?tab=upgrade" style={{ color:'#f59e0b', marginLeft:8, fontWeight:700, textDecoration:'none' }}>
              Add more License →
            </a>
          )}
        </div>
      )}
    </form>
  );
}

export default function DepartmentsPage({ companyId: propCompanyId }) {
  const activeCompanyId = propCompanyId || localStorage.getItem('sa_active_company_id');
  const [depts,    setDepts]    = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [apiErr,   setApiErr]   = useState('');
  const [showForm, setShowForm] = useState(false);
  const [form,     setForm]     = useState({
    name:'',
    description:'',
    assignedSystemCount:'0',
    assignedPhoneCount:'0',
    assignedServerCount:'0',
    adminEmail:'',
    adminName:'',
    adminPassword:'',
  });
  const [errors,   setErrors]   = useState({});
  const [busy,     setBusy]     = useState(false);
  const [formErr,  setFormErr]  = useState('');
  const [addingAllocation, setAddingAllocation] = useState('');
  const [allocationDialog, setAllocationDialog] = useState(null);
  const [allocationQuantity, setAllocationQuantity] = useState('1');
  const [allocationError, setAllocationError] = useState('');
  const totals = depts.reduce((acc, d) => ({
    systems: acc.systems + (Number(d.assignedSystemCount) || 0),
    phones: acc.phones + (Number(d.assignedPhoneCount) || 0),
    servers: acc.servers + (Number(d.assignedServerCount) || 0),
    registered: acc.registered + (
      (Number(d.systemUsedCount) || 0) +
      (Number(d.phoneUsedCount) || 0) +
      (Number(d.serverUsedCount) || 0) ||
      (Number(d.systemCount) || 0)
    ),
  }), { systems:0, phones:0, servers:0, registered:0 });

  useEffect(() => {
    const q = activeCompanyId ? `?companyId=${activeCompanyId}` : '';
    api.get(`/department${q}`)
      .then(r => setDepts(r.data.departments || r.data || []))
      .catch(err => setApiErr(err.response?.data?.message || 'Failed to load departments'))
      .finally(() => setLoading(false));
  }, [activeCompanyId]);

  const createDept = async (e) => {
    e.preventDefault();
    const errs = {
      name:          validateDeptName(form.name),
      adminEmail:    form.adminEmail ? validateEmail(form.adminEmail) : null,
      adminPassword: form.adminEmail ? validatePassword(form.adminPassword) : null,
      assignedSystemCount: validateCount(form.assignedSystemCount),
      assignedPhoneCount:  validateCount(form.assignedPhoneCount),
      assignedServerCount: validateCount(form.assignedServerCount),
    };
    setErrors(errs);
    if (Object.values(errs).some(Boolean)) return;

    setBusy(true); setFormErr('');
    try {
      const { data } = await api.post('/department', {
        name:          form.name.trim(),
        description:   form.description.trim(),
        assignedSystemCount: Number(form.assignedSystemCount) || 0,
        assignedPhoneCount:  Number(form.assignedPhoneCount) || 0,
        assignedServerCount: Number(form.assignedServerCount) || 0,
        adminEmail:    form.adminEmail.trim() || undefined,
        adminName:     form.adminName.trim()  || undefined,
        adminPassword: form.adminPassword     || undefined,
      });
      setDepts(prev => [data.department, ...prev]);
      setShowForm(false);
      setForm({ name:'', description:'', assignedSystemCount:'0', assignedPhoneCount:'0', assignedServerCount:'0', adminEmail:'', adminName:'', adminPassword:'' });
      setErrors({});
    } catch (err) {
      setFormErr(err.response?.data?.message || 'Failed to create department');
    } finally { setBusy(false); }
  };

  const deleteDept = async (id) => {
    if (!confirm('Delete this department? All systems must be removed first.')) return;
    try {
      await api.delete(`/department/${id}`);
      setDepts(prev => prev.filter(d => d._id !== id));
    } catch (err) {
      alert(err.response?.data?.message || 'Delete failed');
    }
  };

  const handleAllocationSaved = (dept) => {
    setDepts(prev => prev.map(d => d._id === dept._id ? {
      ...d,
      ...dept,
      systemUsedCount: d.systemUsedCount || 0,
      phoneUsedCount: d.phoneUsedCount || 0,
      serverUsedCount: d.serverUsedCount || 0,
    } : d));
  };

  const openAllocationDialog = (dept, field, categoryLabel) => {
    setAllocationDialog({ dept, field, categoryLabel });
    setAllocationQuantity('1');
    setAllocationError('');
  };

  const addCategoryAllocation = async (e) => {
    e.preventDefault();
    if (!allocationDialog) return;
    const quantity = Number(allocationQuantity);
    if (!Number.isInteger(quantity) || quantity < 1) {
      setAllocationError('Please enter a whole number greater than 0.');
      return;
    }
    const { dept, field } = allocationDialog;
    const operationKey = `${dept._id}:${field}`;
    setAddingAllocation(operationKey);
    setAllocationError('');
    try {
      const { data } = await api.patch(`/department/${dept._id}`, {
        [field]: (Number(dept[field]) || 0) + quantity,
      });
      handleAllocationSaved(data);
      setAllocationDialog(null);
    } catch (err) {
      setAllocationError(err.response?.data?.message || 'License allocation add nahi ho saki.');
    } finally {
      setAddingAllocation('');
    }
  };

  const validateCount = (value) => {
    const num = Number(value);
    if (!Number.isInteger(num) || num < 0) return 'Enter a whole number 0 or more';
    return null;
  };

  const inp = (key, label, type='text', required=false) => (
    <div style={{ marginBottom:12 }}>
      <label style={{ display:'block', color:'#60a5fa', fontSize:11, marginBottom:3 }}>
        {label}{required && ' *'}
      </label>
      <input type={type} value={form[key]}
        onChange={e => { setForm(f => ({ ...f, [key]:e.target.value })); setErrors(er => ({ ...er, [key]:null })); }}
        style={{
          width:'100%', padding:'10px 12px', borderRadius:8, boxSizing:'border-box',
          background:'#060e1a', color:'#e2e8f0', fontSize:13,
          border:`1px solid ${errors[key] ? '#f87171' : '#1e3a5f'}`,
        }}/>
      {errors[key] && <div style={{ fontSize:11, color:'#f87171', marginTop:2 }}>{errors[key]}</div>}
    </div>
  );

  const countInp = (key, label) => (
    <div style={{ marginBottom:12 }}>
      <label style={{ display:'block', color:'#60a5fa', fontSize:11, marginBottom:3 }}>{label}</label>
      <input
        type="number"
        min="0"
        step="1"
        value={form[key]}
        onChange={e => { setForm(f => ({ ...f, [key]:e.target.value })); setErrors(er => ({ ...er, [key]:null })); }}
        style={{
          width:'100%', padding:'10px 12px', borderRadius:8, boxSizing:'border-box',
          background:'#060e1a', color:'#e2e8f0', fontSize:13,
          border:`1px solid ${errors[key] ? '#f87171' : '#1e3a5f'}`,
        }}
      />
      {errors[key] && <div style={{ fontSize:11, color:'#f87171', marginTop:2 }}>{errors[key]}</div>}
    </div>
  );

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:18, marginBottom:18 }}>
        <div>
          <h2 style={{ fontSize:22, color:'#e0f2fe', margin:'0 0 5px' }}>
            Departments <span style={{ fontSize:13, color:'#60a5fa', fontWeight:500 }}>({depts.length})</span>
          </h2>
          <div style={{ fontSize:12, color:'#60a5fa' }}>
            Organize teams, allocate licenses, and assign systems by department.
          </div>
        </div>
        <button onClick={() => setShowForm(v => !v)} style={{
          fontSize:13, padding:'9px 16px', borderRadius:8, border:'1px solid #2563eb66',
          background: showForm ? '#1e3a5f' : 'linear-gradient(135deg,#2563eb,#1d4ed8)', color:'#fff', cursor:'pointer',
          fontWeight:700,
        }}>
          {showForm ? '✕ Cancel' : '+ New department'}
        </button>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(170px, 1fr))', gap:10, marginBottom:18 }}>
        <StatPill icon="🏢" label="Departments" value={depts.length} />
        <StatPill icon="🖥" label="Assigned systems" value={totals.systems} color="#38bdf8" />
        <StatPill icon="📱" label="Assigned phones" value={totals.phones} color="#a78bfa" />
        <StatPill icon="🖧" label="Assigned servers" value={totals.servers} color="#14b8a6" />
        <StatPill icon="✅" label="Registered systems" value={totals.registered} color="#34d399" />
      </div>

      {apiErr && (
        <div style={{ background:'#1c0a0a', color:'#fca5a5', padding:'10px 14px',
                      borderRadius:6, marginBottom:14, fontSize:13 }}>{apiErr}</div>
      )}

      {/* Create form */}
      {showForm && (
        <form onSubmit={createDept} noValidate style={{
          ...cardStyle,
          padding:'20px 22px', marginBottom:22,
        }}>
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:12, marginBottom:16 }}>
            <h3 style={{ fontSize:16, color:'#e0f2fe', margin:0 }}>New department</h3>
            <span style={{ fontSize:10, color:'#60a5fa', padding:'4px 9px', borderRadius:999, border:'1px solid #1e3a5f', background:'#060e1a' }}>
              License allocation
            </span>
          </div>
          {formErr && (
            <div style={{ background:'#1c0a0a', color:'#fca5a5', padding:'7px 12px',
                          borderRadius:6, marginBottom:12, fontSize:13 }}>{formErr}</div>
          )}
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
            {inp('name',        'Department name', 'text', true)}
            {inp('description', 'Description')}
          </div>
          <p style={{ fontSize:11, color:'#60a5fa', margin:'8px 0 12px', fontWeight:700 }}>
            Assign licenses to this department
          </p>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>
            {countInp('assignedSystemCount', 'System licenses')}
            {countInp('assignedPhoneCount',  'Phone licenses')}
            {countInp('assignedServerCount', 'Server licenses')}
          </div>
          <p style={{ fontSize:11, color:'#60a5fa', margin:'8px 0 12px', fontWeight:700 }}>
            Optional: create a department admin account now
          </p>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>
            {inp('adminName',     'Admin name')}
            {inp('adminEmail',    'Admin email',    'email')}
            {inp('adminPassword', 'Admin password', 'password')}
          </div>
          <button type="submit" disabled={busy} style={{
            padding:'10px 20px', borderRadius:8, border:'none', marginTop:8,
            background: busy ? '#1e3a5f' : '#2563eb', color:'#fff', fontSize:13, cursor:'pointer',
            fontWeight:700,
          }}>
            {busy ? 'Creating…' : 'Create department'}
          </button>
        </form>
      )}

      {/* List */}
      {loading
        ? <p style={{ color:'#1e40af', fontSize:13 }}>Loading…</p>
        : depts.length === 0
          ? (
            <div style={{ background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:10,
                           padding:32, textAlign:'center' }}>
              <p style={{ color:'#1e40af', fontSize:13, marginBottom:4 }}>No departments yet.</p>
              <p style={{ color:'#1e3a5f', fontSize:12 }}>
                Create departments to organise your systems and alerts by team or location.
              </p>
            </div>
          )
          : depts.map(d => (
            <div key={d._id} style={{
              ...cardStyle,
              padding:'16px 18px', marginBottom:12,
            }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12 }}>
                <div style={{ flex:1 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:5 }}>
                    <div style={{ width:34, height:34, borderRadius:9, background:'#2563eb18', border:'1px solid #2563eb44', display:'flex', alignItems:'center', justifyContent:'center', fontSize:17 }}>
                      🏢
                    </div>
                    <div>
                      <div style={{ fontSize:16, fontWeight:800, color:'#e2e8f0' }}>{d.name}</div>
                      {d.description && (
                        <div style={{ fontSize:12, color:'#60a5fa', marginTop:2 }}>{d.description}</div>
                      )}
                    </div>
                  </div>
                  <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginTop:12 }}>
                    <StatPill icon="✅" label="Registered" value={
                      (Number(d.systemUsedCount) || 0) +
                      (Number(d.phoneUsedCount) || 0) +
                      (Number(d.serverUsedCount) || 0) ||
                      (Number(d.systemCount) || 0)
                    } color="#34d399" />
                    <StatPill icon="🖥" label="Systems used" value={`${d.systemUsedCount || 0}/${d.assignedSystemCount || 0}`} color="#38bdf8" onAdd={() => openAllocationDialog(d, 'assignedSystemCount', 'System')} adding={addingAllocation === `${d._id}:assignedSystemCount`} />
                    <StatPill icon="📱" label="Phones used" value={`${d.phoneUsedCount || 0}/${d.assignedPhoneCount || 0}`} color="#a78bfa" onAdd={() => openAllocationDialog(d, 'assignedPhoneCount', 'Phone')} adding={addingAllocation === `${d._id}:assignedPhoneCount`} />
                    <StatPill icon="🖧" label="Servers used" value={`${d.serverUsedCount || 0}/${d.assignedServerCount || 0}`} color="#14b8a6" onAdd={() => openAllocationDialog(d, 'assignedServerCount', 'Server')} adding={addingAllocation === `${d._id}:assignedServerCount`} />
                  </div>
                  {d.adminId && <div style={{ fontSize:11, color:'#93c5fd', marginTop:10 }}>Admin: {d.adminId.name || d.adminId.email}</div>}
                </div>
                <div style={{ display:'flex', gap:6, alignItems:'center', flexShrink:0 }}>
                  <span style={{
                    fontSize:10, padding:'2px 8px', borderRadius:10,
                    background: d.isActive ? '#064e3b' : '#7f1d1d',
                    color:      d.isActive ? '#34d399' : '#fca5a5',
                  }}>{d.isActive ? 'active' : 'inactive'}</span>
                  <button onClick={() => deleteDept(d._id)} style={{
                    fontSize:11, padding:'3px 10px', borderRadius:4, border:'none',
                    background:'#7f1d1d', color:'#fca5a5', cursor:'pointer',
                  }}>Delete</button>
                </div>
              </div>

            </div>
          ))
      }

      {allocationDialog && (
        <div role="dialog" aria-modal="true" onMouseDown={e => {
          if (e.target === e.currentTarget && !addingAllocation) setAllocationDialog(null);
        }} style={{
          position:'fixed', inset:0, zIndex:10000, background:'rgba(2,6,23,.78)',
          display:'flex', alignItems:'center', justifyContent:'center', padding:20,
        }}>
          <form onSubmit={addCategoryAllocation} style={{
            width:'100%', maxWidth:420, background:'#0b172a', border:'1px solid #1e3a5f',
            borderRadius:12, padding:20, boxShadow:'0 24px 70px rgba(0,0,0,.55)',
          }}>
            <h3 style={{ margin:'0 0 5px', color:'#e2e8f0', fontSize:17 }}>
              Add {allocationDialog.categoryLabel} Licenses
            </h3>
            <div style={{ color:'#60a5fa', fontSize:12, marginBottom:18 }}>
              Department: <strong>{allocationDialog.dept.name}</strong>
            </div>
            <label style={{ display:'block', color:'#93c5fd', fontSize:11, marginBottom:5 }}>
              How many licenses do you want to add?
            </label>
            <input autoFocus type="number" min="1" step="1" value={allocationQuantity}
              onChange={e => { setAllocationQuantity(e.target.value); setAllocationError(''); }}
              style={{
                width:'100%', boxSizing:'border-box', padding:'10px 12px', borderRadius:7,
                background:'#060e1a', color:'#fff', border:`1px solid ${allocationError ? '#ef4444' : '#2563eb'}`,
                fontSize:14, outline:'none',
              }}
            />
            {allocationError && <div style={{ color:'#fca5a5', fontSize:11, marginTop:7 }}>{allocationError}</div>}
            <div style={{ display:'flex', justifyContent:'flex-end', gap:8, marginTop:18 }}>
              <button type="button" disabled={Boolean(addingAllocation)} onClick={() => setAllocationDialog(null)} style={{
                padding:'8px 14px', borderRadius:6, border:'1px solid #334155',
                background:'transparent', color:'#94a3b8', cursor:'pointer',
              }}>Cancel</button>
              <button type="submit" disabled={Boolean(addingAllocation)} style={{
                padding:'8px 16px', borderRadius:6, border:'none', fontWeight:700,
                background:addingAllocation ? '#1e3a5f' : '#2563eb', color:'#fff',
                cursor:addingAllocation ? 'wait' : 'pointer',
              }}>{addingAllocation ? 'Adding…' : `Add ${allocationDialog.categoryLabel} Licenses`}</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
