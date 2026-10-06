import { useEffect, useState, useCallback } from 'react';
import api from '../api/axios';
import Swal from 'sweetalert2';
import EnterpriseManagement from '../components/EnterpriseManagement';
import { useSearchParams } from 'react-router-dom';
import { subscriptionStatus } from '../utils/subscriptionStatus';

const fmtInr  = (n) => `₹${Number(n || 0).toLocaleString('en-IN')}`;
const fmtDate = (d) => d ? new Date(d).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' }) : '—';
const fmtDateTime = (d) => d ? new Date(d).toLocaleString('en-IN', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }) : '—';

// ── Shared styles ──
const CSS = {
  page:    { minHeight:'100vh', background:'#0a0f1e', color:'#e2e8f0', fontFamily:"'Inter', system-ui, sans-serif", padding:'28px 32px' },
  card:    { background:'linear-gradient(135deg,#111827 0%,#1a2235 100%)', borderRadius:16, border:'1px solid #1e2d45', padding:24 },
  badge:   (color) => ({ padding:'3px 10px', borderRadius:20, fontSize:11, fontWeight:700, background:`${color}22`, color, border:`1px solid ${color}44` }),
  btn:     (bg, disabled) => ({ padding:'10px 18px', borderRadius:8, border:'none', background: disabled?'#1e2d45':bg, color: disabled?'#4b5563':'#fff', cursor:disabled?'not-allowed':'pointer', fontWeight:600, fontSize:13, transition:'all 0.2s' }),
  inp:     { background:'#0d1525', border:'1px solid #1e2d45', borderRadius:8, color:'#e2e8f0', padding:'10px 14px', fontSize:14, fontFamily:'inherit', outline:'none', width:'100%', boxSizing:'border-box', transition:'border-color 0.2s' },
  tab:     (active) => ({ padding:'10px 20px', border:'none', background:'transparent', color: active?'#60a5fa':'#4b5563', fontSize:13, fontWeight: active?700:400, cursor:'pointer', borderBottom: active?'2px solid #3b82f6':'2px solid transparent', transition:'all 0.2s', whiteSpace:'nowrap' }),
};

const EMPTY_FORM = { pricePerSystemMonthly:'', pricePerSystemYearly:'', pricePerPhoneMonthly:'', pricePerPhoneYearly:'', pricePerServerMonthly:'', pricePerServerYearly:'' };
const paymentCounts = p => {
  const useAdded = p?.isUpgrade || ['upgrade', 'renewal'].includes(p?.source);
  return {
    systems: Number(useAdded ? p?.addedSystems : p?.systemCount) || 0,
    servers: Number(useAdded ? p?.addedServers : p?.serverCount) || 0,
    phones: Number(useAdded ? p?.addedPhones : p?.phoneCount) || 0,
  };
};

const StatCard = ({ icon, label, value, color, sub }) => (
  <div style={{ ...CSS.card, position:'relative', overflow:'hidden' }}>
    <div style={{ position:'absolute', top:-10, right:-10, fontSize:60, opacity:0.06 }}>{icon}</div>
    <div style={{ fontSize:11, color:'#4b5563', marginBottom:6, textTransform:'uppercase', letterSpacing:'0.5px', fontWeight:600 }}>{label}</div>
    <div style={{ fontSize:30, fontWeight:800, color: color||'#e2e8f0' }}>{value}</div>
    {sub && <div style={{ fontSize:11, color:'#6b7280', marginTop:4 }}>{sub}</div>}
  </div>
);

export default function PaymentManagementPage() {
  const [searchParams] = useSearchParams();
  const [tab, setTab] = useState(searchParams.get('tab') === 'enterprise' ? 'enterprise' : 'pricing');
  useEffect(() => { if (searchParams.get('tab') === 'enterprise') setTab('enterprise'); }, [searchParams]);

  // Pricing — two sets stored separately
  const [pricing,      setPricing]      = useState(null); // { newUser:{...}, renewal:{...} }
  const [userType,     setUserType]     = useState('');   // 'new-user' | 'renewal-existing'
  const [pForm,        setPForm]        = useState(EMPTY_FORM);
  const [saving,       setSaving]       = useState(false);
  const [pMsg,         setPMsg]         = useState('');
  const [pErr,         setPErr]         = useState('');
  const [history,      setHistory]      = useState([]);
  const [pLoading,     setPLoading]     = useState(false);

  // Subscriptions
  const [subs,      setSubs]      = useState([]);
  const [subsQ,     setSubsQ]     = useState('');
  const [subsFilt,  setSubsFilt]  = useState('all');
  const [subsLoad,  setSubsLoad]  = useState(false);

  // Payments
  const [pays,      setPays]      = useState([]);
  const [paysLoad,  setPaysLoad]  = useState(false);

  // AutoPay
  const [apBusy,    setApBusy]    = useState({});

  // Deleting history
  const [delBusy,   setDelBusy]   = useState({});

  // Error
  const [error,     setError]     = useState('');

  // ── Loaders ──
  const loadPricing = useCallback(async () => {
    setPLoading(true);
    try {
      const [pRes, hRes] = await Promise.all([
        api.get('/pricing'),
        api.get('/pricing/history').catch(() => ({ data:{ history:[] } })),
      ]);
      setPricing(pRes.data);
      setHistory(hRes.data.history || []);
      // If a user type is already selected, reload its values into the form
      setPForm(prev => {
        if (!prev._type) return EMPTY_FORM;
        const set = prev._type === 'new-user' ? pRes.data.newUser : pRes.data.renewal;
        return set
	          ? { pricePerSystemMonthly: set.pricePerSystemMonthly, pricePerSystemYearly: set.pricePerSystemYearly, pricePerPhoneMonthly: set.pricePerPhoneMonthly, pricePerPhoneYearly: set.pricePerPhoneYearly, pricePerServerMonthly: set.pricePerServerMonthly, pricePerServerYearly: set.pricePerServerYearly, _type: prev._type }
          : prev;
      });
    } catch (e) { setError('Failed to load pricing'); }
    finally { setPLoading(false); }
  }, []);

  const loadSubs = useCallback(async () => {
    setSubsLoad(true);
    try { const r = await api.get('/superadmin/subscriptions'); setSubs(r.data||[]); }
    catch { setError('Failed to load subscriptions'); }
    finally { setSubsLoad(false); }
  }, []);

  const loadPays = useCallback(async () => {
    setPaysLoad(true);
    try { const r = await api.get('/superadmin/payments?limit=50'); setPays(r.data||[]); }
    catch { setError('Failed to load payments'); }
    finally { setPaysLoad(false); }
  }, []);

  useEffect(() => {
    if (tab==='pricing')       { loadPricing(); }
    if (tab==='subscriptions') { loadSubs(); }
    if (tab==='payments')      { loadPays(); }
    if (tab==='autopay')       { loadSubs(); }
  }, [tab]);

  useEffect(() => {
    if (tab !== 'subscriptions') return;
    window.addEventListener('focus', loadSubs);
    return () => window.removeEventListener('focus', loadSubs);
  }, [tab, loadSubs]);

  // ── When user type changes, load that type's prices into the form ──
  const handleUserTypeChange = (type) => {
    setUserType(type);
    setPErr(''); setPMsg('');
    if (!type || !pricing) { setPForm(EMPTY_FORM); return; }
    const set = type === 'new-user' ? pricing.newUser : pricing.renewal;
    if (set) {
      setPForm({
	        pricePerSystemMonthly: set.pricePerSystemMonthly ?? '',
	        pricePerSystemYearly:  set.pricePerSystemYearly  ?? '',
	        pricePerPhoneMonthly:  set.pricePerPhoneMonthly  ?? set.pricePerSystemMonthly ?? '',
	        pricePerPhoneYearly:   set.pricePerPhoneYearly   ?? set.pricePerSystemYearly ?? '',
	        pricePerServerMonthly: set.pricePerServerMonthly ?? '',
        pricePerServerYearly:  set.pricePerServerYearly  ?? '',
        _type: type,
      });
    }
  };

  // ── Save pricing for selected user type only ──
  const savePricing = async () => {
    if (!userType) {
      setPErr('❌ Please select a user type (New User or Renewal for Existing User)');
      return;
    }
	    const keys = ['pricePerSystemMonthly','pricePerSystemYearly','pricePerPhoneMonthly','pricePerPhoneYearly','pricePerServerMonthly','pricePerServerYearly'];
    for (const k of keys) {
      if (pForm[k]==='' || isNaN(Number(pForm[k])) || Number(pForm[k]) < 0) {
        setPErr(`Invalid value for ${k.replace(/([A-Z])/g,' $1').toLowerCase()}`);
        return;
      }
    }
    setSaving(true); setPMsg(''); setPErr('');
    try {
      const payload = {};
      keys.forEach(k => { payload[k] = Number(pForm[k]); });
      payload.note = userType; // 'new-user' or 'renewal-existing'
      const { data } = await api.put('/pricing', payload);
      setPricing(data.pricing);
      const label = userType === 'new-user' ? '👤 New User' : '🔄 Renewal for Existing User';
      setPMsg(`✅ Pricing saved for ${label}!`);
      await Swal.fire({
        icon:'success', title:'💰 Pricing Saved',
	        html:`<div style="text-align:left; font-size:14px; line-height:1.8;"><strong>${label}</strong><br/><br/>🖥️ <strong>System:</strong><br/>Monthly: ₹${pForm.pricePerSystemMonthly}<br/>Yearly: ₹${pForm.pricePerSystemYearly}<br/><br/>📱 <strong>Phone:</strong><br/>Monthly: ₹${pForm.pricePerPhoneMonthly}<br/>Yearly: ₹${pForm.pricePerPhoneYearly}<br/><br/>🗄️ <strong>Server:</strong><br/>Monthly: ₹${pForm.pricePerServerMonthly}<br/>Yearly: ₹${pForm.pricePerServerYearly}</div>`,
        background:'#0a0f1e', color:'#e2e8f0', confirmButtonColor:'#3b82f6', width:400,
      });
      loadPricing();
    } catch (e) { setPErr(e.response?.data?.message || 'Failed to save'); }
    finally { setSaving(false); }
  };

  // ── Delete history entry ──
  const deleteHistory = async (idx) => {
    const res = await Swal.fire({
      title: 'Delete this change record?',
      icon:'warning', showCancelButton:true, confirmButtonText:'Yes, Delete',
      confirmButtonColor:'#ef4444', cancelButtonColor:'#374151',
      background:'#111827', color:'#e2e8f0',
    });
    if (!res.isConfirmed) return;
    setDelBusy(p=>({...p,[idx]:true}));
    try {
      const r = await api.delete(`/pricing/history/${idx}`);
      setHistory(r.data.history || []);
      Swal.fire({ icon:'success', title:'Deleted', timer:1200, showConfirmButton:false, background:'#111827', color:'#e2e8f0' });
    } catch (e) { Swal.fire({ icon:'error', title:'Failed', text:e.response?.data?.message||'Error', background:'#111827', color:'#e2e8f0' }); }
    finally { setDelBusy(p=>({...p,[idx]:false})); }
  };

  // ── AutoPay toggle ──
  const toggleAutoPay = async (companyId, current) => {
    setApBusy(p=>({...p,[companyId]:true}));
    try {
      await api.patch(`/superadmin/subscriptions/${companyId}/autopay`, { enabled: !current });
      setSubs(p => p.map(s => s._id===companyId ? {...s,plan:{...s.plan,autoPay:!current}} : s));
      Swal.fire({ icon:'success', title: !current?'AutoPay Enabled':'AutoPay Disabled', timer:1300, showConfirmButton:false, background:'#111827', color:'#e2e8f0' });
    } catch (e) { Swal.fire({ icon:'error', title:'Error', text:e.response?.data?.message||'Failed', background:'#111827', color:'#e2e8f0' }); }
    finally { setApBusy(p=>({...p,[companyId]:false})); }
  };

  // Filtered subs
  const filtSubs = subs.filter(s => {
    const m = !subsQ || s.name?.toLowerCase().includes(subsQ.toLowerCase()) || s.email?.toLowerCase().includes(subsQ.toLowerCase());
    if (subsFilt==='active')  return m && subscriptionStatus(s).active;
    if (subsFilt==='pending') return m && subscriptionStatus(s).pending;
    if (subsFilt==='autopay') return m && s.plan?.autoPay;
    return m;
  });

  const tabs = [
    { id:'pricing',       icon:'💵', label:'Dynamic Pricing' },
    { id:'enterprise',    icon:'🏢', label:'Enterprise' },
    { id:'subscriptions', icon:'📋', label:'Subscriptions' },
    { id:'payments',      icon:'💰', label:'Payments' },
    { id:'autopay',       icon:'🔄', label:'AutoPay Control' },
  ];

  const PriceInp = ({ label, k, hint }) => (
    <div style={{ marginBottom:16 }}>
      <label style={{ fontSize:11, fontWeight:600, color:'#6b7280', display:'block', marginBottom:6, textTransform:'uppercase', letterSpacing:'0.5px' }}>{label}</label>
      <div style={{ position:'relative' }}>
        <span style={{ position:'absolute', left:12, top:'50%', transform:'translateY(-50%)', color:'#60a5fa', fontWeight:700, fontSize:15 }}>₹</span>
        <input type="number" min="0" step="1" value={pForm[k]||''}
          onChange={e=>setPForm(f=>({...f,[k]:e.target.value}))}
          style={{ ...CSS.inp, paddingLeft:30, fontSize:16, fontWeight:700, color:'#e2e8f0' }}
          onFocus={e=>e.target.style.borderColor='#3b82f6'}
          onBlur={e=>e.target.style.borderColor=pForm[k]?'#10b981':'#1e2d45'}
        />
      </div>
      {hint && <div style={{ fontSize:11, color:'#4b5563', marginTop:3 }}>{hint}</div>}
    </div>
  );

  // ── Pricing mini-comparison card ──
  const PriceSetCard = ({ label, color, icon, set }) => (
    <div style={{ background:'#0d1525', border:`1px solid ${color}33`, borderRadius:12, padding:16 }}>
      <div style={{ fontSize:12, fontWeight:700, color, marginBottom:10 }}>{icon} {label}</div>
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
        {[
	          { lbl:'System/mo',  val:set?.pricePerSystemMonthly },
	          { lbl:'System/yr',  val:set?.pricePerSystemYearly  },
	          { lbl:'Phone/mo',   val:set?.pricePerPhoneMonthly },
	          { lbl:'Phone/yr',   val:set?.pricePerPhoneYearly  },
	          { lbl:'Server/mo',  val:set?.pricePerServerMonthly },
          { lbl:'Server/yr',  val:set?.pricePerServerYearly  },
        ].map(({ lbl, val }) => (
          <div key={lbl} style={{ background:'rgba(0,0,0,0.3)', borderRadius:8, padding:'8px 10px' }}>
            <div style={{ fontSize:10, color:'#4b5563', fontWeight:600, textTransform:'uppercase', marginBottom:2 }}>{lbl}</div>
            <div style={{ fontSize:16, fontWeight:800, color }}>{fmtInr(val)}</div>
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <div style={CSS.page}>
      {/* ── Header ── */}
      <div style={{ marginBottom:28, display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:12 }}>
        <div>
          <h1 style={{ margin:0, fontSize:24, fontWeight:800, color:'#f1f5f9', letterSpacing:'-0.5px' }}>💳 Payment Management</h1>
          <p style={{ margin:'6px 0 0', fontSize:13, color:'#4b5563' }}>Control dynamic pricing, view subscriptions, manage AutoPay</p>
        </div>
      </div>

      {error && <div style={{ background:'#3f0a0a', border:'1px solid #dc2626', color:'#fca5a5', borderRadius:8, padding:'10px 14px', marginBottom:20, fontSize:13, display:'flex', justifyContent:'space-between' }}>{error}<button onClick={()=>setError('')} style={{ background:'none', border:'none', color:'#fca5a5', cursor:'pointer' }}>✕</button></div>}

      {/* ── Tabs ── */}
      <div style={{ display:'flex', gap:0, borderBottom:'1px solid #1e2d45', marginBottom:28, overflowX:'auto' }}>
        {tabs.map(t => (
          <button key={t.id} onClick={()=>setTab(t.id)} style={CSS.tab(tab===t.id)}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* ══════════════ PRICING TAB ══════════════ */}
      {tab === 'enterprise' && <EnterpriseManagement baseUrl="/superadmin/enterprise-plans" initialCompanyId={searchParams.get('companyId')} />}
      {tab==='pricing' && (
        <div>
          {pLoading ? (
            <div style={{ textAlign:'center', color:'#4b5563', padding:60, fontSize:14 }}>⏳ Loading pricing…</div>
          ) : (
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24 }}>

              {/* LEFT COLUMN */}
              <div style={{ display:'flex', flexDirection:'column', gap:20 }}>

                {/* Live Pricing — Both Sets */}
                <div style={CSS.card}>
                  <h2 style={{ margin:'0 0 16px', fontSize:16, fontWeight:700, color:'#f1f5f9', display:'flex', alignItems:'center', gap:8 }}>
                    ⚡ Current Live Pricing
                    <span style={{ fontSize:11, color:'#10b981', background:'rgba(16,185,129,0.1)', padding:'2px 8px', borderRadius:20, border:'1px solid rgba(16,185,129,0.3)', fontWeight:600 }}>● LIVE</span>
                  </h2>
                  <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
                    <PriceSetCard label="New User" color="#60a5fa" icon="👤" set={pricing?.newUser} />
                    <PriceSetCard label="Renewal for Existing User" color="#a78bfa" icon="🔄" set={pricing?.renewal} />
                  </div>
                  <div style={{ fontSize:11, color:'#374151', marginTop:12 }}>Last updated: {fmtDateTime(pricing?.updatedAt)}</div>
                </div>

                {/* Pricing History */}
                {history.length > 0 && (
                  <div style={CSS.card}>
                    <h3 style={{ margin:'0 0 16px', fontSize:15, fontWeight:700, color:'#f1f5f9', display:'flex', alignItems:'center', gap:8 }}>
                      📊 Recent Changes
                      <span style={{ fontSize:11, background:'#1e2d45', color:'#6b7280', padding:'2px 8px', borderRadius:12 }}>{history.length}</span>
                    </h3>
                    <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
                      {history.map((h, i) => {
                        const typeLabel = h.userType === 'new-user' ? '👤 New User' : h.userType === 'renewal-existing' ? '🔄 Renewal' : (h.note ? `📝 ${h.note}` : '');
                        return (
                          <div key={i} style={{ background:'#0d1525', borderRadius:10, padding:14, border:'1px solid #1e2d45', position:'relative' }}>
                            <button onClick={() => deleteHistory(i)} disabled={delBusy[i]}
                              style={{ position:'absolute', top:10, right:10, background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)', color:'#f87171', borderRadius:6, cursor: delBusy[i]?'not-allowed':'pointer', padding:'3px 8px', fontSize:11, fontWeight:600 }}
                            >{delBusy[i] ? '…' : '🗑 Delete'}</button>
                            <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:8 }}>
                              <div style={{ width:8, height:8, borderRadius:'50%', background:'#7c3aed' }} />
                              <span style={{ fontSize:11, color:'#6b7280' }}>{fmtDateTime(h.changedAt)}</span>
                              {h.changedBy?.name && <span style={{ fontSize:11, color:'#4b5563' }}>by {h.changedBy.name}</span>}
                              {typeLabel && <span style={{ fontSize:11, background:'rgba(124,58,237,0.15)', color:'#a78bfa', padding:'1px 8px', borderRadius:10, border:'1px solid rgba(124,58,237,0.3)' }}>{typeLabel}</span>}
                            </div>
                            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:6 }}>
	                              <div style={{ fontSize:12, color:'#93c5fd' }}>🖥️ System: {fmtInr(h.pricePerSystemMonthly)}/mo · {fmtInr(h.pricePerSystemYearly)}/yr</div>
	                              <div style={{ fontSize:12, color:'#2dd4bf' }}>📱 Phone: {fmtInr(h.pricePerPhoneMonthly)}/mo · {fmtInr(h.pricePerPhoneYearly)}/yr</div>
	                              <div style={{ fontSize:12, color:'#c4b5fd' }}>🗄️ Server: {fmtInr(h.pricePerServerMonthly)}/mo · {fmtInr(h.pricePerServerYearly)}/yr</div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>

              {/* RIGHT COLUMN — Edit Pricing */}
              <div>
                <div style={{ ...CSS.card, border:'2px solid #1d4ed8', position:'sticky', top:20 }}>
                  <h2 style={{ margin:'0 0 6px', fontSize:18, fontWeight:800, color:'#60a5fa' }}>🎛️ Update Pricing</h2>
                  <p style={{ fontSize:12, color:'#4b5563', marginBottom:20, lineHeight:1.5 }}>
                    Select the user type first. Changes affect <strong>only</strong> that type and go live instantly.
                  </p>

                  {pErr && <div style={{ background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)', color:'#fca5a5', padding:'10px 14px', borderRadius:8, marginBottom:16, fontSize:13 }}>❌ {pErr}</div>}
                  {pMsg && <div style={{ background:'rgba(16,185,129,0.1)', border:'1px solid rgba(16,185,129,0.3)', color:'#6ee7b7', padding:'10px 14px', borderRadius:8, marginBottom:16, fontSize:13 }}>{pMsg}</div>}

                  {/* ── Step 1: Choose user type ── */}
                  <div style={{ marginBottom:20 }}>
                    <label style={{ fontSize:11, fontWeight:700, color:'#fbbf24', display:'block', marginBottom:8, textTransform:'uppercase', letterSpacing:'0.5px' }}>
                      Step 1 — Choose User Type
                    </label>
                    <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
                      {[
                        { val:'new-user',          icon:'👤', label:'New User',                    color:'#60a5fa', desc:'First-time checkout pricing' },
                        { val:'renewal-existing',  icon:'💵', label:'Renewal Pricing (Latest)',    color:'#a78bfa', desc:'Existing company renewal pricing' },
                      ].map(opt => (
                        <button
                          key={opt.val}
                          type="button"
                          onClick={() => handleUserTypeChange(opt.val)}
                          style={{
                            display:'flex', alignItems:'center', gap:14,
                            border: `2px solid ${userType===opt.val ? opt.color : '#1e2d45'}`,
                            background: userType===opt.val ? `${opt.color}18` : '#0d1525',
                            borderRadius:10, padding:'14px 16px', cursor:'pointer', transition:'all 0.2s',
                            textAlign:'left', outline:'none', width:'100%',
                            boxShadow: userType===opt.val ? `0 0 0 3px ${opt.color}22` : 'none',
                          }}
                        >
                          <span style={{ fontSize:26, lineHeight:1, flexShrink:0 }}>{opt.icon}</span>
                          <span style={{ display:'flex', flexDirection:'column', gap:2 }}>
                            <span style={{ fontSize:14, fontWeight:700, color: userType===opt.val ? opt.color : '#94a3b8' }}>{opt.label}</span>
                            <span style={{ fontSize:11, color:'#4b5563' }}>{opt.desc}</span>
                          </span>
                          {userType===opt.val && (
                            <span style={{ marginLeft:'auto', fontSize:16, color:opt.color }}>✔</span>
                          )}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* ── Step 2: Edit prices (only shown when type is selected) ── */}
                  {userType ? (
                    <>
                      <div style={{ fontSize:11, fontWeight:700, color:'#fbbf24', marginBottom:12, textTransform:'uppercase', letterSpacing:'0.5px' }}>
                        Step 2 — Edit {userType === 'new-user' ? '👤 New User' : '🔄 Renewal'} Prices
                      </div>

                      {/* System Section */}
                      <div style={{ background:'rgba(29,78,216,0.07)', border:'1px solid rgba(29,78,216,0.2)', borderRadius:10, padding:16, marginBottom:16 }}>
                        <div style={{ fontWeight:700, color:'#60a5fa', fontSize:13, marginBottom:12, display:'flex', alignItems:'center', gap:6 }}>
                          🖥️ System Pricing  <span style={{ fontSize:10, color:'#374151', fontWeight:400 }}>(per system, chargeable)</span>
                        </div>
                        <PriceInp label="Monthly (per system)" k="pricePerSystemMonthly" hint="e.g. ₹200 per system per month" />
                        <PriceInp label="Yearly (per system)"  k="pricePerSystemYearly"  hint="e.g. ₹2000 per system per year" />
                      </div>

	                      {/* Server Section */}
	                      <div style={{ background:'rgba(20,184,166,0.07)', border:'1px solid rgba(20,184,166,0.2)', borderRadius:10, padding:16, marginBottom:16 }}>
	                        <div style={{ fontWeight:700, color:'#2dd4bf', fontSize:13, marginBottom:12, display:'flex', alignItems:'center', gap:6 }}>
	                          📱 Phone Pricing  <span style={{ fontSize:10, color:'#374151', fontWeight:400 }}>(Android + iPhone, chargeable)</span>
	                        </div>
	                        <PriceInp label="Monthly (per phone)" k="pricePerPhoneMonthly" hint="e.g. ₹150 per phone per month" />
	                        <PriceInp label="Yearly (per phone)"  k="pricePerPhoneYearly"  hint="e.g. ₹1500 per phone per year" />
	                      </div>

	                      {/* Server Section */}
	                      <div style={{ background:'rgba(109,40,217,0.07)', border:'1px solid rgba(109,40,217,0.2)', borderRadius:10, padding:16, marginBottom:16 }}>
                        <div style={{ fontWeight:700, color:'#a78bfa', fontSize:13, marginBottom:12, display:'flex', alignItems:'center', gap:6 }}>
                          🗄️ Server Pricing  <span style={{ fontSize:10, color:'#374151', fontWeight:400 }}>(per server, additional charge)</span>
                        </div>
                        <PriceInp label="Monthly (per server)" k="pricePerServerMonthly" hint="e.g. ₹500 per server per month" />
                        <PriceInp label="Yearly (per server)"  k="pricePerServerYearly"  hint="e.g. ₹5000 per server per year" />
                      </div>

                      {/* Live preview */}
                      {(Number(pForm.pricePerSystemMonthly)||0) > 0 && (
                        <div style={{ background:'rgba(245,158,11,0.07)', border:'1px solid rgba(245,158,11,0.2)', borderRadius:10, padding:14, marginBottom:16 }}>
	                          <div style={{ fontSize:11, color:'#fbbf24', fontWeight:600, marginBottom:8 }}>📊 Impact Preview (10 systems + 5 phones + 1 server)</div>
	                          <div style={{ display:'flex', gap:12 }}>
	                            <div style={{ fontSize:12, color:'#6b7280' }}>Monthly: <strong style={{ color:'#fbbf24' }}>{fmtInr(10*(Number(pForm.pricePerSystemMonthly)||0) + 5*(Number(pForm.pricePerPhoneMonthly)||0) + 1*(Number(pForm.pricePerServerMonthly)||0))}</strong></div>
	                            <div style={{ fontSize:12, color:'#6b7280' }}>Yearly: <strong style={{ color:'#10b981' }}>{fmtInr(10*(Number(pForm.pricePerSystemYearly)||0) + 5*(Number(pForm.pricePerPhoneYearly)||0) + 1*(Number(pForm.pricePerServerYearly)||0))}</strong></div>
	                          </div>
                        </div>
                      )}

                      <button onClick={savePricing} disabled={saving} style={{
                        width:'100%', padding:13, borderRadius:10, border:'none',
                        background: saving ? '#1e2d45' : 'linear-gradient(135deg,#10b981,#059669)',
                        color: saving?'#4b5563':'#fff', fontSize:14, fontWeight:700,
                        cursor: saving?'not-allowed':'pointer',
                        boxShadow: saving?'none':'0 4px 14px rgba(16,185,129,0.4)',
                        transition:'all 0.2s',
                      }}>
                        {saving ? '⏳ Saving…' : `💾 Save ${userType === 'new-user' ? 'New User' : 'Renewal'} Pricing`}
                      </button>
                    </>
                  ) : (
                    <div style={{ textAlign:'center', padding:'32px 20px', color:'#374151', fontSize:13, background:'#0d1525', borderRadius:10, border:'1px dashed #1e2d45' }}>
                      ☝️ Select a user type above to edit pricing
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ══════════════ SUBSCRIPTIONS TAB ══════════════ */}
      {tab==='subscriptions' && (
        <div>
          {/* Stats */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:16, marginBottom:24 }}>
            <StatCard icon="🏢" label="Total Companies"   value={subs.length} color="#60a5fa" />
            <StatCard icon="✅" label="Active Plans"       value={subs.filter(s=>subscriptionStatus(s).active).length} color="#10b981" />
            <StatCard icon="⏳" label="Pending Payment"    value={subs.filter(s=>subscriptionStatus(s).pending).length} color="#f59e0b" />
            <StatCard icon="🔄" label="AutoPay ON"         value={subs.filter(s=>s.plan?.autoPay).length} color="#a78bfa" />
          </div>

          {/* Filters */}
          <div style={{ display:'flex', gap:10, marginBottom:20, flexWrap:'wrap' }}>
            <input type="text" placeholder="🔍 Search company…" value={subsQ} onChange={e=>setSubsQ(e.target.value)}
              style={{ ...CSS.inp, flex:1, minWidth:200 }}
              onFocus={e=>e.target.style.borderColor='#3b82f6'}
              onBlur={e=>e.target.style.borderColor='#1e2d45'}
            />
            {['all','active','pending','autopay'].map(f => (
              <button key={f} onClick={()=>setSubsFilt(f)} style={{ padding:'10px 16px', border:'1px solid', borderRadius:8, fontSize:12, fontWeight:600, cursor:'pointer', transition:'all 0.2s',
                background: subsFilt===f?'rgba(37,99,235,0.2)':'transparent',
                borderColor: subsFilt===f?'#2563eb':'#1e2d45',
                color: subsFilt===f?'#60a5fa':'#4b5563',
              }}>
                {f==='all'?'All':f==='active'?'✅ Active':f==='pending'?'⏳ Pending':'🔄 AutoPay'}
              </button>
            ))}
            <button onClick={loadSubs} style={{ ...CSS.btn('rgba(37,99,235,0.2)'), border:'1px solid #1d4ed8', color:'#60a5fa' }}>🔄 Refresh</button>
          </div>

          {subsLoad ? <div style={{ textAlign:'center', color:'#4b5563', padding:50, fontSize:14 }}>⏳ Loading…</div> : (
            <div style={{ ...CSS.card, padding:0, overflow:'hidden' }}>
	              <div style={{ display:'grid', gridTemplateColumns:'2fr .8fr .8fr .8fr 1fr 1fr 1fr 1fr', gap:2, padding:'12px 20px', background:'#0d1525', fontSize:11, fontWeight:700, color:'#6b7280', textTransform:'uppercase', letterSpacing:'0.5px' }}>
	                <div>Company</div><div>Systems</div><div>Servers</div><div>Phones</div><div>Billing</div><div>Status</div><div>Expiry</div><div>AutoPay</div>
              </div>
              {filtSubs.length===0 ? (
                <div style={{ textAlign:'center', color:'#4b5563', padding:'40px 20px', fontSize:14 }}>No subscriptions found</div>
              ) : filtSubs.map((s,i) => {
                const { active, pending, expiresAt } = subscriptionStatus(s);
                const remaining = expiresAt ? new Date(expiresAt).getTime() - Date.now() : null;
                const expiring = active && remaining > 0 && remaining < 7*24*60*60*1000;
                return (
	                  <div key={s._id} style={{ display:'grid', gridTemplateColumns:'2fr .8fr .8fr .8fr 1fr 1fr 1fr 1fr', gap:2, padding:'14px 20px', borderTop:'1px solid #1e2d45', alignItems:'center', background: i%2===0?'transparent':'rgba(255,255,255,0.01)' }}>
                    <div>
                      <div style={{ fontWeight:600, color:'#e2e8f0', fontSize:13 }}>{s.name}</div>
                      <div style={{ fontSize:11, color:'#4b5563' }}>{s.email}</div>
                    </div>
	                    <div style={{ fontWeight:800, color:'#60a5fa', fontSize:15 }}>{s.plan?.systemCount||0}</div>
	                    <div style={{ fontWeight:800, color:'#a78bfa', fontSize:15 }}>{s.plan?.serverCount||0}</div>
	                    <div style={{ fontWeight:800, color:'#2dd4bf', fontSize:15 }}>{s.plan?.phoneCount||0}</div>
                    <div style={{ fontSize:12, color:'#6b7280', textTransform:'capitalize' }}>{s.plan?.billingCycle||'—'}</div>
                    <div>
                      <span style={CSS.badge(active?'#10b981':pending?'#f59e0b':'#ef4444')}>
                        {active ? '✅ Active' : pending?'⏳ Pending':'❌ Inactive'}
                      </span>
                    </div>
                    <div style={{ fontSize:12, color: expiring&&active?'#f59e0b':'#6b7280' }}>
                      {expiring && '⚠️ '}{fmtDate(expiresAt)}
                    </div>
                    <div>
                      <button onClick={()=>toggleAutoPay(s._id,s.plan?.autoPay)} disabled={apBusy[s._id]} style={{
                        padding:'4px 12px', borderRadius:20, border:'none', cursor: apBusy[s._id]?'not-allowed':'pointer', fontSize:11, fontWeight:700,
                        background: s.plan?.autoPay?'rgba(16,185,129,0.15)':'rgba(239,68,68,0.1)',
                        color: s.plan?.autoPay?'#10b981':'#f87171',
                      }}>
                        {apBusy[s._id]?'…':s.plan?.autoPay?'✓ ON':'✗ OFF'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <div style={{ marginTop:12, color:'#374151', fontSize:12, textAlign:'right' }}>{filtSubs.length} of {subs.length} companies</div>
        </div>
      )}

      {/* ══════════════ PAYMENTS TAB ══════════════ */}
      {tab==='payments' && (
        <div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:16, marginBottom:24 }}>
            <StatCard icon="💰" label="Total Revenue" color="#10b981"
              value={fmtInr(pays.reduce((a,p)=>a+(p.amountInr||0),0))}
              sub={`${pays.length} transactions`} />
            <StatCard icon="🗓️" label="This Month" color="#60a5fa"
              value={fmtInr(pays.filter(p=>new Date(p.paidAt)>new Date(new Date().setDate(1))).reduce((a,p)=>a+(p.amountInr||0),0))} />
            <StatCard icon="⬆️" label="Upgrades" color="#f59e0b"
              value={pays.filter(p=>p.isUpgrade).length} sub="plan upgrades" />
            <StatCard icon="🔄" label="AutoPay Sales" color="#a78bfa"
              value={pays.filter(p=>p.source==='autopay').length} />
          </div>

          {paysLoad ? <div style={{ textAlign:'center', color:'#4b5563', padding:50 }}>⏳ Loading…</div> : (
            <div style={{ ...CSS.card, padding:0, overflow:'hidden' }}>
	              <div style={{ display:'grid', gridTemplateColumns:'2fr 70px 70px 70px 100px 90px 100px', gap:2, padding:'12px 20px', background:'#0d1525', fontSize:11, fontWeight:700, color:'#6b7280', textTransform:'uppercase', letterSpacing:'0.5px' }}>
	                <div>Company / Payment</div><div>Systems</div><div>Servers</div><div>Phones</div><div>Amount</div><div>Billing</div><div>Date</div>
              </div>
              {pays.length===0 ? (
                <div style={{ textAlign:'center', color:'#4b5563', padding:'50px 20px', fontSize:14 }}>
                  <div style={{ fontSize:40, marginBottom:10 }}>📭</div>No payments yet
                </div>
              ) : pays.map((p,i) => {
                const counts = paymentCounts(p);
                return (
	                <div key={i} style={{ display:'grid', gridTemplateColumns:'2fr 70px 70px 70px 100px 90px 100px', gap:2, padding:'14px 20px', borderTop:'1px solid #1e2d45', alignItems:'center', background: i%2===0?'transparent':'rgba(255,255,255,0.01)' }}>
                  <div>
                    <div style={{ fontWeight:600, color:'#e2e8f0', fontSize:13 }}>{p.companyId?.name||p.companyName||'—'}</div>
                    <div style={{ fontSize:10, color:'#374151', fontFamily:'monospace' }}>{p.paymentId?.slice(0,20)}…</div>
                    <div style={{ display:'flex', gap:4, marginTop:3 }}>
                      {p.isUpgrade && <span style={CSS.badge('#818cf8')}>UPGRADE</span>}
                      {p.source==='autopay' && <span style={CSS.badge('#10b981')}>AUTOPAY</span>}
                      {p.planType==='autopay_activation' && <span style={CSS.badge('#f59e0b')}>₹1 MANDATE</span>}
                    </div>
	                  </div>
	                  <div style={{ fontWeight:800, color:'#60a5fa' }}>{counts.systems}</div>
	                  <div style={{ fontWeight:800, color:'#a78bfa' }}>{counts.servers}</div>
	                  <div style={{ fontWeight:800, color:'#2dd4bf' }}>{counts.phones}</div>
                  <div style={{ fontWeight:800, color:'#10b981', fontSize:15 }}>{fmtInr(p.amountInr)}</div>
                  <div style={{ fontSize:12, color:'#6b7280', textTransform:'capitalize' }}>{p.billingCycle||'—'}</div>
                  <div style={{ fontSize:12, color:'#4b5563' }}>{fmtDate(p.paidAt)}</div>
                </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ══════════════ AUTOPAY CONTROL TAB ══════════════ */}
      {tab==='autopay' && (
        <div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:16, marginBottom:24 }}>
            <StatCard icon="🏢" label="Total Subscriptions" value={subs.length}                              color="#60a5fa" />
            <StatCard icon="✅" label="AutoPay Enabled"      value={subs.filter(s=>s.plan?.autoPay).length} color="#10b981" sub={`${subs.length>0?Math.round(100*subs.filter(s=>s.plan?.autoPay).length/subs.length):0}% of total`} />
            <StatCard icon="❌" label="AutoPay Disabled"     value={subs.filter(s=>!s.plan?.autoPay).length} color="#ef4444" />
          </div>

          <div style={{ ...CSS.card, marginBottom:20, border:'1px solid rgba(245,158,11,0.3)', background:'rgba(245,158,11,0.05)' }}>
            <div style={{ display:'flex', alignItems:'flex-start', gap:14 }}>
              <div style={{ fontSize:28 }}>💡</div>
              <div>
                <div style={{ fontWeight:700, color:'#fbbf24', fontSize:14, marginBottom:4 }}>AutoPay Mandate — ₹1 Verification Charge</div>
                <p style={{ fontSize:13, color:'#6b7280', margin:0, lineHeight:1.6 }}>
                  Company Admins enable AutoPay on their Payments page by completing a <strong style={{ color:'#fbbf24' }}>₹1 Razorpay mandate payment</strong>.
                  As Super Admin, you can also force-enable or disable AutoPay for any company below.
                </p>
              </div>
            </div>
          </div>

          <div style={{ ...CSS.card, padding:0, overflow:'hidden' }}>
	            <div style={{ display:'grid', gridTemplateColumns:'2.5fr 1fr 1fr 1fr 120px', gap:2, padding:'12px 20px', background:'#0d1525', fontSize:11, fontWeight:700, color:'#6b7280', textTransform:'uppercase', letterSpacing:'0.5px' }}>
	              <div>Company</div><div>Licenses</div><div>Expiry</div><div>AutoPay</div><div>Action</div>
            </div>
            {subs.map((s,i) => {
              const expired = new Date()>new Date(s.plan?.expiresAt||0);
              return (
                <div key={s._id} style={{ display:'grid', gridTemplateColumns:'2.5fr 1fr 1fr 1fr 120px', gap:2, padding:'14px 20px', borderTop:'1px solid #1e2d45', alignItems:'center', background: i%2===0?'transparent':'rgba(255,255,255,0.01)' }}>
                  <div>
                    <div style={{ fontWeight:600, color:'#e2e8f0', fontSize:13 }}>{s.name}</div>
                    <div style={{ fontSize:11, color:'#4b5563' }}>{s.email}</div>
                  </div>
	                  <div style={{ fontWeight:700, color:'#60a5fa' }}>{s.plan?.systemCount||0} sys · {s.plan?.phoneCount||0} ph</div>
                  <div style={{ fontSize:12, color: expired?'#ef4444':'#6b7280' }}>
                    {expired && '⚠️ '}{fmtDate(s.plan?.expiresAt)}
                  </div>
                  <div>
                    <span style={CSS.badge(s.plan?.autoPay?'#10b981':'#ef4444')}>
                      {s.plan?.autoPay ? '✅ ON' : '❌ OFF'}
                    </span>
                  </div>
                  <div>
                    <button onClick={()=>toggleAutoPay(s._id,s.plan?.autoPay)} disabled={apBusy[s._id]} style={{
                      width:'100%', padding:'6px 12px', border:'none', borderRadius:8, fontSize:12, fontWeight:700,
                      background: s.plan?.autoPay?'rgba(239,68,68,0.15)':'rgba(16,185,129,0.15)',
                      color: s.plan?.autoPay?'#f87171':'#34d399',
                      cursor: apBusy[s._id]?'not-allowed':'pointer',
                    }}>
                      {apBusy[s._id]?'…':s.plan?.autoPay?'Disable':'Enable'}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
