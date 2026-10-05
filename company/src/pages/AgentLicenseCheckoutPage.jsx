import { useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Swal from 'sweetalert2';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { openRazorpay } from '../utils/razorpay';

const fmtInr = value => `₹${Number(value || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const planLabels = { monthly: 'Monthly', six_monthly: '6-Monthly', yearly: 'Yearly' };
const planDuration = { monthly: 'One Month', six_monthly: 'Six Months', yearly: 'One Year' };

export default function AgentLicenseCheckoutPage() {
  const navigate = useNavigate();
  const { state } = useLocation();
  const { user } = useAuth();
  const [terms, setTerms] = useState(false);
  const [privacy, setPrivacy] = useState(false);
  const [busy, setBusy] = useState(false);

  const checkout = useMemo(() => {
    if (state?.agentLicenseCheckout) return state.agentLicenseCheckout;
    try {
      return JSON.parse(sessionStorage.getItem('agent_license_checkout') || 'null');
    } catch {
      return null;
    }
  }, [state]);

  if (!checkout) {
    return (
      <div style={pageShell}>
        <div style={emptyCard}>
          <h2 style={{ marginTop:0 }}>Checkout unavailable</h2>
          <p style={{ color:'#94a3b8' }}>Please start agent license checkout from Buy Agent License page.</p>
          <button type="button" onClick={() => navigate('/partner-profile?section=requests')} style={payButton}>Go to Buy Agent License</button>
        </div>
      </div>
    );
  }

  const qty = Math.max(Number(checkout.agentQuantity || 0), 0);
  const planType = checkout.planType || 'monthly';
  const agentType = checkout.agentType || 'system';
  const agentLabel = { system: 'System', server: 'Server', android: 'Android' }[agentType] || 'System';
  const pricePerAgent = Number(checkout.pricePerAgent || 0);
  const base = qty * pricePerAgent;
  const gst = base * 0.18;
  const fees = base * 0.02;
  const autoPayFee = Number(checkout.autoPayFeeInr || 0);
  const total = base + gst + fees + autoPayFee;
  const canPay = terms && privacy && !busy && qty > 0 && pricePerAgent > 0;

  const handlePay = async () => {
    if (!canPay) return;
    setBusy(true);
    try {
      const { data } = await api.post('/payment/partner-agent-license/create-order', {
        agentQuantity: qty,
        agentType,
        planType,
        checkoutFees: true,
        autoPay: !!checkout.autoPay,
      }, { timeout: 60000 });

      await openRazorpay({
        order: data.order,
        planLabel: `Buy ${qty} ${agentLabel} Agent License${qty === 1 ? '' : 's'}`,
        email: user?.email,
        phone: user?.phone,
        onSuccess: async response => {
          try {
            await api.post('/payment/partner-agent-license/confirm', {
              ...response,
              agentQuantity: qty,
              agentType,
              planType,
              checkoutFees: true,
              autoPay: !!checkout.autoPay,
            }, { timeout: 60000 });
            try { sessionStorage.removeItem('agent_license_checkout'); } catch {}
            await Swal.fire({
              icon:'success',
              title:'Agent Licenses Added',
              text:`${qty} download permissions allocated.`,
              background:'#0c1a2e',
              color:'#e0f2fe',
            });
            navigate('/partner-profile?section=requests', { replace:true });
          } catch (err) {
            Swal.fire({ icon:'warning', title:'Activation issue', text:err.response?.data?.message || 'Payment received but license activation failed.', background:'#0c1a2e', color:'#e0f2fe' });
          }
        },
        onFailure: msg => Swal.fire({ icon:'error', title:'Payment Failed', text:msg || 'Payment could not be processed.', background:'#0c1a2e', color:'#e0f2fe' }),
      });
    } catch (err) {
      Swal.fire({ icon:'error', title:'Checkout Error', text:err.response?.data?.message || err.message, background:'#0c1a2e', color:'#e0f2fe' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={pageShell}>
      <div style={checkoutLayout}>
        <section style={detailsCard}>
          <button type="button" onClick={() => navigate('/partner-profile?section=requests')} style={backButton}>← Back</button>
          <h1 style={pageTitle}>Agent License Checkout</h1>
          <p style={pageSubtitle}>Review agent license details and accept policies before secure Razorpay payment.</p>

          <div style={metricGrid}>
            <Metric label="Agent Type" value={agentLabel} tone="#34d399" />
            <Metric label="Agent Quantity" value={qty} tone="#60a5fa" />
            <Metric label="Plan Type" value={planLabels[planType] || planType} tone="#a78bfa" />
            <Metric label="Price / Agent" value={fmtInr(pricePerAgent)} tone="#22c55e" />
            <Metric label="Duration" value={planDuration[planType] || '-'} tone="#fbbf24" />
            <Metric label="Auto Pay" value={checkout.autoPay ? 'Enabled' : 'Disabled'} tone={checkout.autoPay ? '#22c55e' : '#f87171'} />
          </div>

          <div style={requiredCard}>
            <h3 style={requiredTitle}>Required Details</h3>
            <Row label="Email" value={user?.email || checkout.email || 'Not provided'} />
            <Row label="Phone" value={user?.phone || checkout.phone || 'Not provided'} />
            <Row label="Payment For" value="Agent License Permissions" />
            <p style={noteText}>This checkout is only for partner agent download permissions. Registered companies can consume licenses from the partner allocation pool after payment confirmation.</p>
          </div>
        </section>

        <section style={breakdownCard}>
          <h2 style={breakdownTitle}>Price Breakdown</h2>
          <Row label="Duration" value={planDuration[planType] || '-'} />
          <div style={divider} />
          <Row label="Base Price" value={fmtInr(base)} />
          <Row label="GST (18%)" value={fmtInr(gst)} />
          <Row label="Other Taxes / Fees (2%)" value={fmtInr(fees)} />
          {checkout.autoPay ? <Row label="Auto Pay Enable Fee" value={fmtInr(autoPayFee)} /> : null}
          <div style={divider} />
          <Row label="Total" value={fmtInr(total)} strong />

          <PolicyCheck checked={terms} onChange={setTerms} label="I accept the Terms & Conditions." />
          <PolicyCheck checked={privacy} onChange={setPrivacy} label="I accept the Privacy Policy." />

          <div style={infoBox}>This payment activates your purchased agent license permissions immediately after Razorpay confirmation.</div>

          <button type="button" onClick={handlePay} disabled={!canPay} style={canPay ? payButton : payButtonDisabled}>
            {busy ? 'Opening payment...' : canPay ? `Pay ${fmtInr(total)}` : 'Accept both policies to continue'}
          </button>
        </section>
      </div>
    </div>
  );
}

function Metric({ label, value, tone }) {
  return (
    <div style={metricCard}>
      <span style={metricLabel}>{label}</span>
      <strong style={{ color:tone }}>{value}</strong>
    </div>
  );
}

function Row({ label, value, strong = false }) {
  return (
    <div style={rowStyle}>
      <span style={{ color:strong ? '#f8fafc' : '#cbd5e1', fontSize:strong ? 20 : 15, fontWeight:strong ? 900 : 600 }}>{label}</span>
      <b style={{ color:'#f8fafc', fontSize:strong ? 24 : 15, textAlign:'right' }}>{value}</b>
    </div>
  );
}

function PolicyCheck({ checked, onChange, label }) {
  return (
    <label style={policyCard}>
      <input type="checkbox" checked={checked} onChange={event => onChange(event.target.checked)} style={checkboxStyle} />
      <span>{label}</span>
    </label>
  );
}

const pageShell = { minHeight:'100vh', background:'linear-gradient(135deg,#020617 0%,#071426 100%)', color:'#f8fafc', padding:24, fontFamily:'system-ui, sans-serif' };
const checkoutLayout = { maxWidth:1160, margin:'0 auto', display:'grid', gridTemplateColumns:'1fr 1fr', gap:24 };
const emptyCard = { width:'min(460px, 100%)', margin:'10vh auto 0', border:'1px solid #1e3a5f', borderRadius:12, background:'#08111f', padding:24 };
const detailsCard = { border:'1px solid #1e3a5f', borderRadius:12, background:'#08111f', padding:28 };
const breakdownCard = { border:'1px solid #1f2937', borderRadius:12, background:'#07090f', padding:30, height:'fit-content' };
const backButton = { background:'transparent', border:0, color:'#60a5fa', cursor:'pointer', marginBottom:18, fontWeight:800 };
const pageTitle = { margin:'0 0 8px', fontSize:30, fontWeight:950 };
const pageSubtitle = { color:'#94a3b8', margin:'0 0 26px', lineHeight:1.7 };
const metricGrid = { display:'grid', gridTemplateColumns:'repeat(2, minmax(0, 1fr))', gap:14, marginBottom:22 };
const metricCard = { background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:9, padding:16, minHeight:82, display:'grid', alignContent:'space-between' };
const metricLabel = { color:'#64748b', fontSize:12, textTransform:'uppercase', fontWeight:900 };
const requiredCard = { border:'1px solid #1e3a5f', borderRadius:10, padding:18, background:'#07101d' };
const requiredTitle = { margin:'0 0 14px', color:'#60a5fa', fontSize:16, fontWeight:950 };
const noteText = { margin:'14px 0 0', color:'#64748b', fontSize:13, lineHeight:1.6 };
const breakdownTitle = { margin:'0 0 24px', fontSize:26, fontWeight:950 };
const rowStyle = { display:'flex', justifyContent:'space-between', gap:18, alignItems:'center', marginBottom:15 };
const divider = { height:1, background:'#1f2937', margin:'20px 0 24px' };
const policyCard = { display:'flex', alignItems:'center', gap:14, border:'1px solid #27272a', background:'#111118', borderRadius:10, padding:'16px 18px', marginTop:14, cursor:'pointer', color:'#e5e7eb', fontSize:15, fontWeight:700 };
const checkboxStyle = { width:22, height:22, accentColor:'#2563eb' };
const infoBox = { background:'#03111f', borderRadius:9, padding:16, color:'#dbeafe', fontSize:14, lineHeight:1.5, marginTop:20 };
const payButton = { width:'100%', marginTop:24, padding:15, border:0, borderRadius:9, background:'linear-gradient(135deg,#2563eb,#16a34a)', color:'#fff', fontWeight:950, fontSize:16, cursor:'pointer' };
const payButtonDisabled = { ...payButton, background:'#a3a3a3', cursor:'not-allowed' };
