import { useMemo, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Swal from 'sweetalert2';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { openRazorpay } from '../utils/razorpay';

const fmtInr = (n) => `₹${Number(n || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const durationOptions = [
  { value: 'one_month', label: 'One Month', multiplier: 1 },
  { value: 'six_month', label: 'Six Month', multiplier: 6 },
  { value: 'one_year', label: '1 Year', multiplier: 12 },
];
const shortCycle = (cycle) => durationOptions.find(option => option.value === cycle)?.label || (cycle === 'yearly' ? '1 Year' : 'One Month');

const row = (label, value, strong = false) => (
  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 18, alignItems: 'center', marginBottom: 14 }}>
    <span style={{ color: strong ? '#e5e7eb' : '#d1d5db', fontSize: strong ? 20 : 15, fontWeight: strong ? 800 : 500 }}>{label}</span>
    <span style={{ color: '#f8fafc', fontSize: strong ? 24 : 15, fontWeight: 800, textAlign: 'right' }}>{value}</span>
  </div>
);

export default function CheckoutPage() {
  const navigate = useNavigate();
  const { state } = useLocation();
  const { user, setCompany, refreshCompany } = useAuth();
  const [terms, setTerms] = useState(false);
  const [privacy, setPrivacy] = useState(false);
  const [busy, setBusy] = useState(false);

  const checkout = state?.checkout;
  const isPartnerPlatform = checkout?.mode === 'partner-platform';
  const [selectedDuration, setSelectedDuration] = useState(checkout?.billingCycle === 'yearly' ? 'one_year' : checkout?.billingCycle || 'one_month');
  const canContinue = terms && privacy && !busy;
  const duration = durationOptions.find(option => option.value === selectedDuration) || durationOptions[0];

  const breakdown = useMemo(() => {
    const base = Number(checkout?.amountInr || checkout?.calc?.totalInr || 0) * (isPartnerPlatform ? duration.multiplier : 1);
    const gst = base * 0.18;
    const fees = base * 0.02;
    const payable = base + gst + fees;
    return { payable, base, gst, fees };
  }, [checkout, duration.multiplier, isPartnerPlatform]);

  if (!checkout) {
    return (
      <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', background: '#030712', color: '#e5e7eb', padding: 24 }}>
        <div style={{ maxWidth: 440, border: '1px solid #1f2937', borderRadius: 12, padding: 24, background: '#0b1120' }}>
          <h2 style={{ marginTop: 0 }}>Checkout unavailable</h2>
          <p style={{ color: '#94a3b8' }}>Please start checkout from the Payments page.</p>
          <button onClick={() => navigate('/payments')} style={{ width: '100%', padding: 12, border: 0, borderRadius: 8, background: '#2563eb', color: '#fff', fontWeight: 800, cursor: 'pointer' }}>Go to Payments</button>
        </div>
      </div>
    );
  }

  const counts = checkout.counts || {};
  const planName = checkout.planName || 'Spartan Cyber Defense Center (SCDC)';
  const billingCycle = isPartnerPlatform ? selectedDuration : checkout.billingCycle || 'monthly';
  const returnTo = checkout.returnTo || '/payments';
  const email = checkout.email || user?.email || '';
  const phone = checkout.phone || user?.phone || '';
  const apiBillingCycle = isPartnerPlatform ? (selectedDuration === 'one_year' ? 'yearly' : 'monthly') : checkout.billingCycle || 'monthly';
  const durationMonths = isPartnerPlatform ? duration.multiplier : undefined;
  const isFirstCompanySubscription = !isPartnerPlatform && checkout.mode === 'base' && checkout.isUpgrade !== true;
  const shouldEnableCompanyAutoPay = checkout.autoPay === true || isFirstCompanySubscription;

  const confirmPayload = () => ({
    systemCount: Number(counts.systemCount) || 0,
    serverCount: Number(counts.serverCount) || 0,
    phoneCount: Number(counts.phoneCount) || 0,
    billingCycle: apiBillingCycle,
    ...(isPartnerPlatform ? { durationMonths } : {}),
    checkoutFees: true,
    ...(isPartnerPlatform ? { autoPay: checkout.autoPay !== false } : {}),
    ...(!isPartnerPlatform ? { autoPay: shouldEnableCompanyAutoPay } : {}),
    isUpgrade: !!checkout.isUpgrade,
  });

  const createOrder = async () => {
    if (isPartnerPlatform) {
      return api.post('/payment/partner-create-order', { checkoutFees: true, durationMonths, autoPay: checkout.autoPay !== false }, { timeout: 60000 });
    }
    if (checkout.mode === 'add-system') {
      return api.post('/add-system/create-order', { ...confirmPayload(), serverDetails: checkout.serverDetails || '' });
    }
    if (checkout.mode === 'batch-renewal') {
      return api.post(`/add-system/renew/${checkout.batchId}`, { billingCycle, checkoutFees: true });
    }
    return api.post('/payment/create-order', confirmPayload());
  };

  const confirmPayment = async (response) => {
    if (isPartnerPlatform) {
      return api.post('/payment/partner-confirm', { ...response, checkoutFees: true, durationMonths, autoPay: checkout.autoPay !== false }, { timeout: 60000 });
    }
    if (checkout.mode === 'add-system') {
      return api.post('/add-system/confirm', { ...response, ...confirmPayload(), serverDetails: checkout.serverDetails || '' });
    }
    if (checkout.mode === 'batch-renewal') {
      return api.post(`/add-system/renew-confirm/${checkout.batchId}`, { ...response, billingCycle, checkoutFees: true });
    }
    return api.post('/payment/confirm', { ...response, ...confirmPayload() });
  };

  const handlePay = async () => {
    if (!canContinue) return;
    setBusy(true);
    try {
      const { data } = await createOrder();
      await openRazorpay({
        order: data.order,
        planLabel: checkout.description || planName,
        email,
        phone,
        onSuccess: async (response) => {
          try {
            const { data: confirmed } = await confirmPayment(response);
            if (confirmed.company) {
              localStorage.setItem('co_company', JSON.stringify(confirmed.company));
              setCompany(confirmed.company);
            }
            if (!isPartnerPlatform) await refreshCompany();
            await Swal.fire({
              icon: 'success',
              title: isPartnerPlatform ? 'Platform Fee Paid' : 'Payment Successful',
              html: `<p><strong>${checkout.description || planName}</strong></p><p style="font-size:13px;color:#94a3b8">${isPartnerPlatform ? 'Your partner dashboard is now unlocked.' : 'Your license is updated.'}</p>`,
              background: '#0c1a2e',
              color: '#e0f2fe',
            });
            navigate(returnTo, { replace: true });
          } catch {
            await Swal.fire({ icon: 'warning', title: 'Activation issue', text: 'Payment received but activation failed. Please check Payments page.', background: '#0c1a2e', color: '#e0f2fe' });
            navigate(isPartnerPlatform ? '/' : '/payments', { replace: true });
          }
        },
        onFailure: (msg) => Swal.fire({ icon: 'error', title: 'Payment Failed', text: msg || 'Payment could not be processed.', background: '#0c1a2e', color: '#e0f2fe' }),
      });
    } catch (err) {
      Swal.fire({ icon: 'error', title: 'Checkout Error', text: err.response?.data?.message || err.message, background: '#0c1a2e', color: '#e0f2fe' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #020617 0%, #071426 100%)', color: '#f8fafc', padding: 24, fontFamily: 'system-ui, sans-serif' }}>
      <div style={{ maxWidth: 980, margin: '0 auto', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 22 }}>
        <div style={{ border: '1px solid #1e3a5f', borderRadius: 12, background: '#08111f', padding: 26 }}>
          <button onClick={() => navigate(returnTo)} style={{ background: 'transparent', border: 0, color: '#60a5fa', cursor: 'pointer', marginBottom: 18, fontWeight: 700 }}>← Back</button>
          <h1 style={{ fontSize: 28, margin: '0 0 6px' }}>Checkout</h1>
          <p style={{ color: '#64748b', margin: '0 0 24px' }}>{isPartnerPlatform ? 'Review your platform fee and accept policies before secure payment.' : 'Review license details and accept policies before secure payment.'}</p>

          {isPartnerPlatform && <div style={{ marginBottom:18 }}>
            <div style={{ color:'#60a5fa', fontWeight:800, marginBottom:10 }}>Duration</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0, 1fr))', gap:10 }}>
              {durationOptions.map(option => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setSelectedDuration(option.value)}
                  style={{
                    border:selectedDuration === option.value ? '1px solid #60a5fa' : '1px solid #1e3a5f',
                    background:selectedDuration === option.value ? '#12345c' : '#0c1a2e',
                    color:selectedDuration === option.value ? '#e0f2fe' : '#93c5fd',
                    borderRadius:8,
                    padding:'12px 10px',
                    fontWeight:900,
                    cursor:'pointer',
                  }}
                >
                  {option.label}
                </button>
              ))}
            </div>
            <div style={partnerAutoPayNote}>AutoPay will be enabled automatically after this subscription payment. You can disable it later from Subscription & Payments.</div>
          </div>}

          {!isPartnerPlatform && <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 18 }}>
            {[
              ['Systems', counts.systemCount || 0, '#60a5fa'],
              ['Servers', counts.serverCount || 0, '#a78bfa'],
              ['Phones', counts.phoneCount || 0, '#2dd4bf'],
              ['Duration', shortCycle(billingCycle), '#fbbf24'],
            ].map(([label, value, color]) => (
              <div key={label} style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 8, padding: 14 }}>
                <div style={{ color: '#64748b', fontSize: 11, textTransform: 'uppercase', fontWeight: 800, marginBottom: 6 }}>{label}</div>
                <div style={{ color, fontSize: 20, fontWeight: 900 }}>{value}</div>
              </div>
            ))}
          </div>}

          <div style={{ border: '1px solid #1e3a5f', borderRadius: 10, padding: 18, background: '#07101d' }}>
            <div style={{ color: '#60a5fa', fontWeight: 800, marginBottom: 12 }}>Required Details</div>
            {row('Email', email || 'Not provided')}
            {row('Phone', phone || 'Not provided')}
            {isPartnerPlatform && row('Payment For', 'Platform Usage')}
            {isPartnerPlatform && row('Duration', duration.label)}
            {checkout.serverDetails && row('Server Notes', checkout.serverDetails)}
            <div style={{ marginTop: 14, color: '#64748b', fontSize: 12 }}>
              {isPartnerPlatform
                ? 'This payment unlocks your partner dashboard and platform access after Razorpay confirmation.'
                : 'Phones include Android and iPhone devices. System, server, phone, and universal package download limits are counted separately.'}
            </div>
          </div>
        </div>

        <div style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#07090f', padding: 30, height: 'fit-content' }}>
          <h2 style={{ margin: '0 0 24px', fontSize: 24 }}>Price Breakdown</h2>
          {!isPartnerPlatform && row('Duration', shortCycle(billingCycle))}
          <div style={{ height: 1, background: '#1f2937', margin: '18px 0 22px' }} />
          {row('Base Price', fmtInr(breakdown.base))}
          {row('GST (18%)', fmtInr(breakdown.gst))}
          {row('Other Taxes / Fees (2%)', fmtInr(breakdown.fees))}
          <div style={{ height: 1, background: '#1f2937', margin: '22px 0 24px' }} />
          {row('Total', fmtInr(breakdown.payable), true)}

          {[['terms', terms, setTerms, 'I accept the Terms & Conditions.'], ['privacy', privacy, setPrivacy, 'I accept the Privacy Policy.']].map(([id, checked, setChecked, label]) => (
            <label key={id} style={{ display: 'flex', alignItems: 'center', gap: 14, border: '1px solid #27272a', background: '#111118', borderRadius: 10, padding: '16px 18px', marginTop: 14, cursor: 'pointer' }}>
              <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} style={{ width: 22, height: 22, accentColor: '#2563eb' }} />
              <span style={{ color: '#e5e7eb', fontSize: 15, fontWeight: 600 }}>{label}</span>
            </label>
          ))}

          <div style={{ background: '#03111f', borderRadius: 9, padding: 16, color: '#dbeafe', fontSize: 14, lineHeight: 1.5, marginTop: 20 }}>
            This payment activates or updates your selected license immediately after Razorpay confirmation.
          </div>

          <button onClick={handlePay} disabled={!canContinue} style={{
            width: '100%', marginTop: 24, padding: 15, border: 0, borderRadius: 9,
            background: canContinue ? 'linear-gradient(135deg, #2563eb, #16a34a)' : '#a3a3a3',
            color: '#fff', fontWeight: 900, fontSize: 16, cursor: canContinue ? 'pointer' : 'not-allowed',
          }}>
            {busy ? 'Opening payment...' : canContinue ? `Pay ${fmtInr(breakdown.payable)}` : 'Accept both policies to continue'}
          </button>
        </div>
      </div>
    </div>
  );
}

const partnerAutoPayNote = {
  marginTop:12,
  border:'1px solid #10b981',
  borderRadius:8,
  background:'rgba(16,185,129,.12)',
  color:'#86efac',
  padding:'10px 12px',
  fontSize:12,
  fontWeight:800,
};
