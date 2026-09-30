import { useEffect, useState } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';

const fmt = n => `₹${Number(n || 0).toLocaleString('en-IN')}`;

const initialRequest = {
  companyCount: 1,
  systemCount: 10,
  serverCount: 0,
  phoneCount: 0,
  notes: '',
};

export default function EnterprisePlanPage() {
  const { user } = useAuth();
  const [plan, setPlan] = useState(null);
  const [form, setForm] = useState(initialRequest);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [paying, setPaying] = useState(false);
  const [message, setMessage] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await api.get('/payment/partner-plan');
      setPlan(data);
      if (data?.request?.requestedAt) {
        setForm({
          companyCount: data.request.companyCount || 1,
          systemCount: data.request.systemCount || 10,
          serverCount: data.request.serverCount || 0,
          phoneCount: data.request.phoneCount || 0,
          notes: data.request.notes || '',
        });
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const setField = (key, value) => {
    setForm(prev => ({
      ...prev,
      [key]: key === 'notes' ? value : Math.max(0, Number(value) || 0),
    }));
  };

  const submitRequest = async e => {
    e.preventDefault();
    setSaving(true);
    setMessage('');
    try {
      await api.post('/payment/partner-plan-request', form);
      setMessage('Request sent to Superadmin. Dashboard unlock hoga jab quote approve aur payment complete hoga.');
      await load();
    } catch (err) {
      setMessage(err.response?.data?.message || err.message);
    } finally {
      setSaving(false);
    }
  };

  const payPartnerPlan = async () => {
    setPaying(true);
    setMessage('');
    try {
      const { data } = await api.post('/payment/partner-create-order', { checkoutFees: true });
      await openRazorpay({
        order: data.order,
        planLabel: 'Partner Enterprise Plan',
        email: user?.email,
        onSuccess: async (response) => {
          await api.post('/payment/partner-confirm', { ...response, checkoutFees: true });
          window.location.href = '/';
        },
        onFailure: (msg) => setMessage(msg || 'Payment failed'),
      });
    } catch (err) {
      setMessage(err.response?.data?.message || err.message);
    } finally {
      setPaying(false);
    }
  };

  const requestStatus = plan?.requestStatus || 'none';
  const isPaid = plan?.isPaid;
  const isQuoted = plan?.isQuoted;

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', gap:18, alignItems:'flex-start', marginBottom:20 }}>
        <div>
          <h2 style={{ fontSize:22, color:'#e9d5ff', margin:'0 0 6px' }}>Enterprise / Customized Plan</h2>
          <div style={{ fontSize:12, color:'#8b5cf6' }}>
            Partner Superadmin plan request, Superadmin quote, then payment unlock
          </div>
        </div>
        <span style={pillStyle}>{requestStatus.replace('_', ' ')}</span>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(170px, 1fr))', gap:12, marginBottom:18 }}>
        <Metric label="Companies Needed" value={form.companyCount} color="#c084fc" />
        <Metric label="Agents / Systems" value={form.systemCount} color="#22d3ee" />
        <Metric label="Servers" value={form.serverCount} color="#34d399" />
        <Metric label="Superadmin Quote" value={plan?.amountInr ? fmt(plan.amountInr) : 'Pending'} color="#f59e0b" />
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(280px, 1fr))', gap:16 }}>
        <form onSubmit={submitRequest} style={panelStyle}>
          <div style={titleStyle}>Plan Requirement Request</div>
          <div style={mutedStyle}>
            Apni company count aur agent requirement bhejo. Superadmin verify karke custom price quote karega.
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(160px, 1fr))', gap:12, marginTop:14 }}>
            <Field label="Company count" value={form.companyCount} onChange={v => setField('companyCount', v)} min={1} />
            <Field label="Agents / systems" value={form.systemCount} onChange={v => setField('systemCount', v)} min={1} />
            <Field label="Servers" value={form.serverCount} onChange={v => setField('serverCount', v)} />
            <Field label="Phones" value={form.phoneCount} onChange={v => setField('phoneCount', v)} />
          </div>
          <textarea
            placeholder="Requirement notes"
            value={form.notes}
            onChange={e => setField('notes', e.target.value)}
            style={{ ...inputStyle, width:'100%', minHeight:84, marginTop:12, resize:'vertical' }}
          />
          {message && <div style={{ color: message.includes('sent') ? '#34d399' : '#fca5a5', fontSize:12, marginTop:10 }}>{message}</div>}
          <button disabled={saving || loading || isPaid} style={buttonStyle(saving || isPaid)}>
            {saving ? 'Sending...' : requestStatus === 'requested' ? 'Update Request' : 'Send Request'}
          </button>
        </form>

        <div style={panelStyle}>
          <div style={titleStyle}>Dashboard Unlock</div>
          {loading ? (
            <div style={mutedStyle}>Loading plan...</div>
          ) : isPaid ? (
            <Status color="#34d399" title="Plan active" text="Partner dashboard unlocked." />
          ) : isQuoted ? (
            <>
              <Status color="#f59e0b" title={`${fmt(plan.amountInr)} quoted`} text={`Billing: ${plan.billingCycle}. Payment ke baad dashboard open hoga.`} />
              {plan.quote?.notes && <div style={{ ...mutedStyle, marginTop:10 }}>{plan.quote.notes}</div>}
              <button onClick={payPartnerPlan} disabled={paying} style={buttonStyle(paying)}>
                {paying ? 'Opening Payment...' : 'Pay & Unlock Dashboard'}
              </button>
            </>
          ) : (
            <Status color="#60a5fa" title="Superadmin quote pending" text="Payment tab quote approve hone ke baad enable hoga." />
          )}
        </div>
      </div>
    </div>
  );
}

function loadRazorpay() {
  return new Promise((resolve, reject) => {
    if (window.Razorpay) return resolve(window.Razorpay);
    const script = document.createElement('script');
    script.src = 'https://checkout.razorpay.com/v1/checkout.js';
    script.async = true;
    script.onload = () => resolve(window.Razorpay);
    script.onerror = () => reject(new Error('Failed to load Razorpay SDK'));
    document.body.appendChild(script);
  });
}

async function openRazorpay({ order, planLabel, email, onSuccess, onFailure }) {
  const RazorpayClass = await loadRazorpay();
  const rzp = new RazorpayClass({
    key: import.meta.env.VITE_RAZORPAY_KEY,
    amount: order.amount,
    currency: order.currency || 'INR',
    name: 'SOC SaaS',
    description: planLabel,
    order_id: order.id,
    prefill: { email: email || '' },
    theme: { color: '#7c3aed' },
    handler: response => onSuccess?.(response),
  });
  rzp.on('payment.failed', r => onFailure?.(r.error?.description || 'Payment failed'));
  rzp.open();
}

function Field({ label, value, onChange, min = 0 }) {
  return (
    <label style={{ display:'grid', gap:6 }}>
      <span style={{ color:'#a78bfa', fontSize:12 }}>{label}</span>
      <input type="number" min={min} value={value} onChange={e => onChange(e.target.value)} style={inputStyle} />
    </label>
  );
}

function Metric({ label, value, color }) {
  return (
    <div style={{ background:'#2e1065', border:`1px solid ${color}33`, borderRadius:8, padding:'14px 16px' }}>
      <div style={{ color, fontSize:22, fontWeight:800 }}>{value}</div>
      <div style={{ color:'#8b5cf6', fontSize:11, marginTop:4 }}>{label}</div>
    </div>
  );
}

function Status({ color, title, text }) {
  return (
    <div style={{ border:`1px solid ${color}55`, background:'#0f172a', borderRadius:8, padding:14 }}>
      <div style={{ color, fontWeight:800, marginBottom:5 }}>{title}</div>
      <div style={mutedStyle}>{text}</div>
    </div>
  );
}

const panelStyle = {
  background:'#1e1b4b',
  border:'1px solid #312e81',
  borderRadius:8,
  padding:18,
};

const titleStyle = { color:'#e9d5ff', fontWeight:800, marginBottom:6 };
const mutedStyle = { color:'#c4b5fd', fontSize:13, lineHeight:1.5 };
const pillStyle = {
  padding:'5px 10px',
  borderRadius:999,
  background:'#2e1065',
  border:'1px solid #7c3aed',
  color:'#e9d5ff',
  fontSize:12,
  fontWeight:700,
  textTransform:'capitalize',
};
const inputStyle = {
  boxSizing:'border-box',
  padding:'9px 11px',
  borderRadius:6,
  background:'#0f172a',
  border:'1px solid #312e81',
  color:'#e2e8f0',
  fontSize:13,
};
const buttonStyle = disabled => ({
  marginTop:14,
  width:'100%',
  border:'none',
  borderRadius:8,
  padding:'11px 16px',
  background: disabled ? '#4c1d95' : '#7c3aed',
  color:'#fff',
  fontWeight:800,
  cursor: disabled ? 'not-allowed' : 'pointer',
});
