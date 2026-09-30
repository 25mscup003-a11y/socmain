import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Swal from 'sweetalert2';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../api/config';
import { openRazorpay } from '../utils/razorpay';
import { useAuth } from '../context/AuthContext';

const fmt = n => `₹${Number(n || 0).toLocaleString('en-IN')}`;

export default function PartnerPaymentPage({ onPaid, initialPlanData = null, onRetry }) {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [plan, setPlan] = useState(initialPlanData);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(!initialPlanData);
  const [loadError, setLoadError] = useState('');

  // Sync when parent passes updated data. Ignore stale cached "amount pending" data
  // after a fresher API response has already loaded a quoted amount.
  useEffect(() => {
    if (!initialPlanData) return;
    const nextAmount = Number(initialPlanData?.amountInr || initialPlanData?.quote?.amountInr || initialPlanData?.partner?.plan?.quote?.amountInr || 0);
    setPlan(current => {
      const currentAmount = Number(current?.amountInr || current?.quote?.amountInr || current?.partner?.plan?.quote?.amountInr || 0);
      if (currentAmount > 0 && nextAmount <= 0 && !initialPlanData?.isPaid) return current;
      return initialPlanData;
    });
  }, [initialPlanData]);

  // Direct refresh — fetches latest plan data from API
  const refreshPlan = async () => {
    setRefreshing(true);
    setLoadError('');
    try {
      const { data } = await api.get(`/payment/partner-plan?t=${Date.now()}`);
      setPlan(data);
    } catch (err) {
      setLoadError(err.response?.data?.message || err.message || 'Could not load payment status');
      console.warn('[PaymentPage] refresh failed:', err.message);
    } finally {
      setRefreshing(false);
    }
  };


  // Socket: auto-refresh when superadmin sets/updates a quote
  useEffect(() => {
    if (!user?.partnerId || !onRetry) return;
    const socket = io(SOCKET_URL, socketOptions);
    socket.on('connect', () => socket.emit('join:partner', user.partnerId));
    socket.emit('join:partner', user.partnerId);
    socket.on('partner:update', (event) => {
      if (String(event.partnerId) === String(user.partnerId)) onRetry();
    });
    return connectSocket(socket);
  }, [user?.partnerId]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (plan?.isPaid) onPaid?.(plan.partner);
  }, [plan?.isPaid]);

  useEffect(() => {
    refreshPlan();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps




  const pay = async () => {
    setBusy(true);
    try {
      const { data } = await api.post('/payment/partner-create-order', { checkoutFees: true, autoPay: true }, { timeout: 60000 });
      await openRazorpay({
        order: data.order,
        planLabel: 'Platform Commission',
        email: user?.email,
        phone: user?.phone,
        onSuccess: async (response) => {
          const confirmed = await api.post('/payment/partner-confirm', { ...response, checkoutFees: true, autoPay: true }, { timeout: 60000 });
          await Swal.fire({
            icon: 'success',
            title: 'Platform Commission Paid',
            text: 'Your partner dashboard is now unlocked.',
            background: '#0c1a2e',
            color: '#e0f2fe',
          });
          onPaid?.(confirmed.data.partner);
        },
        onFailure: (msg) => Swal.fire({ icon:'error', title:'Payment Failed', text:msg || 'Payment could not be completed.' }),
      });
    } catch (err) {
      const isTimeout = err.code === 'ECONNABORTED' || /timeout/i.test(err.message || '');
      Swal.fire({
        icon:'error',
        title:'Payment Error',
        text: isTimeout ? 'Payment gateway is taking longer than expected. Please try again.' : (err.response?.data?.message || err.message),
      });
    } finally {
      setBusy(false);
    }
  };
  const goToCheckout = () => {
    if (!canPay) return;
    navigate('/checkout', {
      state: {
        checkout: {
          mode: 'partner-platform',
          planName: 'Platform Commission',
          description: 'Platform Fee',
          amountInr: payableAmount,
          billingCycle: plan?.billingCycle || plan?.quote?.billingCycle || 'monthly',
          email: user?.email || '',
          phone: user?.phone || '',
          returnTo: '/partner-profile?section=dashboard',
          autoPay: true,
        },
      },
    });
  };


  if (!plan) {
    return (
      <div style={pageShell}>
        <div style={{ ...paymentPanel, textAlign: 'center' }}>
          <h2 style={{ color: loadError ? '#f87171' : '#f59e0b', marginBottom: 12 }}>
            {refreshing ? 'Loading Payment Status' : loadError ? 'Payment Status Not Loaded' : 'Payment Status Pending'}
          </h2>
          <p style={{ color: '#94a3b8', marginBottom: 8 }}>
            {refreshing
              ? 'Fetching latest payment amount from the server...'
              : loadError || 'Payment amount is not available yet.'}
          </p>
          <p style={{ color: '#64748b', fontSize: 13, marginBottom: 24 }}>
            {refreshing ? 'Please wait a moment.' : 'Press refresh to check again.'}
          </p>
          <button
            onClick={refreshPlan}
            disabled={refreshing}
            style={{ padding: '10px 24px', borderRadius: 8, background: '#2563eb', color: '#fff', border: 'none', cursor: refreshing ? 'wait' : 'pointer', fontWeight: 800, opacity: refreshing ? 0.7 : 1 }}
          >
            {refreshing ? 'Loading...' : 'Refresh Status'}
          </button>
        </div>
      </div>
    );
  }

  const payableAmount = Number(plan?.amountInr || plan?.quote?.amountInr || plan?.partner?.plan?.quote?.amountInr || 0);
  const agreementPdf = plan?.partner?.agreementFilePath ? plan.partner.agreementFileName || '' : '';
  const agreementFilePath = plan?.partner?.agreementFilePath || '';
  const apiBase = (import.meta.env.VITE_API_URL || 'http://localhost:5000/api').replace(/\/api\/?$/, '');
  const agreementUrl = agreementFilePath ? `${apiBase}/uploads/${agreementFilePath}` : '';
  const canPay = payableAmount > 0 && !plan?.isPaid;

  const openAgreement = () => {
    if (!agreementUrl) return;
    window.open(agreementUrl, '_blank', 'noopener,noreferrer');
  };

  const closeAgreement = () => {}; // no-op, kept for compatibility

  return (
    <div style={pageShell}>
      <div style={paymentPanel}>
        <div style={paymentHeader}>
          <div style={{ minWidth:0 }}>
            <h1 style={paymentTitle}>Platform Commission</h1>
            <div style={paymentSubtitle}>
              Pay to use our platform. Once payment is complete, your dashboard and server/agent access will be unlocked.
            </div>
          </div>
          <div style={{ display:'flex', flexDirection:'column', alignItems:'flex-end', gap:8 }}>
            <div style={headerAmount}>
              <div style={{ color:payableAmount ? '#34d399' : '#f59e0b', fontSize:28, fontWeight:900, lineHeight:1 }}>
                {payableAmount ? fmt(payableAmount) : 'Amount Pending'}
              </div>
              <div style={{ color:'#64748b', fontSize:12 }}>Platform usage payment</div>
            </div>
            <button
              onClick={refreshPlan}
              disabled={refreshing}
              style={{ padding:'5px 14px', borderRadius:6, background:'#1e3a5f', color:'#93c5fd', border:'1px solid #2563eb', cursor: refreshing ? 'wait' : 'pointer', fontSize:12, fontWeight:700, opacity: refreshing ? 0.6 : 1 }}
            >
              {refreshing ? '⏳ Refreshing...' : '🔄 Refresh'}
            </button>
          </div>
        </div>

        <div style={amountGrid}>
          <div style={amountCard}>
            <span style={amountLabel}>Platform Fee</span>
            <strong style={amountValue}>{payableAmount ? fmt(payableAmount) : 'Pending'}</strong>
          </div>
          <div style={amountCard}>
            <span style={amountLabel}>Payment For</span>
            <strong style={amountText}>Platform Usage</strong>
          </div>
          <div
            style={{
              ...amountCard,
              cursor: agreementUrl ? 'pointer' : 'default',
              borderColor: agreementUrl ? '#2563eb' : amountCard.borderColor,
            }}
            onClick={openAgreement}
            role={agreementUrl ? 'button' : undefined}
            tabIndex={agreementUrl ? 0 : undefined}
            onKeyDown={event => {
              if (agreementUrl && (event.key === 'Enter' || event.key === ' ')) openAgreement();
            }}
            title={agreementUrl ? 'Open Agreement PDF' : 'Agreement PDF not available'}
          >
            <span style={amountLabel}>Agreement PDF</span>
            <strong style={fileNameText}>{agreementPdf || 'Not uploaded'}</strong>
            {agreementUrl && <span style={amountHint}>Click to open</span>}
          </div>
        </div>

        <div style={paymentActionArea}>
          {plan?.isPaid ? (
            <div style={{ color:'#34d399', fontWeight:800 }}>Platform payment paid. Dashboard access is unlocked.</div>
          ) : (
            <>
              {plan.quote?.notes && <div style={{ color:'#bfdbfe', fontSize:13, marginBottom:12 }}>{plan.quote.notes}</div>}
              <button onClick={goToCheckout} disabled={busy || !canPay} style={buttonStyle(busy || !canPay, '#16a34a')}>
                {busy ? 'Opening Checkout...' : canPay ? `Continue to Checkout - ${fmt(payableAmount)}` : 'Platform Fee Pending'}
              </button>
              {!canPay && <div style={{ color:'#60a5fa', fontSize:13, marginTop:10 }}>The Superadmin will set the payment amount. Payment will become active after that.</div>}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

const buttonStyle = (disabled, color) => ({
  width:'100%',
  marginTop:13,
  padding:13,
  borderRadius:8,
  border:'none',
  background: disabled ? '#1e3a5f' : color,
  color:'#fff',
  fontSize:14,
  fontWeight:800,
  cursor: disabled ? 'not-allowed' : 'pointer',
});

const pageShell = {
  minHeight:'70vh',
  display:'grid',
  placeItems:'center',
  padding:24,
};

const paymentPanel = {
  width:'100%',
  maxWidth:960,
  background:'#0c1a2e',
  border:'1px solid #1e3a5f',
  borderRadius:10,
  padding:26,
  color:'#e2e8f0',
  boxSizing:'border-box',
  overflow:'hidden',
};

const paymentHeader = {
  display:'grid',
  gridTemplateColumns:'minmax(0, 1fr) auto',
  alignItems:'start',
  gap:18,
  marginBottom:22,
};

const paymentTitle = {
  margin:'0 0 8px',
  fontSize:26,
  color:'#e0f2fe',
  lineHeight:1.15,
};

const paymentSubtitle = {
  color:'#60a5fa',
  fontSize:13,
  lineHeight:1.6,
  maxWidth:680,
};

const headerAmount = {
  textAlign:'right',
  minWidth:150,
  display:'grid',
  gap:8,
};

const amountGrid = {
  marginTop:16,
  display:'grid',
  gridTemplateColumns:'repeat(auto-fit, minmax(230px, 1fr))',
  gap:12,
};

const amountCard = {
  border:'1px solid #1e3a5f',
  background:'#0a1424',
  borderRadius:8,
  padding:'16px 18px',
  display:'grid',
  gap:8,
  minHeight:116,
  minWidth:0,
  alignContent:'start',
  boxSizing:'border-box',
};

const amountLabel = {
  color:'#60a5fa',
  fontSize:12,
  fontWeight:700,
};

const amountValue = {
  color:'#fbbf24',
  fontSize:24,
  fontWeight:900,
};

const amountText = {
  color:'#e0f2fe',
  fontSize:19,
  fontWeight:900,
  lineHeight:1.25,
};

const fileNameText = {
  ...amountText,
  overflow:'hidden',
  textOverflow:'ellipsis',
  whiteSpace:'nowrap',
  maxWidth:'100%',
};

const amountHint = {
  color:'#60a5fa',
  fontSize:12,
  fontWeight:800,
};

const paymentActionArea = {
  marginTop:24,
  paddingTop:24,
  borderTop:'1px solid #1e3a5f',
};

const modalBackdrop = {
  position:'fixed',
  inset:0,
  zIndex:1000,
  background:'rgba(2, 6, 23, .82)',
  display:'grid',
  placeItems:'center',
  padding:20,
};

const pdfModal = {
  width:'min(980px, 96vw)',
  height:'min(760px, 90vh)',
  background:'#0c1a2e',
  border:'1px solid #2563eb',
  borderRadius:10,
  overflow:'hidden',
  display:'grid',
  gridTemplateRows:'auto minmax(0, 1fr)',
  boxShadow:'0 24px 80px rgba(0,0,0,.45)',
};

const pdfModalHeader = {
  display:'flex',
  alignItems:'center',
  justifyContent:'space-between',
  gap:12,
  padding:'12px 14px',
  borderBottom:'1px solid #1e3a5f',
};

const pdfModalTitle = {
  color:'#e0f2fe',
  fontSize:14,
  overflow:'hidden',
  textOverflow:'ellipsis',
  whiteSpace:'nowrap',
};

const modalCloseButton = {
  border:'1px solid #1e3a5f',
  background:'#08111f',
  color:'#bfdbfe',
  borderRadius:6,
  padding:'8px 12px',
  fontWeight:800,
  cursor:'pointer',
};

const pdfFrame = {
  width:'100%',
  height:'100%',
  border:0,
  background:'#fff',
};
