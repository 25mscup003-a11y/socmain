import { authStorage } from '../api/authStorage';
import { useState, useEffect, useRef } from 'react';
import { useNavigate, Link, useParams, useSearchParams } from 'react-router-dom';
import Swal from 'sweetalert2';
import api from '../api/axios';
import EnterprisePurchase from '../components/EnterprisePurchase';
import { useAuth } from '../context/AuthContext';
import { requiresRegistrationPayment } from '../utils/registrationPayment';
import {
  validateCompanyName, validateEmail, validatePassword,
  validatePhone, firstError,
} from '../utils/validate';
import { getTelemetryId } from '../utils/stytchFingerprint';

const inp = (key, label, type, form, setForm, error, placeholder = '') => (
  <div style={{ marginBottom: 14 }}>
    <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>{label}</label>
    <input type={type} value={form[key]} placeholder={placeholder}
      onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
      style={{
        width: '100%', padding: '9px 12px', borderRadius: 6, boxSizing: 'border-box',
        background: '#060e1a', color: '#e2e8f0', fontSize: 13,
        border: `1px solid ${error ? '#f87171' : '#1e3a5f'}`,
        outline: 'none', transition: 'border-color 0.2s',
      }}
      onFocus={e => e.target.style.borderColor = error ? '#f87171' : '#3b82f6'}
      onBlur={e => e.target.style.borderColor = error ? '#f87171' : '#1e3a5f'}
    />
    {error && <div style={{ fontSize: 11, color: '#f87171', marginTop: 3 }}>{error}</div>}
  </div>
);

export default function RegisterPage() {
  const navigate = useNavigate();
  const { referralSlug } = useParams();
  const [searchParams] = useSearchParams();
  const { user, company, loading, loadFromStorage, refreshCompany } = useAuth();
  const resumedAccount = useRef(null);

  // Pre-fill from partner invite link
  const prefillCompany  = searchParams.get('company')   || '';
  const prefillEmail    = searchParams.get('email')     || '';
  const prefillAdmin    = searchParams.get('adminName') || '';
  const isInvited       = Boolean(prefillEmail || prefillCompany);

  const [step, setStep] = useState(1);
  const [form, setForm] = useState({
    companyName: prefillCompany,
    email:       prefillEmail,
    password:    '',
    phone:       '',
  });
  const [errors, setErrors] = useState({});
  const [regData, setRegData] = useState(null);
  const [apiErr, setApiErr] = useState('');
  const [busy, setBusy] = useState(false);

  // OTP
  const [otp, setOtp] = useState('');
  const [otpErr, setOtpErr] = useState('');
  const [otpTimer, setOtpTimer] = useState(0);

  // Plan config (dynamic)
  const [planType, setPlanType] = useState(searchParams.get('plan') === 'enterprise' ? 'enterprise' : 'dynamic');
  const [pricing, setPricing] = useState(null);
  const [pricingLoading, setPricingLoading] = useState(false);
  const [systemCount, setSystemCount] = useState(10);
  const [serverCount, setServerCount] = useState(0);
  const [phoneCount, setPhoneCount] = useState(0);
  const [billingCycle, setBillingCycle] = useState('monthly');
  const [calcResult, setCalcResult] = useState(null);
  const [calcLoading, setCalcLoading] = useState(false);
  const [referralInfo, setReferralInfo] = useState(null);

  // Resume from server-backed account status after refresh, login, or checkout.
  useEffect(() => {
    if (loading || !user || !company || user.role !== 'company_admin') return;
    if (!requiresRegistrationPayment(user, company)) {
      navigate('/', { replace: true });
      return;
    }
    const accountId = user._id || user.id;
    if (resumedAccount.current === accountId) return;
    resumedAccount.current = accountId;
    setForm(previous => ({ ...previous, companyName: company.name || '', email: user.email || company.email || '', phone: user.phone || company.phone || '', password: '' }));
    setStep(3);
  }, [loading, user, company, navigate]);

  // A verified webhook or payment in another tab can finish registration too.
  useEffect(() => {
    if (!requiresRegistrationPayment(user, company)) return;
    const refresh = () => { if (document.visibilityState !== 'hidden') refreshCompany(); };
    const timer = window.setInterval(refresh, 15000);
    window.addEventListener('focus', refresh);
    return () => { window.clearInterval(timer); window.removeEventListener('focus', refresh); };
  }, [user, company?.status, refreshCompany]);

  useEffect(() => {
    if (!referralSlug) {
      setReferralInfo(null);
      return;
    }

    api.get(`/tenant/referral/${referralSlug}`)
      .then(r => setReferralInfo(r.data))
      .catch(() => setReferralInfo({ invalid: true }));
  }, [referralSlug]);

  // ── OTP Timer ──
  useEffect(() => {
    let interval;
    if (otpTimer > 0) {
      interval = setInterval(() => setOtpTimer(t => t - 1), 1000);
    }
    return () => clearInterval(interval);
  }, [otpTimer]);

  // ── Load pricing when entering step 3 ──
  useEffect(() => {
    if (step === 3) {
      setPricingLoading(true);
      api.get('/pricing')           // uses /pricing which returns both newUser + renewal
        .then(r => {
          // For registration (new user), use the newUser pricing set
          const data = r.data;
          const newUserSet = data.newUser || data; // fallback to flat if newUser missing
          setPricing({
	            pricePerSystemMonthly: newUserSet.pricePerSystemMonthly,
	            pricePerSystemYearly:  newUserSet.pricePerSystemYearly,
	            pricePerPhoneMonthly:  newUserSet.pricePerPhoneMonthly ?? newUserSet.pricePerSystemMonthly,
	            pricePerPhoneYearly:   newUserSet.pricePerPhoneYearly ?? newUserSet.pricePerSystemYearly,
	            pricePerServerMonthly: newUserSet.pricePerServerMonthly,
            pricePerServerYearly:  newUserSet.pricePerServerYearly,
          });
        })
        .catch(() => setPricing(null))
        .finally(() => setPricingLoading(false));
    }
  }, [step]);

  // ── Auto-calculate when inputs change ──
  useEffect(() => {
    if (step !== 3 || !pricing) return;
    const sys = Number(systemCount) || 0;
    const srv = Number(serverCount) || 0;
    const phn = Number(phoneCount) || 0;
    if (sys === 0 && srv === 0 && phn === 0) { setCalcResult(null); return; }
    const controller = new AbortController();
    setCalcLoading(true);

    const timer = setTimeout(async () => {
      try {
        const { data } = await api.post('/payment/calculate', {
	          systemCount: sys,
	          serverCount: srv,
	          phoneCount: phn,
	          billingCycle,
          isUpgrade: false,   // registration = new user pricing
        }, { signal: controller.signal });
        setCalcResult(data);
      } catch (e) {
        if (e.name !== 'CanceledError') setCalcResult(null);
      } finally {
        setCalcLoading(false);
      }
    }, 400);

    return () => {
      clearTimeout(timer);
      controller.abort();
      setCalcLoading(false);
    };
  }, [step, systemCount, serverCount, phoneCount, billingCycle, pricing]);

  // ── Step 1: Signup ──
  const handleSignup = async (e) => {
    e.preventDefault();
    const errs = {
      companyName: validateCompanyName(form.companyName),
      email:       validateEmail(form.email),
      password:    validatePassword(form.password),
      phone:       validatePhone(form.phone),
    };
    setErrors(errs);
    if (Object.values(errs).some(Boolean)) return;

    // Phone mandatory check
    if (!form.phone.trim()) {
      setErrors(prev => ({ ...prev, phone: 'Mobile number is required' }));
      return;
    }

    setBusy(true);
    try {
      const telemetry_id = await getTelemetryId();
      const signupPath = referralSlug ? `/auth/signup/${referralSlug}` : '/auth/signup';
      const { data } = await api.post(signupPath, {
        companyName: form.companyName.trim(),
        email:       form.email.trim().toLowerCase(),
        password:    form.password,
        phone:       form.phone.trim(),
        telemetry_id,
      });
      setRegData(data);
      setOtp(''); setOtpErr(''); setApiErr('');
      setOtpTimer(40);

      await Swal.fire({
        icon: 'success', title: '✅ Account Created',
        html: `<p><strong>OTP sent to:</strong> ${form.email}</p>
               <p style="font-size:13px;color:#666;margin-top:8px">Enter the 6-digit code to verify your email.</p>`,
        confirmButtonText: '🔐 Verify Email', allowOutsideClick: false, background: '#fff',
      });
      setStep(2);
    } catch (err) {
      const message = err.response?.data?.message || 'Signup failed';
      if (message.includes('already registered')) {
        await Swal.fire({
          icon: 'error', title: '❌ Email Already Registered',
          text: 'This email is already registered. Please login.',
          confirmButtonText: 'Go to Login', background: '#fff',
        }).then(() => navigate('/login'));
      } else {
        Swal.fire({ icon: 'error', title: '❌ Registration Failed', text: message, background: '#fff' });
      }
      setApiErr(message);
    } finally {
      setBusy(false);
    }
  };

  // ── Step 2: OTP Verification ──
  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    if (!otp || otp.length !== 6) { setOtpErr('Please enter a valid 6-digit OTP'); return; }

    setBusy(true); setOtpErr(''); setApiErr('');
    try {
      const telemetry_id = await getTelemetryId();
      const { data } = await api.post('/auth/verify-otp', {
        email: form.email.trim().toLowerCase(), otp: otp.trim(), telemetry_id,
      });
      authStorage.setItem('co_token',   data.token);
      authStorage.setItem('co_user',    JSON.stringify(data.user));
      authStorage.setItem('co_company', JSON.stringify(data.company));
      if (data.tenant) authStorage.setItem('co_tenant', JSON.stringify(data.tenant));
      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
      setRegData(data);

      await Swal.fire({
        icon: 'success', title: '✅ Email Verified!',
        html: `<p><strong>Your email is verified.</strong></p>
               <p style="font-size:13px;color:#666;margin-top:8px">Configure your plan and complete payment to finish registration.</p>`,
        confirmButtonText: '📋 Configure Plan', allowOutsideClick: false, background: '#fff',
      });
      loadFromStorage();
      setStep(3);
    } catch (err) {
      const message = err.response?.data?.message || 'OTP verification failed';
      if (message.includes('expired')) {
        setOtpErr('OTP expired. Please request a new one.');
      } else if (message.includes('Invalid OTP')) {
        const remaining = err.response?.data?.remainingAttempts || 'several';
        setOtpErr(`Invalid OTP. ${remaining} attempts remaining.`);
      } else {
        setOtpErr(message);
      }
    } finally {
      setBusy(false);
    }
  };

  const handleResendOTP = async () => {
    setBusy(true);
    try {
      await api.post('/auth/resend-otp', { email: form.email.trim().toLowerCase() });
      setOtp(''); setOtpErr(''); setOtpTimer(40);
      await Swal.fire({ icon: 'success', title: '✅ OTP Resent', text: `New OTP sent to ${form.email}`, background: '#fff' });
    } catch (err) {
      setOtpErr(err.response?.data?.message || 'Failed to resend OTP');
    } finally {
      setBusy(false);
    }
  };

  // ── Step 3 → 4: Proceed to payment ──
  const handleConfigurePlan = () => {
    const sys = Number(systemCount) || 0;
    const srv = Number(serverCount) || 0;
    const phn = Number(phoneCount) || 0;
    if (sys === 0 && srv === 0 && phn === 0) {
      Swal.fire({ icon: 'warning', title: 'Invalid Configuration', text: 'Please enter at least 1 system, server, or phone.', background: '#fff' });
      return;
    }
    if (sys < 0 || srv < 0 || phn < 0) {
      Swal.fire({ icon: 'warning', title: 'Invalid Configuration', text: 'Counts cannot be negative.', background: '#fff' });
      return;
    }
    setStep(4);
  };

  // ── Step 4: Payment ──
  const handlePay = async () => {
    navigate('/checkout', {
      state: {
        checkout: {
          mode: 'base',
          planName: 'Dynamic Pricing',
          description: `${systemCount} Systems + ${serverCount} Server(s) + ${phoneCount} Phone(s)`,
          counts: {
            systemCount: Number(systemCount),
            serverCount: Number(serverCount),
            phoneCount: Number(phoneCount),
          },
          billingCycle,
          amountInr: calcResult?.totalInr,
          calc: calcResult,
          isUpgrade: false,
          autoPay: true,
          email: form.email,
          phone: form.phone,
          returnTo: '/',
          cancelTo: '/register',
          registration: true,
        },
      },
    });
  };

  const fmtInr = (n) => `₹${Number(n || 0).toLocaleString('en-IN')}`;

  const stepLabels = ['Company details', 'Email verification', 'Configure plan', 'Payment'];

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: 'linear-gradient(135deg, #020b18 0%, #060e1a 60%, #0a1628 100%)',
                  fontFamily: 'system-ui,sans-serif', padding: 24 }}>
      <div style={{ background: 'linear-gradient(145deg, #0c1a2e 0%, #0f2040 100%)', padding: 40, borderRadius: 16,
                    width: '100%', maxWidth: 520, border: '1px solid #1e3a5f',
                    boxShadow: '0 20px 60px rgba(0,0,0,0.6)' }}>

        {/* Step indicator */}
        <div style={{ display: 'flex', gap: 6, marginBottom: 28 }}>
          {stepLabels.map((s, i) => (
            <div key={s} style={{
              flex: 1, textAlign: 'center', fontSize: 10, padding: '5px 2px', borderRadius: 6,
              background: step === i + 1 ? '#1e3a5f' : step > i + 1 ? '#0f4a2e' : '#060e1a',
              color:      step === i + 1 ? '#93c5fd' : step > i + 1 ? '#34d399' : '#334155',
              border:     `1px solid ${step === i + 1 ? '#2563eb' : step > i + 1 ? '#10b981' : '#1e3a5f'}`,
              transition: 'all 0.3s',
            }}>{step > i + 1 ? '✓' : s}</div>
          ))}
        </div>

        {apiErr && (
          <div style={{ background: '#fee2e2', color: '#991b1b', padding: '9px 12px', borderRadius: 6, marginBottom: 16, fontSize: 13 }}>
            {apiErr}
          </div>
        )}

        {/* ── Step 1: Company details ── */}
        {step === 1 && (
          <form onSubmit={handleSignup} noValidate>
            <h2 style={{ color: '#e0f2fe', fontSize: 20, marginBottom: 6, fontWeight: 700 }}>Register your company</h2>
            <p style={{ color: '#475569', fontSize: 12, marginBottom: 20 }}>Create your Spartan Cyber Defense Center (SCDC) admin account</p>
            {/* Invite pre-fill banner */}
            {isInvited && (
              <div style={{
                background:'rgba(16,185,129,0.1)', border:'1px solid rgba(16,185,129,0.4)',
                borderRadius:8, padding:'10px 14px', marginBottom:16,
                display:'flex', alignItems:'center', gap:10,
              }}>
                <span style={{ fontSize:18 }}>✉</span>
                <div>
                  <div style={{ fontSize:12, fontWeight:700, color:'#34d399' }}>Partner Invite — Form Auto-Filled</div>
                  <div style={{ fontSize:11, color:'#64748b', marginTop:2 }}>
                    {prefillCompany && <span>Company: <b style={{ color:'#6ee7b7' }}>{prefillCompany}</b> · </span>}
                    {prefillEmail   && <span>Email: <b style={{ color:'#6ee7b7' }}>{prefillEmail}</b></span>}
                  </div>
                </div>
              </div>
            )}
            {referralSlug && (
              <div style={{
                background: referralInfo?.invalid ? '#3b1020' : '#062a22',
                color: referralInfo?.invalid ? '#fecdd3' : '#99f6e4',
                border: `1px solid ${referralInfo?.invalid ? '#be123c' : '#0f766e'}`,
                borderRadius: 6,
                padding: '9px 12px',
                marginBottom: 14,
                fontSize: 12,
              }}>
                {referralInfo?.invalid
                  ? 'Invalid partner registration link.'
                  : `Partner registration${referralInfo?.partner?.name ? `: ${referralInfo.partner.name}` : ''}`}
              </div>
            )}
            {inp('companyName', 'Company name *',     'text',     form, setForm, errors.companyName)}
            {inp('email',       'Admin email *',       'email',    form, setForm, errors.email)}
            {inp('password',    'Password * (min 8)', 'password', form, setForm, errors.password)}
            <div style={{ marginBottom: 14 }}>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>
                Mobile number * <span style={{ color: '#f87171', fontSize: 10 }}>(required)</span>
              </label>
              <input type="tel" value={form.phone} placeholder="+91 9876543210"
                onChange={e => setForm(f => ({ ...f, phone: e.target.value }))}
                style={{
                  width: '100%', padding: '9px 12px', borderRadius: 6, boxSizing: 'border-box',
                  background: '#060e1a', color: '#e2e8f0', fontSize: 13,
                  border: `1px solid ${errors.phone ? '#f87171' : '#1e3a5f'}`,
                }}
              />
              {errors.phone && <div style={{ fontSize: 11, color: '#f87171', marginTop: 3 }}>{errors.phone}</div>}
            </div>
            <button type="submit" disabled={busy} style={{
              width: '100%', padding: 12, borderRadius: 8, border: 'none', marginTop: 4,
              background: busy ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #1d4ed8)',
              color: '#fff', fontSize: 14, cursor: busy ? 'not-allowed' : 'pointer', fontWeight: 600,
              transition: 'all 0.2s',
            }}>
              {busy ? 'Creating account…' : 'Create account →'}
            </button>
            <p style={{ textAlign: 'center', fontSize: 12, color: '#475569', marginTop: 14 }}>
              Already registered? <Link to="/login" style={{ color: '#60a5fa', textDecoration: 'none' }}>Sign in</Link>
            </p>
          </form>
        )}

        {/* ── Step 2: OTP Verification ── */}
        {step === 2 && (
          <div>
            <h2 style={{ color: '#e0f2fe', fontSize: 18, marginBottom: 6, fontWeight: 700 }}>Verify your email</h2>
            <p style={{ fontSize: 12, color: '#475569', marginBottom: 18 }}>Enter the 6-digit OTP sent to <strong style={{ color: '#60a5fa' }}>{form.email}</strong></p>

            {otpTimer > 0 && (
              <div style={{ background: '#dbeafe', color: '#1e40af', padding: '10px 12px', borderRadius: 6, marginBottom: 16, fontSize: 13, textAlign: 'center', fontWeight: 500 }}>
                ⏰ OTP expires in <strong>{otpTimer}s</strong>
              </div>
            )}

            <form onSubmit={handleVerifyOTP} noValidate>
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>OTP *</label>
                <input type="text" value={otp}
                  onChange={e => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  maxLength="6" placeholder="000000"
                  style={{ width: '100%', padding: '12px', borderRadius: 6, boxSizing: 'border-box',
                    background: '#060e1a', color: '#e2e8f0', fontSize: 24, letterSpacing: '8px',
                    border: `1px solid ${otpErr ? '#f87171' : '#1e3a5f'}`, textAlign: 'center' }}
                />
                {otpErr && <div style={{ fontSize: 11, color: '#f87171', marginTop: 3 }}>{otpErr}</div>}
              </div>
              <button type="submit" disabled={busy || otp.length !== 6} style={{
                width: '100%', padding: 11, borderRadius: 6, border: 'none', marginBottom: 12,
                background: (busy || otp.length !== 6) ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #1d4ed8)',
                color: '#fff', fontSize: 14, cursor: (busy || otp.length !== 6) ? 'not-allowed' : 'pointer',
              }}>
                {busy ? 'Verifying…' : 'Verify OTP →'}
              </button>
            </form>

            <button onClick={handleResendOTP} disabled={busy || otpTimer > 0} style={{
              width: '100%', padding: 10, background: 'none', color: otpTimer > 0 ? '#334155' : '#60a5fa',
              border: '1px solid #1e3a5f', borderRadius: 6, fontSize: 12, cursor: otpTimer > 0 ? 'not-allowed' : 'pointer', marginBottom: 12,
            }}>
              {otpTimer > 0 ? `Resend OTP in ${otpTimer}s` : 'Resend OTP'}
            </button>
            <button onClick={() => setStep(1)} style={{
              width: '100%', padding: 8, background: 'none', color: '#475569', border: 'none', fontSize: 12, cursor: 'pointer',
            }}>← Back</button>
          </div>
        )}

        {/* ── Step 3: Configure Plan (dynamic, no predefined plans) ── */}
        {step === 3 && (
          <div>
            {/* Verified badge */}
            <div style={{ background: '#0a2e1f', border: '1px solid #10b981', borderRadius: 8, padding: 14, marginBottom: 20, textAlign: 'center' }}>
              <div style={{ fontSize: 24, color: '#10b981', marginBottom: 4 }}>✓</div>
              <div style={{ color: '#10b981', fontSize: 13, fontWeight: 600 }}>Email Verified!</div>
            </div>

	            <h2 style={{ color: '#e0f2fe', fontSize: 18, marginBottom: 6, fontWeight: 700 }}>Configure your plan</h2>
	            <p style={{ fontSize: 12, color: '#475569', marginBottom: 20 }}>
	              Choose how many systems, phones, and servers you need. Pricing is dynamic.
	            </p>
            <p role="status" style={{ color: '#fbbf24', fontSize: 12, marginBottom: 20 }}>
              Complete your payment to finish registration. Dashboard access opens only after payment is verified.
            </p>

            <div style={{ display: 'flex', gap: 10, marginBottom: 20 }} role="tablist" aria-label="Plan type">
              {[['dynamic', '💵 Dynamic Pricing'], ['enterprise', '🏢 Enterprise']].map(([id, label]) => <button type="button" role="tab" aria-selected={planType === id} key={id} onClick={() => setPlanType(id)} style={{ flex: 1, padding: 12, borderRadius: 8, border: '1px solid #2563eb', background: planType === id ? '#1e3a5f' : '#060e1a', color: '#e0f2fe', cursor: 'pointer' }}>{label}</button>)}
            </div>
            {planType === 'enterprise' ? <EnterprisePurchase registration /> : pricingLoading ? (
              <div style={{ textAlign: 'center', color: '#60a5fa', padding: 20, fontSize: 13 }}>Loading pricing…</div>
            ) : pricing ? (
              <>
                {/* Pricing card — shows newUser rates */}
                <div style={{ background: '#060e1a', borderRadius: 8, padding: 14, marginBottom: 20, border: '1px solid #1e3a5f' }}>
                  <div style={{ fontSize: 11, color: '#475569', marginBottom: 8, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>New User Pricing</div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
	                    {[
	                      { label: 'System / Month', val: fmtInr(pricing.pricePerSystemMonthly) },
	                      { label: 'System / Year',  val: fmtInr(pricing.pricePerSystemYearly) },
	                      { label: 'Phone / Month', val: fmtInr(pricing.pricePerPhoneMonthly) },
	                      { label: 'Phone / Year',  val: fmtInr(pricing.pricePerPhoneYearly) },
	                      { label: 'Server / Month', val: fmtInr(pricing.pricePerServerMonthly) },
	                      { label: 'Server / Year',  val: fmtInr(pricing.pricePerServerYearly) },
	                    ].map(({ label, val }) => (
                      <div key={label} style={{ background: '#0c1a2e', borderRadius: 6, padding: '8px 10px' }}>
                        <div style={{ fontSize: 10, color: '#475569', marginBottom: 2 }}>{label}</div>
                        <div style={{ fontSize: 14, color: '#60a5fa', fontWeight: 700 }}>{val}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Inputs */}
                <div style={{ marginBottom: 14 }}>
                  <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>
                    Number of Systems *
                    <span style={{ color: '#475569', fontWeight: 400, marginLeft: 6 }}>(how many endpoints to protect)</span>
                  </label>
                  <input type="number" min="1" value={systemCount}
                    onChange={e => setSystemCount(e.target.value)}
                    style={{ width: '100%', padding: '10px 12px', borderRadius: 6, boxSizing: 'border-box',
                      background: '#060e1a', color: '#e2e8f0', fontSize: 18, fontWeight: 600,
                      border: '1px solid #2563eb', textAlign: 'center' }}
                  />
                </div>

	                <div style={{ marginBottom: 14 }}>
	                  <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>
	                    Number of Servers
	                    <span style={{ color: '#475569', fontWeight: 400, marginLeft: 6 }}>(0 if none)</span>
                  </label>
                  <input type="number" min="0" value={serverCount}
                    onChange={e => setServerCount(e.target.value)}
                    style={{ width: '100%', padding: '10px 12px', borderRadius: 6, boxSizing: 'border-box',
                      background: '#060e1a', color: '#e2e8f0', fontSize: 18, fontWeight: 600,
                      border: '1px solid #1e3a5f', textAlign: 'center' }}
	                  />
	                </div>

	                <div style={{ marginBottom: 14 }}>
	                  <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>
	                    Number of Phones
	                    <span style={{ color: '#475569', fontWeight: 400, marginLeft: 6 }}>(Android + iPhone)</span>
	                  </label>
	                  <input type="number" min="0" value={phoneCount}
	                    onChange={e => setPhoneCount(e.target.value)}
	                    style={{ width: '100%', padding: '10px 12px', borderRadius: 6, boxSizing: 'border-box',
	                      background: '#060e1a', color: '#e2e8f0', fontSize: 18, fontWeight: 600,
	                      border: '1px solid #1e3a5f', textAlign: 'center' }}
	                  />
	                </div>

                {/* Billing cycle */}
                <div style={{ marginBottom: 20 }}>
                  <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 8 }}>Billing Cycle</label>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {['monthly', 'yearly'].map(cycle => (
                      <div key={cycle} onClick={() => setBillingCycle(cycle)} style={{
                        flex: 1, padding: '10px 12px', borderRadius: 8, cursor: 'pointer', textAlign: 'center',
                        border: `2px solid ${billingCycle === cycle ? '#2563eb' : '#1e3a5f'}`,
                        background: billingCycle === cycle ? '#0f2a4a' : '#060e1a',
                        transition: 'all 0.2s',
                      }}>
                        <div style={{ fontSize: 13, fontWeight: 600, color: billingCycle === cycle ? '#93c5fd' : '#475569', textTransform: 'capitalize' }}>{cycle}</div>
                        {cycle === 'yearly' && <div style={{ fontSize: 10, color: '#10b981', marginTop: 2 }}>Save ~17%</div>}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Live total */}
                {calcLoading ? (
                  <div style={{ textAlign: 'center', color: '#475569', fontSize: 12, padding: 10 }}>Calculating…</div>
                ) : calcResult ? (
                  <div style={{ background: '#0a2e1f', border: '1px solid #10b981', borderRadius: 8, padding: 16, marginBottom: 20 }}>
                    <div style={{ fontSize: 11, color: '#10b981', fontWeight: 600, marginBottom: 10, textTransform: 'uppercase' }}>💰 Total Payable</div>
                    {Number(calcResult.systemCount) > 0 && (
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span style={{ fontSize: 12, color: '#6ee7b7' }}>{calcResult.systemCount} Systems × {fmtInr(billingCycle === 'yearly' ? calcResult.pricePerSystemYearly : calcResult.pricePerSystemMonthly)}</span>
                        <span style={{ fontSize: 12, color: '#6ee7b7', fontWeight: 600 }}>{fmtInr(calcResult.subtotalSystems)}</span>
                      </div>
                    )}
	                    {Number(calcResult.serverCount) > 0 && (
	                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
	                        <span style={{ fontSize: 12, color: '#6ee7b7' }}>{calcResult.serverCount} Server(s) × {fmtInr(billingCycle === 'yearly' ? calcResult.pricePerServerYearly : calcResult.pricePerServerMonthly)}</span>
	                        <span style={{ fontSize: 12, color: '#6ee7b7', fontWeight: 600 }}>{fmtInr(calcResult.subtotalServers)}</span>
	                      </div>
	                    )}
	                    {Number(calcResult.phoneCount) > 0 && (
	                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
	                        <span style={{ fontSize: 12, color: '#6ee7b7' }}>{calcResult.phoneCount} Phone(s) × {fmtInr(billingCycle === 'yearly' ? calcResult.pricePerPhoneYearly : calcResult.pricePerPhoneMonthly)}</span>
	                        <span style={{ fontSize: 12, color: '#6ee7b7', fontWeight: 600 }}>{fmtInr(calcResult.subtotalPhones)}</span>
	                      </div>
	                    )}
                    <div style={{ borderTop: '1px solid #10b981', paddingTop: 10, marginTop: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 14, color: '#e0f2fe', fontWeight: 600 }}>Total ({billingCycle})</span>
                      <span style={{ fontSize: 22, color: '#34d399', fontWeight: 800 }}>{fmtInr(calcResult.totalInr)}</span>
                    </div>
                    <div style={{ fontSize: 10, color: '#4b5563', marginTop: 6 }}>Using new user pricing rates</div>
                  </div>
                ) : null}

                <button onClick={handleConfigurePlan} disabled={!calcResult || calcLoading} style={{
                  width: '100%', padding: 12, borderRadius: 8, border: 'none',
                  background: (!calcResult || calcLoading) ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #1d4ed8)',
                  color: '#fff', fontSize: 14, cursor: (!calcResult || calcLoading) ? 'not-allowed' : 'pointer', fontWeight: 600,
                }}>
                  Next: Confirm & Pay →
                </button>
              </>
            ) : (
              <div style={{ textAlign: 'center', color: '#f87171', fontSize: 13, padding: 20 }}>
                Failed to load pricing. Please refresh.
              </div>
            )}
          </div>
        )}

        {/* ── Step 4: Payment confirmation ── */}
        {step === 4 && (
          <div>
            <h2 style={{ color: '#e0f2fe', fontSize: 18, marginBottom: 18, fontWeight: 700 }}>Confirm &amp; Pay</h2>

            <div style={{ background: '#060e1a', borderRadius: 10, padding: 20, border: '1px solid #1e3a5f', marginBottom: 20 }}>
              <div style={{ fontSize: 11, color: '#475569', marginBottom: 12, textTransform: 'uppercase', letterSpacing: '0.5px', fontWeight: 600 }}>Order Summary</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontSize: 13, color: '#94a3b8' }}>Company</span>
                <span style={{ fontSize: 13, color: '#e0f2fe', fontWeight: 600 }}>{form.companyName}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontSize: 13, color: '#94a3b8' }}>Systems</span>
                <span style={{ fontSize: 13, color: '#60a5fa', fontWeight: 700 }}>{systemCount} systems</span>
              </div>
	              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
	                <span style={{ fontSize: 13, color: '#94a3b8' }}>Servers</span>
	                <span style={{ fontSize: 13, color: '#60a5fa', fontWeight: 700 }}>{serverCount} server(s)</span>
	              </div>
	              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
	                <span style={{ fontSize: 13, color: '#94a3b8' }}>Phones</span>
	                <span style={{ fontSize: 13, color: '#60a5fa', fontWeight: 700 }}>{phoneCount} phone(s)</span>
	              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
                <span style={{ fontSize: 13, color: '#94a3b8' }}>Billing</span>
                <span style={{ fontSize: 13, color: '#93c5fd', fontWeight: 600, textTransform: 'capitalize' }}>{billingCycle}</span>
              </div>
              <div style={{ borderTop: '1px solid #1e3a5f', paddingTop: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 15, color: '#e0f2fe', fontWeight: 700 }}>Total (incl. all fees)</span>
                <span style={{ fontSize: 26, color: '#34d399', fontWeight: 800 }}>
                  {calcResult ? `₹${Number(calcResult.totalInr).toLocaleString('en-IN')}` : '—'}
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 10 }}>
              <button onClick={() => setStep(3)} style={{
                flex: 1, padding: 11, background: 'none', color: '#60a5fa',
                border: '1px solid #1e3a5f', borderRadius: 8, fontSize: 13, cursor: 'pointer',
              }}>← Back</button>
              <button onClick={handlePay} disabled={busy} style={{
                flex: 2, padding: 11, background: busy ? '#1e3a5f' : 'linear-gradient(135deg, #059669, #047857)',
                color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, cursor: busy ? 'not-allowed' : 'pointer', fontWeight: 700,
              }}>
                {busy ? 'Opening payment…' : '💳 Pay with Razorpay'}
              </button>
            </div>

            <p style={{ fontSize: 11, color: '#334155', marginTop: 12, textAlign: 'center' }}>
              🔒 Secure payment via Razorpay · Subscription activates instantly
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
