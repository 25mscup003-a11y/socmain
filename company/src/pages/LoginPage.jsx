import { authStorage } from '../api/authStorage';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Swal from 'sweetalert2';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';
import { validateEmail } from '../utils/validate';
import { getTelemetryId } from '../utils/stytchFingerprint';
import { captureBrowserLocation } from '../utils/browserLocation';

/**
 * Login flow:
 *  screen = 'login'   → Email + Password
 *  screen = 'otp'     → Email OTP (unverified email)
 *  screen = '2fa'     → Google Authenticator TOTP (if 2FA enabled)
 *  screen = 'reset'   → Temporary password update before dashboard
 */
export default function LoginPage() {
  const { loadFromStorage } = useAuth();
  const navigate = useNavigate();

  const [screen, setScreen] = useState('login');  // 'login' | 'otp' | '2fa' | 'reset'
  const [form, setForm] = useState({ email: '', password: '' });
  const [busy, setBusy] = useState(false);
  const [pendingLogin, setPendingLogin] = useState(null);
  const [loginLocation, setLoginLocation] = useState(null);
  const [resetForm, setResetForm] = useState({ newPassword: '', confirmPassword: '' });
  const [resetErr, setResetErr] = useState('');

  // Email OTP state
  const [otp, setOtp] = useState('');
  const [otpErr, setOtpErr] = useState('');

  // 2FA TOTP state
  const [tfaCode, setTfaCode] = useState('');
  const [tfaErr, setTfaErr] = useState('');
  const [tfaAttempts, setTfaAttempts] = useState(0);

  // ── Finalize login — store token and go to dashboard ──
  const finalizeLogin = (data) => {
    if (data.requiresPasswordReset) {
      setPendingLogin(data);
      setResetForm({ newPassword: '', confirmPassword: '' });
      setResetErr('');
      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
      setScreen('reset');
      return;
    }
    authStorage.setItem('co_token', data.token);
    authStorage.setItem('co_user', JSON.stringify(data.user));
    authStorage.removeItem('co_impersonation');
    if (data.company) {
      authStorage.setItem('co_company', JSON.stringify(data.company));
    }
    if (data.tenant) {
      authStorage.setItem('co_tenant', JSON.stringify(data.tenant));
    }
    api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;

    Swal.fire({
      icon: 'success',
      title: '✅ Login Successful',
      text: 'Redirecting to dashboard…',
      timer: 1400,
      showConfirmButton: false,
      background: '#fff',
    }).then(() => {
      loadFromStorage();
      if (data.redirectUrl && data.redirectUrl.startsWith('http') && !data.redirectUrl.includes(window.location.host)) {
        window.location.href = data.redirectUrl;
      } else {
        setTimeout(() => navigate('/'), 50);
      }
    });
  };

  // ── Step 1: Email + Password ──
  const handleLogin = async (e) => {
    e.preventDefault();

    const emailErr = validateEmail(form.email);
    if (emailErr) {
      Swal.fire({ icon: 'error', title: '❌ Validation Error', text: emailErr });
      return;
    }
    if (!form.password) {
      Swal.fire({ icon: 'error', title: '❌ Validation Error', text: 'Password is required' });
      return;
    }

    setBusy(true);
    try {
      const location = await captureBrowserLocation();
      setLoginLocation(location);
      // Collect device fingerprint silently before login
      const telemetry_id = await getTelemetryId();

      const { data } = await api.post('/auth/login', {
        email: form.email.trim().toLowerCase(),
        password: form.password,
        telemetry_id,
        location,
      });

      if (data.requiresOTP) {
        // Email not yet verified — show OTP screen
        setOtp(''); setOtpErr('');
        setScreen('otp');
        Swal.fire({
          icon: 'info',
          title: '📧 Email Verification Required',
          text: `We sent a 6-digit code to ${form.email}`,
          timer: 2500, showConfirmButton: false, background: '#fff',
        });
      } else if (data.requires2FA) {
        // 2FA enabled — show Google Authenticator screen
        setTfaCode(''); setTfaErr(''); setTfaAttempts(0);
        setScreen('2fa');
        Swal.fire({
          icon: 'info',
          title: '🔐 Two-Factor Authentication',
          text: 'Open Google Authenticator and enter your 6-digit code.',
          timer: 2800, showConfirmButton: false, background: '#fff',
        });
      } else {
        // Direct login (no 2FA, email already verified)
        finalizeLogin(data);
      }
    } catch (err) {
      const msg = err.response?.data?.message || err.message || 'Login failed';
      const lower = msg.toLowerCase();
      let title = '❌ Login Failed';
      let text = msg;
      if (lower.includes('user not found') || lower.includes('not found')) {
        title = '❌ User Not Found'; text = 'This email is not registered.';
      } else if (lower.includes('wrong password') || lower.includes('incorrect')) {
        title = '❌ Wrong Password'; text = 'The password you entered is incorrect.';
      } else if (lower.includes('verify') || lower.includes('email')) {
        title = '📧 Email Verification Required'; text = 'Please verify your email first.';
      }
      Swal.fire({ icon: 'error', title, text });
    } finally {
      setBusy(false);
    }
  };

  // ── Step 2a: Email OTP verification ──
  const handleOTPSubmit = async (e) => {
    e.preventDefault();
    if (!otp || otp.length !== 6) {
      setOtpErr('Please enter a 6-digit OTP');
      return;
    }
    setBusy(true); setOtpErr('');
    try {
      const telemetry_id = await getTelemetryId();
      const { data } = await api.post('/auth/verify-login-otp', {
        email: form.email.trim().toLowerCase(),
        otp: otp.trim(),
        telemetry_id,
        location: loginLocation,
      });

      // After OTP → check if this user also has 2FA
      if (data.requires2FA) {
        setTfaCode(''); setTfaErr(''); setTfaAttempts(0);
        setScreen('2fa');
      } else {
        finalizeLogin(data);
      }
    } catch (err) {
      const msg = err.response?.data?.message || 'OTP verification failed';
      const lower = msg.toLowerCase();
      if (lower.includes('expired')) {
        setOtpErr('OTP expired. Please login again.');
        await Swal.fire({ icon: 'error', title: '⏰ OTP Expired', text: 'Please login again.', background: '#fff' });
        setScreen('login'); setOtp('');
      } else if (lower.includes('too many') || err.response?.status === 429) {
        await Swal.fire({ icon: 'error', title: '🔒 Too Many Attempts', text: 'Account locked. Try again in 30 minutes.', background: '#fff' });
        setScreen('login'); setOtp('');
      } else {
        setOtpErr(msg);
      }
      setOtp('');
    } finally {
      setBusy(false);
    }
  };

  const handleResendOTP = async () => {
    setBusy(true);
    try {
      await api.post('/auth/resend-otp', { email: form.email.trim().toLowerCase() });
      setOtp(''); setOtpErr('');
      Swal.fire({ icon: 'success', title: '✅ OTP Resent', text: `New code sent to ${form.email}`, timer: 2000, showConfirmButton: false, background: '#fff' });
    } catch (err) {
      Swal.fire({ icon: 'error', title: '❌ Resend Failed', text: err.response?.data?.message || 'Could not resend OTP' });
    } finally {
      setBusy(false);
    }
  };

  // ── Step 2b: Google Authenticator TOTP ──
  const handle2FASubmit = async (e) => {
    e.preventDefault();
    if (!tfaCode || tfaCode.length !== 6) {
      setTfaErr('Enter the 6-digit code from Google Authenticator');
      return;
    }
    setBusy(true); setTfaErr('');
    try {
      const { data } = await api.post('/auth/verify-2fa-login', {
        email: form.email.trim().toLowerCase(),
        code: tfaCode.trim(),
        location: loginLocation,
      });
      finalizeLogin(data);
    } catch (err) {
      const msg = err.response?.data?.message || 'Invalid code';
      const newAtt = tfaAttempts + 1;
      setTfaAttempts(newAtt);
      setTfaErr(msg);
      setTfaCode('');

      // Lock out after 5 failed attempts
      if (newAtt >= 5) {
        await Swal.fire({
          icon: 'error',
          title: '🔒 Too Many Attempts',
          text: 'Too many failed 2FA attempts. Please login again.',
          background: '#fff',
        });
        setScreen('login'); setTfaCode(''); setTfaErr(''); setTfaAttempts(0);
      }
    } finally {
      setBusy(false);
    }
  };

  const handleTemporaryPasswordReset = async (e) => {
    e.preventDefault();
    setResetErr('');
    if (!pendingLogin?.token) {
      setResetErr('Login session expired. Please login again.');
      setScreen('login');
      return;
    }
    if (!resetForm.newPassword || resetForm.newPassword.length < 8) {
      setResetErr('New password must be at least 8 characters.');
      return;
    }
    if (resetForm.newPassword !== resetForm.confirmPassword) {
      setResetErr('New password and confirm password must match.');
      return;
    }
    if (resetForm.newPassword === form.password) {
      setResetErr('New password must be different from temporary password.');
      return;
    }

    setBusy(true);
    try {
      api.defaults.headers.common['Authorization'] = `Bearer ${pendingLogin.token}`;
      const { data } = await api.post('/users/force-password-reset', {
        newPassword: resetForm.newPassword,
      });
      const nextLogin = {
        ...pendingLogin,
        requiresPasswordReset: false,
        user: { ...pendingLogin.user, ...(data.user || {}), forcePasswordReset: false },
      };
      setPendingLogin(null);
      setResetForm({ newPassword: '', confirmPassword: '' });
      finalizeLogin(nextLogin);
    } catch (err) {
      setResetErr(err.response?.data?.message || err.message || 'Password update failed.');
    } finally {
      setBusy(false);
    }
  };

  // ── Shared styles ──
  const card = {
    background: 'linear-gradient(145deg, #0c1a2e 0%, #0f2040 100%)',
    padding: 40, borderRadius: 16, width: 380,
    border: '1px solid #1e3a5f',
    boxShadow: '0 20px 60px rgba(0,0,0,0.6)',
  };
  const inpStyle = {
    width: '100%', padding: 11, borderRadius: 8, boxSizing: 'border-box',
    background: '#060e1a', color: '#e2e8f0', fontSize: 13,
    border: '1px solid #1e3a5f', outline: 'none', transition: 'border-color 0.2s',
  };
  const btnPrimary = (disabled) => ({
    width: '100%', padding: 12, borderRadius: 8, border: 'none',
    background: disabled ? '#1e3a5f' : 'linear-gradient(135deg, #2563eb, #1d4ed8)',
    color: '#fff', fontSize: 14, fontWeight: 600,
    cursor: disabled ? 'not-allowed' : 'pointer', marginBottom: 12,
    transition: 'all 0.2s',
  });

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'linear-gradient(135deg, #020b18 0%, #060e1a 60%, #0a1628 100%)',
      fontFamily: 'system-ui,sans-serif'
    }}>
      <div style={card}>

        {/* ── SCREEN: Login ── */}
        {screen === 'login' && (
          <form onSubmit={handleLogin} noValidate>
            <div style={{ textAlign: 'center', marginBottom: 28 }}>
              <div style={{ fontSize: 36, marginBottom: 8 }}>🔐</div>
              <h1 style={{ color: '#e0f2fe', fontSize: 22, margin: 0, fontWeight: 800 }}>Sign In</h1>
              <p style={{ color: '#475569', fontSize: 13, margin: '6px 0 0' }}>Spartan Cyber Defense Center (SCDC)</p>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 5, fontWeight: 600 }}>EMAIL *</label>
              <input type="email" value={form.email}
                onChange={e => setForm({ ...form, email: e.target.value })}
                placeholder="your@email.com"
                style={inpStyle}
                onFocus={e => e.target.style.borderColor = '#3b82f6'}
                onBlur={e => e.target.style.borderColor = '#1e3a5f'}
              />
            </div>

            <div style={{ marginBottom: 20 }}>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 5, fontWeight: 600 }}>PASSWORD *</label>
              <input type="password" value={form.password}
                onChange={e => setForm({ ...form, password: e.target.value })}
                placeholder="••••••••"
                style={inpStyle}
                onFocus={e => e.target.style.borderColor = '#3b82f6'}
                onBlur={e => e.target.style.borderColor = '#1e3a5f'}
              />
            </div>

            <button type="submit" disabled={busy} style={btnPrimary(busy)}>
              {busy ? 'Signing in…' : 'Sign in →'}
            </button>

            <div style={{ textAlign: 'center', marginBottom: 16 }}>
              <a href="/forgot-password" style={{ color: '#60a5fa', textDecoration: 'none', fontSize: 12 }}>
                🔑 Forgot Password?
              </a>
            </div>

            <p style={{ textAlign: 'center', fontSize: 13, color: '#475569', marginTop: 8 }}>
              New company?{' '}
              <a href="/register" style={{ color: '#60a5fa', textDecoration: 'none' }}>Register here</a>
            </p>
          </form>
        )}

        {/* ── SCREEN: Email OTP ── */}
        {screen === 'otp' && (
          <form onSubmit={handleOTPSubmit} noValidate>
            <div style={{ textAlign: 'center', marginBottom: 24 }}>
              <div style={{ fontSize: 36, marginBottom: 8 }}>📧</div>
              <h1 style={{ color: '#e0f2fe', fontSize: 20, margin: 0, fontWeight: 800 }}>Verify Email</h1>
              <p style={{ color: '#475569', fontSize: 13, margin: '6px 0 0' }}>
                Code sent to <strong style={{ color: '#60a5fa' }}>{form.email}</strong>
              </p>
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 5, fontWeight: 600 }}>OTP *</label>
              <input type="text" value={otp}
                onChange={e => { setOtp(e.target.value.replace(/\D/g, '').slice(0, 6)); setOtpErr(''); }}
                maxLength="6" placeholder="000000" autoFocus
                style={{ ...inpStyle, fontSize: 28, letterSpacing: '10px', textAlign: 'center', padding: '14px 12px' }}
              />
              {otpErr && <div style={{ fontSize: 12, color: '#f87171', marginTop: 5 }}>{otpErr}</div>}
            </div>

            <button type="submit" disabled={busy || otp.length !== 6} style={btnPrimary(busy || otp.length !== 6)}>
              {busy ? 'Verifying…' : 'Verify OTP →'}
            </button>

            <button type="button" onClick={handleResendOTP} disabled={busy} style={{
              width: '100%', padding: 10, background: 'none', color: '#60a5fa',
              border: '1px solid #1e3a5f', borderRadius: 8, fontSize: 12,
              cursor: busy ? 'not-allowed' : 'pointer', marginBottom: 10,
            }}>
              📨 Resend OTP
            </button>

            <button type="button" onClick={() => { setScreen('login'); setOtp(''); setOtpErr(''); }} style={{
              width: '100%', padding: 8, background: 'none', color: '#475569',
              border: 'none', fontSize: 12, cursor: 'pointer',
            }}>
              ← Back to login
            </button>
          </form>
        )}

        {/* ── SCREEN: Google Authenticator 2FA ── */}
        {screen === '2fa' && (
          <form onSubmit={handle2FASubmit} noValidate>
            {/* Header */}
            <div style={{ textAlign: 'center', marginBottom: 24 }}>
              <div style={{ fontSize: 48, marginBottom: 8 }}>🔐</div>
              <h1 style={{ color: '#e0f2fe', fontSize: 20, margin: 0, fontWeight: 800 }}>
                Two-Factor Authentication
              </h1>
              <p style={{ color: '#475569', fontSize: 13, margin: '8px 0 0' }}>
                Open <strong style={{ color: '#34d399' }}>Google Authenticator</strong> and enter the 6-digit code for your account.
              </p>
            </div>

            {/* Info box */}
            <div style={{ background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.25)', borderRadius: 10, padding: '12px 16px', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ fontSize: 22 }}>📱</div>
                <div>
                  <div style={{ fontSize: 13, color: '#34d399', fontWeight: 600 }}>Google Authenticator</div>
                  <div style={{ fontSize: 12, color: '#6ee7b7', marginTop: 2 }}>
                    Find <strong>SOC4 ({form.email})</strong> in the app
                  </div>
                </div>
              </div>
            </div>

            {/* 6-digit code input */}
            <div style={{ marginBottom: 18 }}>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 6, fontWeight: 600 }}>
                AUTHENTICATOR CODE *
              </label>
              <input
                type="text" value={tfaCode} autoFocus
                onChange={e => { setTfaCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setTfaErr(''); }}
                maxLength="6" placeholder="000000"
                style={{
                  width: '100%', padding: '16px 12px', borderRadius: 10, boxSizing: 'border-box',
                  background: '#060e1a', color: '#34d399', fontSize: 32, fontWeight: 800,
                  letterSpacing: '14px', textAlign: 'center',
                  border: `2px solid ${tfaErr ? '#f87171' : tfaCode.length === 6 ? '#10b981' : '#1e3a5f'}`,
                  outline: 'none', transition: 'border-color 0.2s',
                  fontFamily: 'monospace',
                }}
                onFocus={e => { if (!tfaErr) e.target.style.borderColor = '#10b981'; }}
                onBlur={e => { if (!tfaErr && tfaCode.length !== 6) e.target.style.borderColor = '#1e3a5f'; }}
              />
              {tfaErr && (
                <div style={{ fontSize: 12, color: '#f87171', marginTop: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span>❌</span> {tfaErr}
                </div>
              )}
              {tfaAttempts > 0 && !tfaErr && (
                <div style={{ fontSize: 11, color: '#f59e0b', marginTop: 4 }}>
                  ⚠️ {5 - tfaAttempts} attempts remaining
                </div>
              )}
            </div>

            {/* Code refreshes every 30s hint */}
            <div style={{ fontSize: 11, color: '#334155', textAlign: 'center', marginBottom: 16 }}>
              ⏱ Code refreshes every 30 seconds. If it doesn't work, wait for the next code.
            </div>

            <button type="submit" disabled={busy || tfaCode.length !== 6} style={{
              width: '100%', padding: 13, borderRadius: 10, border: 'none',
              background: (busy || tfaCode.length !== 6)
                ? '#1e3a5f'
                : 'linear-gradient(135deg, #10b981, #059669)',
              color: '#fff', fontSize: 15, fontWeight: 700,
              cursor: (busy || tfaCode.length !== 6) ? 'not-allowed' : 'pointer',
              marginBottom: 12, transition: 'all 0.2s',
              boxShadow: (busy || tfaCode.length !== 6) ? 'none' : '0 4px 14px rgba(16,185,129,0.4)',
            }}>
              {busy ? (
                <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                  <span style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}>⟳</span>
                  Verifying…
                </span>
              ) : '✅ Verify & Sign In'}
            </button>

            <button type="button" onClick={() => { setScreen('login'); setTfaCode(''); setTfaErr(''); setTfaAttempts(0); }} style={{
              width: '100%', padding: 9, background: 'none', color: '#475569',
              border: 'none', fontSize: 12, cursor: 'pointer',
            }}>
              ← Back to login
            </button>
          </form>
        )}

        {/* ── SCREEN: Temporary Password Reset ── */}
        {screen === 'reset' && (
          <form onSubmit={handleTemporaryPasswordReset} noValidate>
            <div style={{ textAlign: 'center', marginBottom: 24 }}>
              <div style={{ fontSize: 42, marginBottom: 8 }}>🔑</div>
              <h1 style={{ color: '#e0f2fe', fontSize: 20, margin: 0, fontWeight: 800 }}>
                Update Temporary Password
              </h1>
              <p style={{ color: '#94a3b8', fontSize: 13, margin: '8px 0 0', lineHeight: 1.5 }}>
                For security, create your own password before opening the dashboard.
              </p>
            </div>

            <div style={{ background: 'rgba(245,158,11,0.10)', border: '1px solid rgba(245,158,11,0.28)', borderRadius: 10, padding: '12px 14px', marginBottom: 18, color: '#fde68a', fontSize: 12, lineHeight: 1.5 }}>
              You are using a temporary password created by Super Admin. This step is required only on first login.
            </div>

            <div style={{ marginBottom: 14 }}>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 5, fontWeight: 600 }}>NEW PASSWORD *</label>
              <input
                type="password"
                value={resetForm.newPassword}
                onChange={e => { setResetForm(prev => ({ ...prev, newPassword: e.target.value })); setResetErr(''); }}
                placeholder="Minimum 8 characters"
                style={inpStyle}
              />
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 5, fontWeight: 600 }}>CONFIRM PASSWORD *</label>
              <input
                type="password"
                value={resetForm.confirmPassword}
                onChange={e => { setResetForm(prev => ({ ...prev, confirmPassword: e.target.value })); setResetErr(''); }}
                placeholder="Confirm new password"
                style={inpStyle}
              />
              {resetErr && <div style={{ fontSize: 12, color: '#f87171', marginTop: 6 }}>{resetErr}</div>}
            </div>

            <button type="submit" disabled={busy} style={btnPrimary(busy)}>
              {busy ? 'Updating password…' : 'Update Password & Continue →'}
            </button>
          </form>
        )}
      </div>

      {/* Spin animation for loading */}
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
