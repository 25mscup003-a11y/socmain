import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';
import { captureBrowserLocation } from '../utils/browserLocation';
import { getTelemetryId } from '../utils/stytchFingerprint';

/**
 * Superadmin Login — 2-screen flow:
 *  screen = 'login' → Email + Password
 *  screen = '2fa'   → Google Authenticator TOTP (if enabled)
 */
export default function LoginPage() {
  const { login } = useAuth();
  const navigate  = useNavigate();

  const [screen, setScreen]     = useState('login');
  const [form,   setForm]       = useState({ email: '', password: '' });
  const [error,  setError]      = useState('');
  const [busy,   setBusy]       = useState(false);
  const [loginLocation, setLoginLocation] = useState(null);

  // 2FA state
  const [tfaCode,     setTfaCode]     = useState('');
  const [tfaErr,      setTfaErr]      = useState('');
  const [tfaAttempts, setTfaAttempts] = useState(0);

  // ── Step 1: Email + Password ──
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      const [location, telemetryId] = await Promise.all([captureBrowserLocation(), getTelemetryId()]);
      setLoginLocation(location);
      await login(form.email, form.password, location, telemetryId);
      // login() throws if 2FA required (handled below in catch)
      setError('');
      setTimeout(() => navigate('/'), 50);
    } catch (err) {
      // Check if 2FA is required
      if (err.requires2FA) {
        setTfaCode(''); setTfaErr(''); setTfaAttempts(0);
        setScreen('2fa');
        return;
      }
      const msg = err.message?.includes('Access denied')
        ? 'Access denied. Only superadmin or partner admin accounts are allowed.'
        : err.response?.data?.message || err.message || 'Login failed';
      setError(msg);
    } finally {
      setBusy(false);
    }
  };

  // ── Step 2: Google Authenticator TOTP ──
  const handle2FA = async (e) => {
    e.preventDefault();
    if (!tfaCode || tfaCode.length !== 6) {
      setTfaErr('Enter the 6-digit code from Google Authenticator');
      return;
    }
    setBusy(true); setTfaErr('');
    try {
      const { data } = await api.post('/auth/verify-2fa-login', {
        email: form.email.trim().toLowerCase(),
        code:  tfaCode.trim(),
        location: loginLocation,
      });

      // Ensure it's an allowed admin role
      if (!data?.user || !['superadmin', 'partner_admin'].includes(data.user.role)) {
        setTfaErr('Access denied: superadmin or partner admin only');
        return;
      }

      localStorage.setItem('sa_token', data.token);
      localStorage.setItem('sa_user',  JSON.stringify(data.user));
      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
      setTimeout(() => navigate('/'), 50);
    } catch (err) {
      const newAtt = tfaAttempts + 1;
      setTfaAttempts(newAtt);
      setTfaErr(err.response?.data?.message || 'Invalid code. Try again.');
      setTfaCode('');
      if (newAtt >= 5) {
        setError('Too many failed 2FA attempts. Please login again.');
        setScreen('login'); setTfaCode(''); setTfaErr(''); setTfaAttempts(0);
      }
    } finally {
      setBusy(false);
    }
  };

  // ── Styles ──
  const card = {
    background: 'linear-gradient(145deg, #1e1b4b 0%, #0f172a 100%)',
    padding: 40, borderRadius: 16, width: 380,
    border: '1px solid #312e81',
    boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
  };
  const inpStyle = {
    width: '100%', padding: '10px 12px', borderRadius: 8, boxSizing: 'border-box',
    background: '#0f172a', border: '1px solid #312e81', color: '#e2e8f0', fontSize: 14,
    outline: 'none', transition: 'border-color 0.2s',
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: 'linear-gradient(135deg, #020617 0%, #0f172a 100%)',
                  fontFamily: 'system-ui,sans-serif' }}>
      <div style={card}>

        {/* ── Login Screen ── */}
        {screen === 'login' && (
          <form onSubmit={submit}>
            <div style={{ textAlign: 'center', marginBottom: 28 }}>
              <div style={{ fontSize: 36, marginBottom: 8 }}>👑</div>
              <h1 style={{ color: '#e9d5ff', fontSize: 22, margin: 0, fontWeight: 800 }}>Super Admin</h1>
              <p style={{ color: '#4c1d95', fontSize: 13, margin: '6px 0 0' }}>Spartan Cyber Defense Center (SCDC) Control Panel</p>
            </div>

            {error && (
              <div style={{ background: '#7f1d1d', color: '#fca5a5', padding: '10px 12px', borderRadius: 8, marginBottom: 16, fontSize: 13 }}>
                {error}
              </div>
            )}

            {[['email', 'Email', 'email'], ['password', 'Password', 'password']].map(([key, label, type]) => (
              <div key={key} style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', color: '#7c3aed', fontSize: 12, marginBottom: 5, fontWeight: 600 }}>
                  {label.toUpperCase()}
                </label>
                <input type={type} required value={form[key]}
                  onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                  style={inpStyle}
                  onFocus={e => e.target.style.borderColor = '#7c3aed'}
                  onBlur={e => e.target.style.borderColor = '#312e81'}
                />
              </div>
            ))}

            <button type="submit" disabled={busy} style={{
              width: '100%', padding: 12, borderRadius: 8, border: 'none',
              background: busy ? '#312e81' : 'linear-gradient(135deg, #7c3aed, #6d28d9)',
              color: '#fff', fontSize: 14, fontWeight: 600,
              cursor: busy ? 'not-allowed' : 'pointer', marginBottom: 16,
              boxShadow: busy ? 'none' : '0 4px 14px rgba(124,58,237,0.4)',
              transition: 'all 0.2s',
            }}>
              {busy ? 'Signing in…' : 'Sign in →'}
            </button>

            <p style={{ textAlign: 'center', fontSize: 13, color: '#4c1d95' }}>
              Don't have an account?{' '}
              <Link to="/signup" style={{ color: '#7c3aed', textDecoration: 'none', fontWeight: 500 }}>Sign up</Link>
            </p>
          </form>
        )}

        {/* ── Google Authenticator 2FA Screen ── */}
        {screen === '2fa' && (
          <form onSubmit={handle2FA} noValidate>
            <div style={{ textAlign: 'center', marginBottom: 24 }}>
              <div style={{ fontSize: 48, marginBottom: 8 }}>🔐</div>
              <h1 style={{ color: '#e9d5ff', fontSize: 20, margin: 0, fontWeight: 800 }}>
                Two-Factor Auth
              </h1>
              <p style={{ color: '#6d28d9', fontSize: 13, margin: '8px 0 0' }}>
                Enter your Google Authenticator code to continue
              </p>
            </div>

            {/* Info box */}
            <div style={{ background: 'rgba(124,58,237,0.1)', border: '1px solid rgba(124,58,237,0.3)', borderRadius: 10, padding: '12px 16px', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ fontSize: 22 }}>📱</div>
                <div>
                  <div style={{ fontSize: 13, color: '#a78bfa', fontWeight: 600 }}>Google Authenticator</div>
                  <div style={{ fontSize: 12, color: '#c4b5fd', marginTop: 2 }}>
                    Find <strong>SOC4 ({form.email})</strong>
                  </div>
                </div>
              </div>
            </div>

            {/* TOTP input */}
            <div style={{ marginBottom: 18 }}>
              <label style={{ display: 'block', color: '#7c3aed', fontSize: 12, marginBottom: 6, fontWeight: 600 }}>
                AUTHENTICATOR CODE *
              </label>
              <input
                type="text" value={tfaCode} autoFocus
                onChange={e => { setTfaCode(e.target.value.replace(/\D/g, '').slice(0, 6)); setTfaErr(''); }}
                maxLength="6" placeholder="000000"
                style={{
                  width: '100%', padding: '16px 12px', borderRadius: 10, boxSizing: 'border-box',
                  background: '#0f172a', color: '#a78bfa', fontSize: 32, fontWeight: 800,
                  letterSpacing: '14px', textAlign: 'center',
                  border: `2px solid ${tfaErr ? '#f87171' : tfaCode.length === 6 ? '#7c3aed' : '#312e81'}`,
                  outline: 'none', transition: 'border-color 0.2s',
                  fontFamily: 'monospace',
                }}
                onFocus={e => { if (!tfaErr) e.target.style.borderColor = '#7c3aed'; }}
                onBlur={e => { if (!tfaErr && tfaCode.length !== 6) e.target.style.borderColor = '#312e81'; }}
              />
              {tfaErr && (
                <div style={{ fontSize: 12, color: '#f87171', marginTop: 6 }}>❌ {tfaErr}</div>
              )}
              {tfaAttempts > 0 && !tfaErr && (
                <div style={{ fontSize: 11, color: '#f59e0b', marginTop: 4 }}>
                  ⚠️ {5 - tfaAttempts} attempts remaining
                </div>
              )}
            </div>

            <div style={{ fontSize: 11, color: '#4c1d95', textAlign: 'center', marginBottom: 16 }}>
              ⏱ Code refreshes every 30 seconds
            </div>

            <button type="submit" disabled={busy || tfaCode.length !== 6} style={{
              width: '100%', padding: 13, borderRadius: 10, border: 'none',
              background: (busy || tfaCode.length !== 6)
                ? '#312e81'
                : 'linear-gradient(135deg, #7c3aed, #6d28d9)',
              color: '#fff', fontSize: 15, fontWeight: 700,
              cursor: (busy || tfaCode.length !== 6) ? 'not-allowed' : 'pointer',
              marginBottom: 12, transition: 'all 0.2s',
              boxShadow: (busy || tfaCode.length !== 6) ? 'none' : '0 4px 14px rgba(124,58,237,0.4)',
            }}>
              {busy ? 'Verifying…' : '✅ Verify & Sign In'}
            </button>

            <button type="button" onClick={() => { setScreen('login'); setTfaCode(''); setTfaErr(''); setTfaAttempts(0); }} style={{
              width: '100%', padding: 9, background: 'none', color: '#4c1d95',
              border: 'none', fontSize: 12, cursor: 'pointer',
            }}>
              ← Back to login
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
