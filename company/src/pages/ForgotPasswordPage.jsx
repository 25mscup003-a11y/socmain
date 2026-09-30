import { useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/axios';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [sent,  setSent]  = useState(false);
  const [busy,  setBusy]  = useState(false);
  const [error, setError] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError('');
    try {
      await api.post('/users/forgot-password', { email });
      setSent(true);
    } catch {
      setError('Something went wrong. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={outer}>
      <form onSubmit={submit} style={card}>
        <h1 style={{ color: '#e0f2fe', fontSize: 22, marginBottom: 6 }}>Forgot password</h1>
        <p style={{ color: '#1e40af', fontSize: 13, marginBottom: 24 }}>
          Enter your email and we'll send a reset link.
        </p>

        {sent ? (
          <div style={{ background: '#064e3b', color: '#34d399', padding: '12px 14px',
                        borderRadius: 6, fontSize: 13, marginBottom: 16 }}>
            If that email exists, a reset link has been sent. Check your inbox.
          </div>
        ) : (
          <>
            {error && (
              <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '8px 12px',
                            borderRadius: 6, marginBottom: 14, fontSize: 13 }}>{error}</div>
            )}
            <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>
              Email
            </label>
            <input type="email" required value={email}
              onChange={e => setEmail(e.target.value)}
              style={{ ...inputStyle, marginBottom: 16 }}/>
            <button type="submit" disabled={busy} style={{
              width: '100%', padding: 10, borderRadius: 6, border: 'none',
              background: busy ? '#1e3a5f' : '#2563eb', color: '#fff',
              fontSize: 14, cursor: 'pointer',
            }}>
              {busy ? 'Sending…' : 'Send reset link'}
            </button>
          </>
        )}

        <p style={{ textAlign: 'center', fontSize: 12, color: '#1e40af', marginTop: 20 }}>
          <Link to="/login" style={{ color: '#60a5fa', textDecoration: 'none' }}>← Back to login</Link>
        </p>
      </form>
    </div>
  );
}

const outer = {
  minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
  background: '#060e1a', fontFamily: 'system-ui, sans-serif',
};
const card = {
  background: '#0c1a2e', padding: 40, borderRadius: 12,
  width: 360, border: '1px solid #1e3a5f',
};
const inputStyle = {
  width: '100%', padding: '9px 12px', borderRadius: 6, boxSizing: 'border-box',
  background: '#060e1a', border: '1px solid #1e3a5f', color: '#e2e8f0', fontSize: 13,
};
