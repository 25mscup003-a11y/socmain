import { useState } from 'react';
import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import api from '../api/axios';

export default function ResetPasswordPage() {
  const [params]   = useSearchParams();
  const navigate   = useNavigate();
  const token      = params.get('token');
  const [form, setForm]   = useState({ password: '', confirm: '' });
  const [error, setError] = useState('');
  const [busy, setBusy]   = useState(false);
  const [done, setDone]   = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (form.password !== form.confirm) return setError('Passwords do not match');
    setBusy(true); setError('');
    try {
      await api.post('/users/reset-password', { token, password: form.password });
      setDone(true);
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid or expired reset link');
    } finally {
      setBusy(false);
    }
  };

  if (!token) {
    return (
      <div style={outer}>
        <div style={card}>
          <p style={{ color: '#fca5a5', fontSize: 14 }}>Invalid reset link.</p>
          <Link to="/forgot-password" style={{ color: '#60a5fa', fontSize: 13 }}>
            Request a new one
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div style={outer}>
      <form onSubmit={submit} style={card}>
        <h1 style={{ color: '#e0f2fe', fontSize: 22, marginBottom: 6 }}>Reset password</h1>
        <p style={{ color: '#1e40af', fontSize: 13, marginBottom: 24 }}>
          Choose a new password for your account.
        </p>

        {done && (
          <div style={{ background: '#064e3b', color: '#34d399', padding: '10px 12px',
                        borderRadius: 6, marginBottom: 14, fontSize: 13 }}>
            Password updated! Redirecting to login…
          </div>
        )}
        {error && (
          <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '8px 12px',
                        borderRadius: 6, marginBottom: 14, fontSize: 13 }}>{error}</div>
        )}

        {[
          { key: 'password', label: 'New password' },
          { key: 'confirm',  label: 'Confirm password' },
        ].map(({ key, label }) => (
          <div key={key} style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>{label}</label>
            <input type="password" required value={form[key]}
              onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
              style={inputStyle}/>
          </div>
        ))}

        <button type="submit" disabled={busy || done} style={{
          width: '100%', padding: 10, borderRadius: 6, border: 'none',
          background: busy ? '#1e3a5f' : '#2563eb', color: '#fff',
          fontSize: 14, cursor: 'pointer', marginTop: 8,
        }}>
          {busy ? 'Updating…' : 'Update password'}
        </button>

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
