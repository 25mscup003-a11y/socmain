import { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import api from '../api/axios';

export default function AcceptInvitePage() {
  const [params]   = useSearchParams();
  const navigate   = useNavigate();
  const token      = params.get('token');
  const [form, setForm]   = useState({ name: '', password: '', confirm: '' });
  const [error, setError] = useState('');
  const [busy, setBusy]   = useState(false);
  const [done, setDone]   = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (form.password !== form.confirm) {
      return setError('Passwords do not match');
    }
    setBusy(true); setError('');
    try {
      const { data } = await api.post('/users/accept-invite', {
        token,
        name:     form.name,
        password: form.password,
      });
      localStorage.setItem('co_token', data.token);
      localStorage.setItem('co_user',  JSON.stringify(data.user));
      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
      setDone(true);
      setTimeout(() => navigate('/'), 1500);
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid or expired invite link');
    } finally {
      setBusy(false);
    }
  };

  if (!token) {
    return (
      <div style={outer}>
        <div style={card}>
          <p style={{ color: '#fca5a5', fontSize: 14 }}>
            Invalid invite link. Please ask your admin to resend the invitation.
          </p>
          <Link to="/login" style={{ color: '#60a5fa', fontSize: 13 }}>Go to login</Link>
        </div>
      </div>
    );
  }

  return (
    <div style={outer}>
      <form onSubmit={submit} style={card}>
        <h1 style={{ color: '#e0f2fe', fontSize: 22, marginBottom: 6 }}>Accept invitation</h1>
        <p style={{ color: '#1e40af', fontSize: 13, marginBottom: 24 }}>
          Create your account to join your team.
        </p>

        {done && (
          <div style={{ background: '#064e3b', color: '#34d399', padding: '8px 12px',
                        borderRadius: 6, marginBottom: 16, fontSize: 13 }}>
            Account created! Redirecting…
          </div>
        )}
        {error && (
          <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '8px 12px',
                        borderRadius: 6, marginBottom: 16, fontSize: 13 }}>{error}</div>
        )}

        {[
          { key: 'name',     label: 'Full name',       type: 'text' },
          { key: 'password', label: 'Password',        type: 'password' },
          { key: 'confirm',  label: 'Confirm password', type: 'password' },
        ].map(({ key, label, type }) => (
          <div key={key} style={{ marginBottom: 14 }}>
            <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>{label}</label>
            <input type={type} required value={form[key]}
              onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
              style={inputStyle}/>
          </div>
        ))}

        <button type="submit" disabled={busy || done} style={{
          width: '100%', padding: 10, borderRadius: 6, border: 'none',
          background: busy ? '#1e3a5f' : '#2563eb', color: '#fff',
          fontSize: 14, cursor: 'pointer', marginTop: 8,
        }}>
          {busy ? 'Creating account…' : 'Create account'}
        </button>
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
