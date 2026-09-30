import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';

export default function SignupPage() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [form, setForm] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    phone: '',
  });
  const [errors, setErrors] = useState({});
  const [apiErr, setApiErr] = useState('');
  const [busy, setBusy] = useState(false);

  const set = (key, val) => {
    setForm(f => ({ ...f, [key]: val }));
    setErrors(e => ({ ...e, [key]: null }));
  };

  const validate = () => {
    const errs = {};

    if (!form.name || form.name.trim().length < 3)
      errs.name = 'Name must be at least 3 characters';

    if (!form.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      errs.email = 'Valid email required';

    if (!form.password || form.password.length < 8)
      errs.password = 'Password must be at least 8 characters';

    if (form.password !== form.confirmPassword)
      errs.confirmPassword = 'Passwords do not match';

    if (form.phone && !/^\d{10,}$/.test(form.phone.replace(/\D/g, '')))
      errs.phone = 'Valid phone number required';

    return errs;
  };

  const submit = async (e) => {
    e.preventDefault();
    const errs = validate();
    setErrors(errs);
    if (Object.keys(errs).length > 0) return;

    setBusy(true);
    setApiErr('');
    try {
      const { data } = await api.post('/auth/superadmin-signup', {
        name: form.name.trim(),
        email: form.email.trim().toLowerCase(),
        password: form.password,
        phone: form.phone.trim(),
      });

      localStorage.setItem('sa_token', data.token);
      localStorage.setItem('sa_user', JSON.stringify(data.user));
      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;

      navigate('/');
    } catch (err) {
      setApiErr(err.response?.data?.message || 'Signup failed. Please try again.');
    } finally {
      setBusy(false);
    }
  };

  const field = (key, label, type, placeholder) => (
    <div key={key} style={{ marginBottom: 16 }}>
      <label style={{ display: 'block', color: '#7c3aed', fontSize: 12, marginBottom: 4 }}>
        {label}
      </label>
      <input
        type={type}
        value={form[key]}
        onChange={e => set(key, e.target.value)}
        placeholder={placeholder}
        style={{
          width: '100%',
          padding: '10px 12px',
          borderRadius: 6,
          boxSizing: 'border-box',
          background: '#0f172a',
          border: `1px solid ${errors[key] ? '#ef4444' : '#312e81'}`,
          color: '#e2e8f0',
          fontSize: 14,
          outline: 'none',
        }}
      />
      {errors[key] && (
        <div style={{ fontSize: 11, color: '#ef4444', marginTop: 3 }}>
          {errors[key]}
        </div>
      )}
    </div>
  );

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#0f172a',
        fontFamily: 'system-ui,sans-serif',
        padding: '20px',
      }}
    >
      <form
        onSubmit={submit}
        noValidate
        style={{
          background: '#1e1b4b',
          padding: 40,
          borderRadius: 12,
          width: '100%',
          maxWidth: 400,
          border: '1px solid #312e81',
        }}
      >
        <h1 style={{ color: '#e9d5ff', marginBottom: 6, fontSize: 22 }}>
          Create Superadmin Account
        </h1>
        <p style={{ color: '#4c1d95', marginBottom: 28, fontSize: 13 }}>
          Spartan Cyber Defense Center (SCDC) Control Panel
        </p>

        {apiErr && (
          <div
            style={{
              background: '#7f1d1d',
              color: '#fca5a5',
              padding: '8px 12px',
              borderRadius: 6,
              marginBottom: 16,
              fontSize: 13,
            }}
          >
            {apiErr}
          </div>
        )}

        {field('name', 'Full Name', 'text', 'Your full name')}
        {field('email', 'Email', 'email', 'your.email@example.com')}
        {field('password', 'Password', 'password', 'At least 8 characters')}
        {field('confirmPassword', 'Confirm Password', 'password', 'Repeat password')}
        {field('phone', 'Phone (Optional)', 'tel', '+1 (555) 000-0000')}

        <button
          type="submit"
          disabled={busy}
          style={{
            width: '100%',
            padding: 11,
            borderRadius: 6,
            border: 'none',
            background: busy ? '#3730a3' : '#7c3aed',
            color: '#fff',
            fontSize: 14,
            fontWeight: 500,
            cursor: busy ? 'not-allowed' : 'pointer',
            marginBottom: 16,
            transition: 'background 0.2s',
          }}
          onMouseEnter={e => !busy && (e.target.style.background = '#6d28d9')}
          onMouseLeave={e => !busy && (e.target.style.background = '#7c3aed')}
        >
          {busy ? 'Creating account…' : 'Create Account'}
        </button>

        <p style={{ textAlign: 'center', fontSize: 13, color: '#4c1d95' }}>
          Already have an account?{' '}
          <Link
            to="/login"
            style={{ color: '#a78bfa', textDecoration: 'none', fontWeight: 500 }}
          >
            Sign in here
          </Link>
        </p>
      </form>
    </div>
  );
}
