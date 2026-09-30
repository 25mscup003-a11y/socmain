import { useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/axios';

const benefits = [
  'Apne customers ko dedicated SOC monitoring platform provide karo',
  'Partner tenant, referral link, and customer onboarding flow',
  'Company dashboards, users, agents, alerts, and reports under one partner view',
  'Enterprise/custom plan request and payment approval flow',
];

const steps = [
  'Partner details submit karo',
  'Superadmin partner tenant aur admin login create karega',
  'Enterprise plan approve/payment ke baad dashboard unlock hoga',
  'Referral link se customer companies onboard hongi',
];

const initialForm = {
  name: '',
  slug: '',
  adminName: '',
  adminEmail: '',
  adminPassword: '',
  confirmPassword: '',
  phone: '',
};

export default function PartnerRegistrationPage() {
  const [form, setForm] = useState(initialForm);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [created, setCreated] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const generatedSubdomain = slugify(`${form.name}-${form.slug}`);

  const setField = (key, value) => {
    setForm(prev => ({
      ...prev,
      [key]: key === 'slug' ? value.toLowerCase().replace(/[^a-z0-9-]/g, '-') : value,
    }));
  };

  const submit = async e => {
    e.preventDefault();
    setSaving(true);
    setError('');
    setCreated(null);
    if (form.adminPassword !== form.confirmPassword) {
      setSaving(false);
      setError('Password aur confirm password match nahi kar rahe');
      return;
    }
    try {
      const { data } = await api.post('/auth/partner-register', form);
      setCreated(data);
      setForm(initialForm);
    } catch (err) {
      setError(err.response?.data?.message || 'Partner registration submit nahi ho paya');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="partnerPage">
      <style>{css}</style>
      <nav className="partnerNav">
        <Link className="brand" to="/#home">
          <span>S</span>
          <strong>Spartan Cyber Defense Center (SCDC)</strong>
        </Link>
        <div>
          <Link to="/#home">Home</Link>
          <Link to="/login">Login</Link>
          <Link className="navCta" to="/register">Start</Link>
        </div>
      </nav>

      <main>
        <section className="hero">
          <div>
            <p className="eyebrow">Partner Program</p>
            <h1>Partner Registration</h1>
            <p className="lead">
              Agar aap cyber security service provider, consultant, MSP, ya reseller ho,
              to Spartan Cyber Defense Center (SCDC) partner dashboard ke through apne clients ko centralized monitoring,
              alerts, reports, compliance, and SOC operations provide kar sakte ho.
            </p>
            <div className="actions">
              <Link className="primary" to="/login">Partner Login</Link>
              <Link className="secondary" to="/#home">View Platform</Link>
            </div>
          </div>

          <form className="requestBox" onSubmit={submit}>
            <h2>Create Partner Request</h2>
            <p>
              Form submit hote hi request Super Admin ke Partner Management me Pending Approval status ke saath show hogi.
            </p>
            <div className="formGrid">
              <label>
                <span>Partner Company Name *</span>
                <input value={form.name} onChange={e => setField('name', e.target.value)} required placeholder="Acme Security" />
              </label>
              <label>
                <span>State *</span>
                <input value={form.slug} onChange={e => setField('slug', e.target.value)} required placeholder="uttar-pradesh" />
              </label>
              <label>
                <span>Admin Name *</span>
                <input value={form.adminName} onChange={e => setField('adminName', e.target.value)} placeholder="Partner Admin" />
              </label>
              <label>
                <span>Admin Email *</span>
                <input type="email" value={form.adminEmail} onChange={e => setField('adminEmail', e.target.value)} required placeholder="admin@example.com" />
              </label>
              <label>
                <span>Mobile Number *</span>
                <input value={form.phone} onChange={e => setField('phone', e.target.value)} required placeholder="+91 9876543210" />
              </label>
              <label>
                <span>Password *</span>
                <div className="passwordField">
                  <input type={showPassword ? 'text' : 'password'} value={form.adminPassword} onChange={e => setField('adminPassword', e.target.value)} required minLength={8} placeholder="Minimum 8 characters" />
                  <button type="button" onClick={() => setShowPassword(v => !v)} aria-label={showPassword ? 'Hide password' : 'Show password'}>
                    {showPassword ? '◉' : '◎'}
                  </button>
                </div>
              </label>
              <label>
                <span>Confirm Password *</span>
                <div className="passwordField">
                  <input type={showConfirmPassword ? 'text' : 'password'} value={form.confirmPassword} onChange={e => setField('confirmPassword', e.target.value)} required minLength={8} placeholder="Re-enter password" />
                  <button type="button" onClick={() => setShowConfirmPassword(v => !v)} aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'}>
                    {showConfirmPassword ? '◉' : '◎'}
                  </button>
                </div>
              </label>
              <div className="subdomainPreview">
                Partner Subdomain: <strong>{generatedSubdomain || 'company-state'}</strong>
              </div>
            </div>
            {error && <div className="formError">{error}</div>}
            {created && (
              <div className="formSuccess">
                <strong>Partner request submitted.</strong>
                <span>Status: Pending Approval</span>
                <span>Your request will be approved in the next 24h.</span>
                <span>Partner admin: {created.partnerAdmin?.email}</span>
              </div>
            )}
            <button className="submitBtn" disabled={saving}>{saving ? 'Submitting...' : 'Submit Request'}</button>
          </form>
        </section>

        <section className="contentGrid">
          <div className="panel">
            <h2>Partner Ko Kya Milega</h2>
            <div className="list">
              {benefits.map(item => (
                <div key={item}><span>✓</span><p>{item}</p></div>
              ))}
            </div>
          </div>

          <div className="panel">
            <h2>Kaise Start Hoga</h2>
            <div className="steps">
              {steps.map((item, index) => (
                <div key={item}>
                  <b>{index + 1}</b>
                  <p>{item}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="cta">
          <h2>Partner dashboard ready karwana hai?</h2>
          <p>Form submit karne ke baad entry Superadmin partners page par visible hogi.</p>
          <div className="ctaActions">
            <Link className="primary dark" to="/login">Go To Login</Link>
            <a className="secondary darkOutline" href="http://localhost:3001/partners">Open Superadmin Partners</a>
          </div>
        </section>
      </main>
    </div>
  );
}

const slugify = value => String(value || '')
  .trim()
  .toLowerCase()
  .replace(/[^a-z0-9-]/g, '-')
  .replace(/-+/g, '-')
  .replace(/^-|-$/g, '');

const css = `
.partnerPage {
  min-height: 100vh;
  background: #07110f;
  color: #eef8f3;
}
.partnerNav {
  min-height: 68px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 clamp(18px, 5vw, 64px);
  border-bottom: 1px solid rgba(148, 163, 184, 0.18);
  background: rgba(7, 17, 15, 0.9);
}
.brand, .partnerNav a {
  color: #e2e8f0;
  text-decoration: none;
  font-size: 13px;
  font-weight: 800;
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  font-size: 17px;
}
.brand span {
  width: 34px;
  height: 34px;
  border-radius: 8px;
  display: grid;
  place-items: center;
  background: #42f5a7;
  color: #03110d;
}
.partnerNav div {
  display: flex;
  align-items: center;
  gap: 18px;
}
.navCta {
  padding: 8px 13px;
  border-radius: 7px;
  background: #42f5a7;
  color: #03110d !important;
}
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(310px, 0.58fr);
  gap: clamp(24px, 5vw, 58px);
  align-items: center;
  padding: clamp(44px, 7vw, 88px) clamp(18px, 5vw, 64px);
}
.eyebrow {
  color: #42f5a7;
  font-size: 12px;
  font-weight: 900;
  text-transform: uppercase;
  margin-bottom: 14px;
}
h1 {
  font-size: clamp(44px, 7vw, 82px);
  line-height: 0.96;
  margin-bottom: 18px;
}
.lead {
  max-width: 760px;
  color: #b8c7c0;
  font-size: clamp(16px, 2vw, 20px);
}
.actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 26px;
}
.primary, .secondary {
  min-height: 44px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 0 18px;
  border-radius: 8px;
  text-decoration: none;
  font-size: 14px;
  font-weight: 900;
}
.primary {
  background: #42f5a7;
  color: #03110d;
}
.secondary {
  border: 1px solid rgba(226, 232, 240, 0.25);
  color: #e2e8f0;
}
.requestBox, .panel {
  border: 1px solid rgba(148, 163, 184, 0.22);
  border-radius: 8px;
  background: #0d1f1b;
  padding: 22px;
}
.requestBox h2, .panel h2 {
  margin-bottom: 10px;
  color: #f8fafc;
}
.requestBox p {
  color: #b8c7c0;
  font-size: 14px;
}
.contactCard {
  margin-top: 18px;
  padding: 14px;
  border-radius: 8px;
  background: #07110f;
  border: 1px solid rgba(66, 245, 167, 0.24);
}
.contactCard span {
  display: block;
  color: #42f5a7;
  font-size: 12px;
  font-weight: 800;
  margin-bottom: 5px;
}
.contactCard strong {
  color: #e2e8f0;
  font-size: 14px;
}
.formGrid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  margin-top: 16px;
}
.formGrid label, .wideField {
  display: grid;
  gap: 6px;
}
.formGrid span, .wideField span {
  color: #9ff8cc;
  font-size: 12px;
  font-weight: 800;
}
.formGrid input, .wideField textarea {
  width: 100%;
  border: 1px solid rgba(148, 163, 184, 0.22);
  border-radius: 7px;
  background: #07110f;
  color: #e2e8f0;
  padding: 10px 11px;
  font: inherit;
  font-size: 13px;
}
.formGrid input:focus, .wideField textarea:focus {
  border-color: rgba(66, 245, 167, 0.65);
}
.passwordField {
  position: relative;
}
.passwordField input {
  padding-right: 44px;
}
.passwordField button {
  position: absolute;
  right: 9px;
  top: 50%;
  transform: translateY(-50%);
  width: 28px;
  height: 28px;
  border: none;
  background: transparent;
  color: #42f5a7;
  cursor: pointer;
  font-size: 18px;
}
.wideField {
  margin-top: 10px;
}
.wideField textarea {
  min-height: 78px;
  resize: vertical;
}
.subdomainPreview {
  padding: 10px 12px;
  border: 1px solid rgba(66, 245, 167, 0.24);
  border-radius: 8px;
  background: #07110f;
  color: #b8c7c0;
  font-size: 12px;
  min-height: 42px;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
}
.subdomainPreview strong {
  color: #42f5a7;
}
.formError, .formSuccess {
  margin-top: 12px;
  border-radius: 8px;
  padding: 11px 12px;
  font-size: 12px;
}
.formError {
  color: #fecaca;
  background: rgba(127, 29, 29, 0.34);
  border: 1px solid rgba(248, 113, 113, 0.34);
}
.formSuccess {
  display: grid;
  gap: 4px;
  color: #bbf7d0;
  background: rgba(6, 78, 59, 0.34);
  border: 1px solid rgba(52, 211, 153, 0.34);
  word-break: break-all;
}
.formSuccess strong {
  color: #86efac;
}
.submitBtn {
  width: 100%;
  min-height: 44px;
  margin-top: 12px;
  border: none;
  border-radius: 8px;
  background: #42f5a7;
  color: #03110d;
  font-weight: 900;
  cursor: pointer;
}
.submitBtn:disabled {
  opacity: 0.65;
  cursor: not-allowed;
}
.contentGrid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 16px;
  padding: 0 clamp(18px, 5vw, 64px) 64px;
}
.list, .steps {
  display: grid;
  gap: 10px;
}
.list div, .steps div {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  padding: 12px;
  border-radius: 8px;
  background: #07110f;
  border: 1px solid rgba(148, 163, 184, 0.14);
}
.list span, .steps b {
  width: 28px;
  height: 28px;
  flex: 0 0 28px;
  display: grid;
  place-items: center;
  border-radius: 7px;
  background: #42f5a7;
  color: #03110d;
  font-weight: 900;
}
.list p, .steps p {
  color: #cbd5e1;
  font-size: 14px;
}
.cta {
  text-align: center;
  padding: 54px clamp(18px, 5vw, 64px);
  background: #42f5a7;
  color: #03110d;
}
.cta h2 {
  font-size: clamp(28px, 4vw, 42px);
  margin-bottom: 8px;
}
.cta p {
  color: #174137;
  margin-bottom: 20px;
}
.dark {
  background: #03110d;
  color: #fff;
}
.ctaActions {
  display: flex;
  justify-content: center;
  gap: 12px;
  flex-wrap: wrap;
}
.darkOutline {
  border-color: rgba(3, 17, 13, 0.35);
  color: #03110d;
}
@media (max-width: 820px) {
  .partnerNav {
    align-items: flex-start;
    flex-direction: column;
    gap: 12px;
    padding-top: 14px;
    padding-bottom: 14px;
  }
  .partnerNav div {
    width: 100%;
    overflow-x: auto;
  }
  .hero {
    grid-template-columns: 1fr;
  }
  .formGrid {
    grid-template-columns: 1fr;
  }
}
`;
