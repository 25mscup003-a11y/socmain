import { Link } from 'react-router-dom';

const modules = [
  { title: 'SIEM Log Monitoring', text: 'Servers, endpoints, applications, and network devices ke logs collect, normalize, aur search karo.' },
  { title: 'EDR Endpoint Protection', text: 'Processes, suspicious activity, malware behavior, and endpoint health ko central dashboard se monitor karo.' },
  { title: 'IDS / IPS Visibility', text: 'Network threats, intrusion attempts, blocked IPs, and live security events ko track karo.' },
  { title: 'Firewall Control', text: 'Rules, blocked sources, allowlists, and policy changes ko SOC workflow ke saath manage karo.' },
  { title: 'Compliance Reports', text: 'SOC 2 style evidence, daily reports, controls, and audit summaries ko organized format mein rakho.' },
  { title: 'SOAR Automation', text: 'Alerts ko auto-triage, enrich, assign, and response actions se speed up karo.' },
];

const outcomes = [
  'Real-time alerts and incident tracking',
  'Company, department, analyst role management',
  'Agent download and system onboarding',
  'Threat investigation with evidence history',
  'Security score and risk overview',
  'Payments, plans, and subscription control',
];

export default function HomePage() {
  return (
    <div className="homePage">
      <style>{css}</style>

      <nav className="homeNav">
        <a className="brand" href="#home" aria-label="Spartan Cyber Defense Center (SCDC) home">
          <span className="brandMark">S</span>
          <span>Spartan Cyber Defense Center (SCDC)</span>
        </a>
        <div className="navLinks">
          <a href="#home">Home</a>
          <a href="#features">Features</a>
          <a href="#workflow">Workflow</a>
          <a href="#modules">Modules</a>
          <Link to="/partner-registration">Partner Registration</Link>
          <Link to="/login">Login</Link>
          <Link className="navCta" to="/register">Start</Link>
        </div>
      </nav>

      <main id="home">
        <section className="hero">
          <div className="heroCopy">
            <div className="eyebrow">Security Operations Platform</div>
            <h1>Spartan Cyber Defense Center (SCDC)</h1>
            <p>
              Ek centralized cyber security software jahan company apne systems, alerts, logs,
              EDR, IDS/IPS, firewall, compliance, reports, aur team operations ko ek jagah se
              manage kar sakti hai.
            </p>
            <div className="heroActions">
              <Link className="primaryBtn" to="/register">Create Company Account</Link>
              <Link className="secondaryBtn" to="/login">Open Dashboard</Link>
            </div>
          </div>

          <div className="productVisual" aria-label="SOC dashboard preview">
            <div className="screenTop">
              <span />
              <span />
              <span />
              <strong>Live SOC Console</strong>
            </div>
            <div className="screenGrid">
              <div className="statusPanel">
                <div className="panelLabel">Threat Level</div>
                <div className="threatValue">Medium</div>
                <div className="bar"><span style={{ width: '62%' }} /></div>
              </div>
              <div className="statusPanel">
                <div className="panelLabel">Protected Assets</div>
                <div className="bigNumber">248</div>
              </div>
              <div className="timeline">
                {['EDR alert enriched', 'Firewall rule synced', 'SOC 2 report generated', 'Analyst assigned'].map(item => (
                  <div key={item} className="timelineRow">
                    <span />
                    <p>{item}</p>
                  </div>
                ))}
              </div>
              <div className="signalMap">
                <i />
                <i />
                <i />
                <i />
              </div>
            </div>
          </div>
        </section>

        <section id="features" className="band">
          <div className="sectionTitle">
            <h2>Software Kya Kar Sakta Hai</h2>
            <p>Daily SOC operations ko simple, fast, aur measurable banane ke liye built-in tools.</p>
          </div>
          <div className="outcomeGrid">
            {outcomes.map(item => (
              <div key={item} className="outcome">
                <span>✓</span>
                <p>{item}</p>
              </div>
            ))}
          </div>
        </section>

        <section id="workflow" className="workflow">
          <div>
            <h2>From Alert To Action</h2>
            <p>
              Platform suspicious activity ko detect karta hai, context add karta hai, analyst ko
              assign karta hai, aur response actions ko track karta hai so nothing gets missed.
            </p>
          </div>
          <div className="steps">
            <div><b>1</b><span>Collect logs and endpoint signals</span></div>
            <div><b>2</b><span>Detect threats and correlate alerts</span></div>
            <div><b>3</b><span>Investigate, respond, and report</span></div>
          </div>
        </section>

        <section id="modules" className="band">
          <div className="sectionTitle">
            <h2>Core Security Modules</h2>
            <p>Company dashboard ke andar ye modules available hain.</p>
          </div>
          <div className="moduleGrid">
            {modules.map(module => (
              <article key={module.title} className="module">
                <h3>{module.title}</h3>
                <p>{module.text}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="ctaBand">
          <h2>Apni company ka SOC dashboard start karo</h2>
          <p>Register karo, plan select karo, agents install karo, aur monitoring begin karo.</p>
          <div>
            <Link className="primaryBtn" to="/register">Register Now</Link>
            <Link className="secondaryBtn light" to="/login">Login</Link>
          </div>
        </section>
      </main>
    </div>
  );
}

const css = `
.homePage {
  min-height: 100vh;
  background: #07110f;
  color: #eef8f3;
}
.homeNav {
  position: sticky;
  top: 0;
  z-index: 20;
  height: 68px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 clamp(18px, 5vw, 64px);
  background: rgba(7, 17, 15, 0.88);
  border-bottom: 1px solid rgba(148, 163, 184, 0.18);
  backdrop-filter: blur(14px);
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  color: #f8fafc;
  text-decoration: none;
  font-weight: 800;
  font-size: 17px;
}
.brandMark {
  width: 34px;
  height: 34px;
  border-radius: 8px;
  display: grid;
  place-items: center;
  color: #04100d;
  background: #42f5a7;
}
.navLinks {
  display: flex;
  align-items: center;
  gap: clamp(10px, 2vw, 22px);
}
.navLinks a {
  color: #b8c7c0;
  text-decoration: none;
  font-size: 13px;
  font-weight: 700;
}
.navLinks a:hover { color: #ffffff; }
.navCta {
  padding: 8px 13px;
  border-radius: 7px;
  background: #42f5a7;
  color: #03110d !important;
}
.hero {
  min-height: calc(100vh - 68px);
  display: grid;
  grid-template-columns: minmax(0, 0.92fr) minmax(340px, 1.08fr);
  align-items: center;
  gap: clamp(28px, 5vw, 64px);
  padding: clamp(34px, 6vw, 72px) clamp(18px, 5vw, 64px);
}
.eyebrow {
  color: #42f5a7;
  font-size: 12px;
  font-weight: 900;
  text-transform: uppercase;
  margin-bottom: 14px;
}
.hero h1 {
  font-size: clamp(48px, 8vw, 92px);
  line-height: 0.95;
  margin-bottom: 18px;
}
.hero p {
  max-width: 650px;
  color: #b8c7c0;
  font-size: clamp(16px, 2vw, 20px);
}
.heroActions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 26px;
}
.primaryBtn, .secondaryBtn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  padding: 0 18px;
  border-radius: 8px;
  text-decoration: none;
  font-weight: 800;
  font-size: 14px;
}
.primaryBtn {
  background: #42f5a7;
  color: #03110d;
}
.secondaryBtn {
  color: #e2e8f0;
  border: 1px solid rgba(226, 232, 240, 0.25);
}
.secondaryBtn.light { border-color: rgba(3, 17, 13, 0.22); color: #03110d; }
.productVisual {
  border: 1px solid rgba(148, 163, 184, 0.24);
  background: #0d1f1b;
  border-radius: 8px;
  box-shadow: 0 28px 90px rgba(0,0,0,0.34);
  overflow: hidden;
}
.screenTop {
  height: 44px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 0 14px;
  border-bottom: 1px solid rgba(148, 163, 184, 0.18);
  color: #7dd3fc;
  font-size: 12px;
}
.screenTop span {
  width: 9px;
  height: 9px;
  border-radius: 999px;
  background: #64748b;
}
.screenTop strong { margin-left: 8px; }
.screenGrid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  padding: 16px;
}
.statusPanel, .timeline, .signalMap {
  min-height: 120px;
  border-radius: 8px;
  background: #07110f;
  border: 1px solid rgba(148, 163, 184, 0.16);
  padding: 14px;
}
.panelLabel {
  color: #94a3b8;
  font-size: 12px;
  margin-bottom: 10px;
}
.threatValue, .bigNumber {
  color: #f8fafc;
  font-size: 32px;
  font-weight: 900;
}
.bar {
  height: 8px;
  margin-top: 18px;
  border-radius: 999px;
  background: #1f2937;
  overflow: hidden;
}
.bar span {
  display: block;
  height: 100%;
  background: #facc15;
}
.timeline { grid-column: span 1; }
.timelineRow {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 7px 0;
  color: #cbd5e1;
  font-size: 12px;
}
.timelineRow span {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: #42f5a7;
}
.signalMap {
  position: relative;
  min-height: 170px;
  background:
    linear-gradient(rgba(66,245,167,.08) 1px, transparent 1px),
    linear-gradient(90deg, rgba(66,245,167,.08) 1px, transparent 1px),
    #07110f;
  background-size: 28px 28px;
}
.signalMap i {
  position: absolute;
  width: 13px;
  height: 13px;
  border-radius: 999px;
  background: #38bdf8;
  box-shadow: 0 0 0 8px rgba(56, 189, 248, 0.12);
}
.signalMap i:nth-child(1) { left: 18%; top: 28%; }
.signalMap i:nth-child(2) { left: 62%; top: 22%; background:#42f5a7; }
.signalMap i:nth-child(3) { left: 42%; top: 64%; background:#facc15; }
.signalMap i:nth-child(4) { left: 76%; top: 72%; background:#fb7185; }
.band, .workflow, .ctaBand {
  padding: 64px clamp(18px, 5vw, 64px);
}
.band { background: #f8fafc; color: #0f172a; }
.sectionTitle {
  max-width: 720px;
  margin-bottom: 26px;
}
.sectionTitle h2, .workflow h2, .ctaBand h2 {
  font-size: clamp(28px, 4vw, 44px);
  line-height: 1.05;
  margin-bottom: 10px;
}
.sectionTitle p, .workflow p, .ctaBand p {
  color: #52615d;
  font-size: 16px;
}
.outcomeGrid, .moduleGrid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
  gap: 12px;
}
.outcome, .module {
  border: 1px solid #dbe4df;
  border-radius: 8px;
  padding: 16px;
  background: #ffffff;
}
.outcome {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  font-weight: 700;
}
.outcome span {
  color: #047857;
  font-weight: 900;
}
.workflow {
  display: grid;
  grid-template-columns: minmax(0, .85fr) minmax(300px, 1.15fr);
  gap: 34px;
  align-items: center;
  background: #10231f;
}
.workflow p { color: #b8c7c0; }
.steps {
  display: grid;
  gap: 12px;
}
.steps div {
  display: flex;
  align-items: center;
  gap: 14px;
  background: #07110f;
  border: 1px solid rgba(148, 163, 184, 0.18);
  border-radius: 8px;
  padding: 16px;
}
.steps b {
  width: 34px;
  height: 34px;
  border-radius: 8px;
  display: grid;
  place-items: center;
  background: #42f5a7;
  color: #03110d;
}
.module h3 {
  font-size: 17px;
  margin-bottom: 8px;
}
.module p {
  color: #52615d;
  font-size: 14px;
}
.ctaBand {
  text-align: center;
  background: #42f5a7;
  color: #03110d;
}
.ctaBand p {
  color: #174137;
  margin-bottom: 22px;
}
.ctaBand div {
  display: flex;
  justify-content: center;
  gap: 12px;
  flex-wrap: wrap;
}
.ctaBand .primaryBtn {
  background: #03110d;
  color: #ffffff;
}
@media (max-width: 860px) {
  .homeNav { height: auto; min-height: 68px; align-items: flex-start; padding-top: 14px; padding-bottom: 14px; gap: 12px; flex-direction: column; }
  .navLinks { width: 100%; overflow-x: auto; padding-bottom: 2px; }
  .hero, .workflow { grid-template-columns: 1fr; }
  .hero { min-height: auto; }
  .screenGrid { grid-template-columns: 1fr; }
}
`;
