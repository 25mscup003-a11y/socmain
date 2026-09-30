import { Link } from 'react-router-dom';

const monitoringItems = [
  {
    icon: '📊',
    title: 'System Monitoring',
    desc: 'Open live endpoint monitoring and system-level activity.',
    to: '/system-monitoring',
    color: '#34d399',
  },
  {
    icon: '🔔',
    title: 'Alerts',
    desc: 'Review security alerts, severity, status, and actions.',
    to: '/alerts',
    color: '#f87171',
  },
  {
    icon: '📡',
    title: 'SIEM',
    desc: 'Analyze centralized events, logs, and correlations.',
    to: '/siem',
    color: '#60a5fa',
  },
  {
    icon: '🛡',
    title: 'EDR',
    desc: 'Investigate endpoint activity, processes, users, and threats.',
    to: '/edr',
    color: '#a78bfa',
  },
  {
    icon: '🔍',
    title: 'IDS/IPS',
    desc: 'Monitor network detection and prevention events.',
    to: '/ids',
    color: '#f59e0b',
  },
  {
    icon: '🔥',
    title: 'Firewall',
    desc: 'Manage firewall rules, blocks, and network controls.',
    to: '/firewall',
    color: '#fb7185',
  },
  {
    icon: '📈',
    title: 'Log Monitor',
    desc: 'View log monitoring dashboards and operational signals.',
    to: '/log-monitor',
    color: '#38bdf8',
  },
  {
    icon: '📊',
    title: 'Security Score',
    desc: 'Track security posture, risk, and system health.',
    to: '/security-score',
    color: '#22c55e',
  },
  {
    icon: '🔎',
    title: 'Investigate',
    desc: 'Search and investigate threats across monitored systems.',
    to: '/investigate',
    color: '#c084fc',
  },
  {
    icon: '✅',
    title: 'Compliance',
    desc: 'Review compliance status and reporting evidence.',
    to: '/compliance',
    color: '#14b8a6',
  },
  {
    icon: '📄',
    title: 'Reports',
    desc: 'Open operational and security reports.',
    to: '/reports',
    color: '#94a3b8',
  },
];

export default function MonitoringPage() {
  return (
    <div>
      <div style={{ marginBottom:22 }}>
        <h2 style={{ fontSize:20, color:'#e0f2fe', margin:'0 0 6px' }}>Start Monitoring</h2>
        <div style={{ fontSize:12, color:'#60a5fa' }}>
          Open monitoring, alerting, log, and investigation tools from one place.
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(260px, 1fr))', gap:14 }}>
        {monitoringItems.map(item => (
          <Link
            key={item.to}
            to={item.to}
            style={{
              background:'linear-gradient(135deg, rgba(12,26,46,.95), rgba(8,18,34,.95))',
              border:`1px solid ${item.color}55`,
              borderRadius:12,
              padding:'18px 20px',
              textDecoration:'none',
              minHeight:132,
              display:'flex',
              flexDirection:'column',
              justifyContent:'space-between',
              boxShadow:`0 10px 24px ${item.color}10`,
            }}
          >
            <div>
              <div style={{
                width:44,
                height:44,
                borderRadius:10,
                background:`${item.color}18`,
                border:`1px solid ${item.color}44`,
                display:'flex',
                alignItems:'center',
                justifyContent:'center',
                fontSize:22,
                marginBottom:12,
              }}>{item.icon}</div>
              <div style={{ fontSize:16, fontWeight:700, color:'#e0f2fe', marginBottom:5 }}>
                {item.title}
              </div>
              <div style={{ fontSize:12, color:'#7dd3fc', lineHeight:1.45 }}>
                {item.desc}
              </div>
            </div>
            <div style={{ marginTop:14, fontSize:12, fontWeight:700, color:item.color }}>
              Open →
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
