import { Link } from 'react-router-dom';

const setupItems = [
  {
    icon: '🏢',
    title: 'Departments',
    desc: 'Create departments and assign system, phone, and server licenses.',
    to: '/departments',
    color: '#60a5fa',
  },
  {
    icon: '🖥',
    title: 'Systems',
    desc: 'Register endpoints and assign them to departments.',
    to: '/systems',
    color: '#38bdf8',
  },
  {
    icon: '⬇',
    title: 'Download Agent',
    desc: 'Download system, server, phone, and universal agent packages.',
    to: '/download-agent',
    color: '#a78bfa',
  },
  {
    icon: '🛡',
    title: 'EDR Setup',
    desc: 'Configure endpoint security controls, geolocation, and DNS Sinkhole policies.',
    to: '/edrsystemstupe',
    color: '#22d3ee',
  },
  {
    icon: '👥',
    title: 'Team',
    desc: 'Invite and manage team members for SOC operations.',
    to: '/team',
    color: '#34d399',
  },
  {
    icon: '💳',
    title: 'Payments',
    desc: 'Manage plan, license purchases, renewals, and upgrades.',
    to: '/payments',
    color: '#f59e0b',
  },
  {
    icon: '⚙',
    title: 'Settings',
    desc: 'Update company settings, profile, and dashboard preferences.',
    to: '/settings',
    color: '#94a3b8',
  },
];

export default function SystemSetupPage() {
  return (
    <div>
      <div style={{ marginBottom:22 }}>
        <h2 style={{ fontSize:20, color:'#e0f2fe', margin:'0 0 6px' }}>System Setup</h2>
        <div style={{ fontSize:12, color:'#60a5fa' }}>
          Setup departments, systems, agents, users, payments, and settings from one place.
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(260px, 1fr))', gap:14 }}>
        {setupItems.map(item => (
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
