import { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import api from '../api/axios';
import CompanyDetail from './CompanyDetail';

export default function CompaniesPage() {
  const location = useLocation();
  const isPartnerOnly = location.pathname.includes('partner-company') ||
    location.pathname.includes('partnercompany') ||
    location.pathname.includes('partnercompanies') ||
    location.search.includes('filter=partner');

  const [companies, setCompanies] = useState([]);
  const [partners, setPartners] = useState([]);
  const [selectedPartnerId, setSelectedPartnerId] = useState('');
  const [selectedCompanyId, setSelectedCompanyId] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [impersonatingId, setImpersonatingId] = useState('');

  const handleLoginAsCompanyAdmin = async (e, companyId) => {
    e.stopPropagation();
    // Synchronously open blank tab before async request so browser popup blocker does not block it
    const newWindow = window.open('about:blank', '_blank');
    try {
      setImpersonatingId(companyId);
      const { data } = await api.post(`/superadmin/companies/${companyId}/impersonate`);
      const targetUrl = data.redirectUrl || `http://localhost:3000/?impersonationToken=${data.token}`;
      if (newWindow) {
        newWindow.location.href = targetUrl;
      } else {
        window.location.href = targetUrl;
      }
    } catch (err) {
      if (newWindow) newWindow.close();
      console.error('Error logging in as company admin:', err);
      alert(err.response?.data?.message || 'Failed to login as company admin');
    } finally {
      setImpersonatingId('');
    }
  };

  // 1. Filter out partner vs direct companies based on URL route
  const isPartnerComp = (c) => Boolean(c.partnerId || c.tenantId?.type === 'partner' || c.source === 'partner_referral');
  const filteredCompanies = companies.filter(c => isPartnerOnly ? isPartnerComp(c) : !isPartnerComp(c));

  // 2. Filter companies by selected partner
  const partnerCompanies = isPartnerOnly
    ? filteredCompanies.filter(c => {
      if (!selectedPartnerId) return true;
      const pId = c.partnerId?._id || c.partnerId || c.tenantId?._id;
      return String(pId) === String(selectedPartnerId);
    })
    : filteredCompanies;

  // 3. Search and Status Filtering
  const displayedCompanies = partnerCompanies.filter(c => {
    const matchesSearch = !searchQuery ||
      c.name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      c.email?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (c.plan?.type && c.plan.type.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesStatus = statusFilter === 'all' ||
      (statusFilter === 'active' && c.status === 'active') ||
      (statusFilter === 'suspended' && c.status === 'suspended') ||
      (statusFilter === 'pending' && (c.status === 'pending_payment' || c.status === 'trial'));

    return matchesSearch && matchesStatus;
  });

  const loadData = () => {
    setLoading(true);
    Promise.all([
      api.get('/superadmin/companies'),
      api.get('/superadmin/partners')
    ]).then(([compRes, partRes]) => {
      const compList = compRes.data || [];
      const partList = partRes.data || [];
      setCompanies(compList);
      setPartners(partList);

      // Check if URL specifies a partnerId or companyId query param
      const params = new URLSearchParams(location.search);
      const queryPartnerId = params.get('partnerId');
      const queryCompanyId = params.get('companyId');

      if (queryPartnerId && partList.some(p => p._id === queryPartnerId)) {
        setSelectedPartnerId(queryPartnerId);
      }
      if (queryCompanyId && compList.some(c => c._id === queryCompanyId)) {
        setSelectedCompanyId(queryCompanyId);
      }
    }).catch(err => {
      console.error('Error fetching data:', err);
    }).finally(() => {
      setLoading(false);
    });
  };

  useEffect(() => {
    loadData();
  }, [isPartnerOnly, location.search]);

  const handlePartnerChange = (partnerId) => {
    setSelectedPartnerId(partnerId);
  };

  // Helper for status badge styling
  const getStatusBadge = (status) => {
    switch (status) {
      case 'active':
        return { bg: 'rgba(16, 185, 129, 0.15)', text: '#34d399', border: 'rgba(16, 185, 129, 0.4)', label: 'ACTIVE', dot: '#10b981' };
      case 'suspended':
        return { bg: 'rgba(239, 68, 68, 0.15)', text: '#f87171', border: 'rgba(239, 68, 68, 0.4)', label: 'SUSPENDED', dot: '#ef4444' };
      case 'trial':
        return { bg: 'rgba(59, 130, 246, 0.15)', text: '#60a5fa', border: 'rgba(59, 130, 246, 0.4)', label: 'TRIAL', dot: '#3b82f6' };
      default:
        return { bg: 'rgba(245, 158, 11, 0.15)', text: '#fbbf24', border: 'rgba(245, 158, 11, 0.4)', label: 'PENDING', dot: '#f59e0b' };
    }
  };

  // Helper for generating avatar initials
  const getInitials = (name) => {
    if (!name) return 'CO';
    const parts = name.trim().split(' ');
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return name.substring(0, 2).toUpperCase();
  };

  // Calculate high level KPI totals
  const totalCompaniesCount = partnerCompanies.length;
  const activeCount = partnerCompanies.filter(c => c.status === 'active').length;
  const suspendedCount = partnerCompanies.filter(c => c.status === 'suspended').length;
  const totalCapacity = partnerCompanies.reduce((acc, c) => acc + (c.plan?.systemCount || c.plan?.systemLimit || 0), 0);

  return (
    <div style={{ paddingBottom: 40 }}>
      {/* ── TOP CONTROL HEADER ── */}
      <div style={{
        padding: '20px 24px',
        background: 'linear-gradient(135deg, #09172a 0%, #040b14 100%)',
        border: '1px solid #1e3a5f',
        borderRadius: 16,
        marginBottom: 24,
        boxShadow: '0 10px 35px rgba(0,0,0,0.4)',
        display: 'flex',
        flexDirection: 'column',
        gap: 18
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h2 style={{ fontSize: 22, color: '#f8fafc', margin: 0, fontWeight: 900, letterSpacing: '-0.5px' }}>
                🏢 {isPartnerOnly ? 'Partner Companies Directory' : 'Superadmin Companies Directory'}
              </h2>
              <span style={{
                background: 'rgba(56, 189, 248, 0.12)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                padding: '3px 10px',
                borderRadius: 20,
                fontSize: 11,
                fontWeight: 800
              }}>
                {displayedCompanies.length} {displayedCompanies.length === 1 ? 'Company' : 'Companies'}
              </span>
            </div>
            <p style={{ fontSize: 12, color: '#64748b', margin: '4px 0 0 0' }}>
              {isPartnerOnly
                ? 'Manage partner-assigned tenant companies. Use the dashboard button when you want to open a company summary.'
                : 'Manage direct companies under Main Superadmin. Use the dashboard button when you want to open a company summary.'}
            </p>
          </div>

          {/* Quick toggle if viewing a company dashboard */}
          {selectedCompanyId && (
            <button
              onClick={() => setSelectedCompanyId('')}
              style={{
                padding: '10px 18px',
                borderRadius: 10,
                background: 'linear-gradient(135deg, #2563eb, #1d4ed8)',
                color: '#ffffff',
                border: '1px solid #60a5fa',
                fontWeight: 800,
                fontSize: 13,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                boxShadow: '0 4px 14px rgba(37, 99, 235, 0.4)'
              }}
            >
              ← Back to Company Cards Grid
            </button>
          )}
        </div>

        {/* Top KPI Metrics Row (Only shown when browsing cards) */}
        {!selectedCompanyId && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 14 }}>
            <div style={{ background: 'rgba(15, 23, 42, 0.6)', border: '1px solid #1e293b', borderRadius: 12, padding: '12px 16px' }}>
              <div style={{ fontSize: 10, color: '#94a3b8', fontWeight: 800, textTransform: 'uppercase' }}>Total Companies</div>
              <div style={{ fontSize: 22, color: '#f8fafc', fontWeight: 900, marginTop: 4 }}>{totalCompaniesCount}</div>
            </div>
            <div style={{ background: 'rgba(16, 185, 129, 0.08)', border: '1px solid rgba(16, 185, 129, 0.25)', borderRadius: 12, padding: '12px 16px' }}>
              <div style={{ fontSize: 10, color: '#34d399', fontWeight: 800, textTransform: 'uppercase' }}>Active Tenants</div>
              <div style={{ fontSize: 22, color: '#34d399', fontWeight: 900, marginTop: 4 }}>{activeCount}</div>
            </div>
            <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)', borderRadius: 12, padding: '12px 16px' }}>
              <div style={{ fontSize: 10, color: '#f87171', fontWeight: 800, textTransform: 'uppercase' }}>Suspended</div>
              <div style={{ fontSize: 22, color: '#f87171', fontWeight: 900, marginTop: 4 }}>{suspendedCount}</div>
            </div>
            <div style={{ background: 'rgba(167, 139, 250, 0.08)', border: '1px solid rgba(167, 139, 250, 0.25)', borderRadius: 12, padding: '12px 16px' }}>
              <div style={{ fontSize: 10, color: '#a78bfa', fontWeight: 800, textTransform: 'uppercase' }}>Endpoint Capacity</div>
              <div style={{ fontSize: 22, color: '#c4b5fd', fontWeight: 900, marginTop: 4 }}>{totalCapacity.toLocaleString()} <span style={{ fontSize: 11, fontWeight: 500 }}>Systems</span></div>
            </div>
          </div>
        )}

        {/* Filter Controls Row */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 14, flexWrap: 'wrap', borderTop: '1px solid #1e293b', paddingTop: 16 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', flex: 1, minWidth: 280 }}>
            {/* Search Box */}
            <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
              <input
                type="text"
                placeholder="🔍 Search company name, email, plan..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  width: '100%',
                  padding: '9px 14px 9px 36px',
                  borderRadius: 10,
                  background: '#07111f',
                  border: '1px solid #1e3a5f',
                  color: '#f1f5f9',
                  fontSize: 13,
                  outline: 'none',
                  boxSizing: 'border-box'
                }}
              />
              <span style={{ position: 'absolute', left: 12, top: 10, color: '#64748b', fontSize: 14 }}>🔍</span>
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  style={{ position: 'absolute', right: 10, top: 8, background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: 14 }}
                >
                  ✕
                </button>
              )}
            </div>

            {/* Status Filter Buttons */}
            <div style={{ display: 'flex', background: '#07111f', border: '1px solid #1e3a5f', borderRadius: 10, padding: 3 }}>
              {[
                { id: 'all', label: 'All' },
                { id: 'active', label: '🟢 Active' },
                { id: 'suspended', label: '🔴 Suspended' },
                { id: 'pending', label: '🟡 Pending' },
              ].map(f => (
                <button
                  key={f.id}
                  onClick={() => setStatusFilter(f.id)}
                  style={{
                    padding: '6px 12px',
                    borderRadius: 8,
                    border: 'none',
                    background: statusFilter === f.id ? '#1e3a5f' : 'transparent',
                    color: statusFilter === f.id ? '#38bdf8' : '#94a3b8',
                    fontSize: 12,
                    fontWeight: statusFilter === f.id ? 800 : 500,
                    cursor: 'pointer',
                    transition: 'all 0.15s'
                  }}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            {isPartnerOnly && partners.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <label style={{ fontSize: 12, color: '#a78bfa', fontWeight: 800, whiteSpace: 'nowrap' }}>
                  🤝 Partner:
                </label>
                <select
                  value={selectedPartnerId}
                  onChange={e => handlePartnerChange(e.target.value)}
                  style={{
                    padding: '8px 12px', borderRadius: 8, background: '#07111f',
                    border: '1px solid #a78bfa', color: '#f1f5f9', fontSize: 12,
                    fontWeight: 700, cursor: 'pointer', outline: 'none'
                  }}
                >
                  <option value="">All Partners ({partners.length})</option>
                  {partners.map(p => (
                    <option key={p._id} value={p._id}>
                      {p.name || p.companyName || p.email}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Quick Switch Dropdown */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <label style={{ fontSize: 12, color: '#38bdf8', fontWeight: 800, whiteSpace: 'nowrap' }}>
                🏢 Select Company:
              </label>
              <select
                value={selectedCompanyId}
                onChange={e => setSelectedCompanyId(e.target.value)}
                style={{
                  padding: '8px 12px', borderRadius: 8, background: '#07111f',
                  border: '1px solid #38bdf8', color: '#f1f5f9', fontSize: 12,
                  fontWeight: 700, cursor: 'pointer', outline: 'none', maxWidth: 220
                }}
              >
                <option value="">-- Browse Cards List --</option>
                {partnerCompanies.map(c => (
                  <option key={c._id} value={c._id}>
                    {c.name} ({c.status})
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* ── CONTENT BODY ── */}
      {loading ? (
        <div style={{ padding: 60, textAlign: 'center', color: '#38bdf8', fontWeight: 800 }}>
          <div style={{ fontSize: 24, marginBottom: 12 }}>⚡</div>
          Loading telemetry and company profiles...
        </div>
      ) : selectedCompanyId ? (
        /* ── SELECTED COMPANY DETAILED SUMMARY DASHBOARD ── */
        <div style={{ border: '1px solid #1e3a5f', borderRadius: 16, background: '#07111f', overflow: 'hidden', boxShadow: '0 12px 40px rgba(0,0,0,0.5)' }}>
          {/* Dashboard Header Bar with Back Button */}
          <div style={{
            padding: '12px 20px',
            background: 'linear-gradient(90deg, #0b192e, #07111f)',
            borderBottom: '1px solid #1e2d45',
            display: 'flex',
            justify: 'space-between',
            alignItems: 'center'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <button
                onClick={() => setSelectedCompanyId('')}
                style={{
                  background: '#1e293b',
                  border: '1px solid #334155',
                  color: '#94a3b8',
                  padding: '6px 12px',
                  borderRadius: 8,
                  fontSize: 12,
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                ← All Cards
              </button>
              <span style={{ color: '#475569' }}>|</span>
              <span style={{ color: '#38bdf8', fontSize: 13, fontWeight: 800 }}>
                Viewing Summary Dashboard for: <strong style={{ color: '#ffffff' }}>{companies.find(c => c._id === selectedCompanyId)?.name || 'Selected Company'}</strong>
              </span>
            </div>

            <div style={{ fontSize: 11, color: '#64748b' }}>
              Real-Time Security & Telemetry Center
            </div>
          </div>

          <CompanyDetail
            key={selectedCompanyId}
            companyIdOverride={selectedCompanyId}
            initialCompanyData={companies.find(c => c._id === selectedCompanyId)}
            hideBackButton={true}
          />
        </div>
      ) : (
        /* ── COMPANY CARDS GRID VIEW ── */
        <div>
          {displayedCompanies.length === 0 ? (
            <div style={{
              padding: 50, textAlign: 'center', color: '#f87171', background: '#07111f',
              border: '1px solid #ef444433', borderRadius: 16, fontWeight: 700
            }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>🏢</div>
              No companies match your filters or search criteria.
            </div>
          ) : (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(330px, 1fr))',
              gap: 20
            }}>
              {displayedCompanies.map(company => {
                const statusBadge = getStatusBadge(company.status);
                const planType = (company.plan?.type || 'CUSTOM').toUpperCase();
                const systemLimit = company.plan?.systemCount || company.plan?.systemLimit || 0;
                const partnerName = company.partnerId?.name || company.tenantId?.name;

                return (
                  <div
                    key={company._id}
                    style={{
                      background: 'linear-gradient(145deg, #091729 0%, #050e1a 100%)',
                      border: `1px solid ${statusBadge.border}`,
                      borderRadius: 16,
                      padding: 20,
                      boxShadow: '0 10px 30px rgba(0,0,0,0.3)',
                      cursor: 'default',
                      transition: 'all 0.2s ease-in-out',
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      position: 'relative',
                      overflow: 'hidden'
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.boxShadow = '0 14px 34px rgba(0,0,0,0.4)';
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.boxShadow = '0 10px 30px rgba(0,0,0,0.3)';
                    }}
                  >
                    {/* Top Glow Accent Bar */}
                    <div style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      right: 0,
                      height: 4,
                      background: `linear-gradient(90deg, ${statusBadge.dot}, ${company.status === 'active' ? '#38bdf8' : '#818cf8'})`
                    }} />

                    <div>
                      {/* Card Header: Avatar, Name & Status */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, marginBottom: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <div style={{
                            width: 44,
                            height: 44,
                            borderRadius: 12,
                            background: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)',
                            border: '1px solid #334155',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: '#38bdf8',
                            fontWeight: 900,
                            fontSize: 16,
                            boxShadow: '0 4px 12px rgba(0,0,0,0.3)'
                          }}>
                            {getInitials(company.name)}
                          </div>
                          <div>
                            <h3 style={{ fontSize: 16, color: '#f8fafc', margin: '0 0 2px 0', fontWeight: 800, lineHeight: 1.2 }}>
                              {company.name}
                            </h3>
                            <div style={{ fontSize: 11, color: '#64748b', display: 'flex', alignItems: 'center', gap: 4 }}>
                              <span>✉️</span> {company.email}
                            </div>
                          </div>
                        </div>

                        {/* Status Badge */}
                        <span style={{
                          background: statusBadge.bg,
                          color: statusBadge.text,
                          border: `1px solid ${statusBadge.border}`,
                          padding: '3px 9px',
                          borderRadius: 20,
                          fontSize: 10,
                          fontWeight: 800,
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 5,
                          whiteSpace: 'nowrap'
                        }}>
                          <span style={{
                            width: 6,
                            height: 6,
                            borderRadius: '50%',
                            background: statusBadge.dot,
                            boxShadow: `0 0 8px ${statusBadge.dot}`
                          }} />
                          {statusBadge.label}
                        </span>
                      </div>

                      {/* Card Grid Details */}
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: '1fr 1fr',
                        gap: 10,
                        padding: 12,
                        borderRadius: 12,
                        background: 'rgba(7, 17, 31, 0.7)',
                        border: '1px solid #1e293b',
                        marginBottom: 16
                      }}>
                        <div>
                          <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Plan Tier</div>
                          <div style={{ fontSize: 12, color: '#c4b5fd', fontWeight: 800, marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                            💳 {planType}
                          </div>
                        </div>

                        <div>
                          <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Endpoint Capacity</div>
                          <div style={{ fontSize: 12, color: '#38bdf8', fontWeight: 800, marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                            🖥️ {systemLimit} Systems
                          </div>
                        </div>

                        <div>
                          <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Account Source</div>
                          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 700, marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {partnerName ? `🤝 ${partnerName}` : '🛡️ Direct Main'}
                          </div>
                        </div>

                        <div>
                          <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Registered Date</div>
                          <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 700, marginTop: 2 }}>
                            📅 {company.createdAt ? new Date(company.createdAt).toLocaleDateString() : '—'}
                          </div>
                        </div>
                      </div>

                      {/* Health / Risk Score Bar */}
                      <div style={{ marginBottom: 16 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#94a3b8', fontWeight: 700, marginBottom: 4 }}>
                          <span>Security Health Score</span>
                          <span style={{ color: company.status === 'active' ? '#34d399' : '#f87171' }}>
                            {company.status === 'active' ? '98% Posture' : 'Action Required'}
                          </span>
                        </div>
                        <div style={{ width: '100%', height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{
                            width: company.status === 'active' ? '98%' : '40%',
                            height: '100%',
                            background: company.status === 'active' ? 'linear-gradient(90deg, #10b981, #38bdf8)' : '#ef4444',
                            borderRadius: 3
                          }} />
                        </div>
                      </div>
                    </div>

                    {/* Card Footer Buttons */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
                      <button
                        onClick={(e) => handleLoginAsCompanyAdmin(e, company._id)}
                        disabled={impersonatingId === company._id}
                        style={{
                          width: '100%',
                          padding: '10px 14px',
                          borderRadius: 10,
                          background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                          border: '1px solid #34d399',
                          color: '#ffffff',
                          fontWeight: 800,
                          fontSize: 12,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          gap: 6,
                          boxShadow: '0 4px 12px rgba(16, 185, 129, 0.3)',
                          transition: 'all 0.2s',
                          opacity: impersonatingId === company._id ? 0.7 : 1
                        }}
                      >
                        {impersonatingId === company._id ? '🔑 Logging in...' : '🔑 Login as Company Admin'}
                      </button>

                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedCompanyId(company._id);
                        }}
                        style={{
                          width: '100%',
                          padding: '9px 14px',
                          borderRadius: 10,
                          background: 'rgba(37, 99, 235, 0.15)',
                          border: '1px solid rgba(56, 189, 248, 0.4)',
                          color: '#38bdf8',
                          fontWeight: 800,
                          fontSize: 12,
                          cursor: 'pointer',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          gap: 6,
                          transition: 'all 0.2s'
                        }}
                      >
                        Open Summary Dashboard →
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
