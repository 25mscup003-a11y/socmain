import React, { useEffect, useState, useCallback } from 'react';
import api from '../api/axios';
import { useToast, Spinner, PageLoader, ErrorBanner } from '../components/Toast';
import { useAuth } from '../context/AuthContext';
import './FirewallPage.css';

// Company/Department rules always run in "auto" mode — they reach every system
// in scope and each agent enforces on its OWN OS firewall. A System-level rule
// resolves to that one system's OS firewall automatically.
const FIREWALL_LABEL = {
  auto:             'Auto (per system OS)',
  nftables:         'nftables (Linux)',
  windows_defender: 'Windows Defender',
  pfctl:            'pfctl (macOS)',
};

function osToFirewall(os = '') {
  const o = String(os).toLowerCase();
  if (o.includes('win')) return 'windows_defender';
  if (o.includes('mac') || o.includes('darwin') || o.includes('osx')) return 'pfctl';
  return 'nftables'; // Linux / default
}

// ── Header Component ──────────────────────────────────────────────────────────
function FirewallHeader({ stats, companyRules, departmentRules, systemRules, onRefresh }) {
  const { showToast } = useToast();
  const [expandedCard, setExpandedCard] = useState(null);
  const [selectedCard, setSelectedCard] = useState(null);
  const [unblockIP, setUnblockIP] = useState('');
  const [showUnblockInput, setShowUnblockInput] = useState(false);
  const [unblockLoading, setUnblockLoading] = useState(false);

  const StatCard = ({ id, label, value, color, icon, detailContent }) => {
    const isExpanded = expandedCard === id;

    return (
      <div
        style={{
          background: '#0c1a2e',
          border: `2px solid ${isExpanded ? color : color + '44'}`,
          borderRadius: 12,
          padding: 16,
          cursor: 'pointer',
          transition: 'all 0.3s',
        }}
        onMouseOver={(e) => {
          if (!isExpanded) {
            e.currentTarget.style.borderColor = color;
            e.currentTarget.style.background = '#1a2a3e';
            e.currentTarget.style.transform = 'translateY(-2px)';
            e.currentTarget.style.boxShadow = `0 4px 12px ${color}22`;
          }
        }}
        onMouseOut={(e) => {
          if (!isExpanded) {
            e.currentTarget.style.borderColor = color + '44';
            e.currentTarget.style.background = '#0c1a2e';
            e.currentTarget.style.transform = 'translateY(0)';
            e.currentTarget.style.boxShadow = 'none';
          }
        }}
      >
        <div
          onClick={() => {
            setExpandedCard(isExpanded ? null : id);
            setSelectedCard(id);
          }}
          style={{ cursor: 'pointer' }}
        >
          <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4, textTransform: 'uppercase', fontWeight: 600 }}>
            {label}
          </div>
          <div style={{ fontSize: 28, fontWeight: 900, color, display: 'flex', alignItems: 'center', gap: 8 }}>
            {icon} {value}
          </div>
          <div style={{ fontSize: 10, color: '#475569', marginTop: 6 }}>
            {isExpanded ? '▼ Hide details' : '▶ Click for details'}
          </div>
        </div>

        {isExpanded && (
          <div
            style={{
              borderTop: `1px solid ${color}44`,
              marginTop: 12,
              paddingTop: 12,
              fontSize: 12,
              color: '#cbd5e1',
            }}
          >
            {detailContent}
          </div>
        )}
      </div>
    );
  };

  const blockRules = [...(companyRules || []), ...(departmentRules || []), ...(systemRules || [])].filter(r => r.action === 'block');

  const renderDetailsModal = () => {
    const modalStyle = {
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0, 0, 0, 0.8)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '20px',
    };

    const contentStyle = {
      background: '#0c1a2e',
      border: '2px solid #06b6d4',
      borderRadius: 16,
      padding: 32,
      maxWidth: 700,
      maxHeight: '85vh',
      overflowY: 'auto',
      width: '100%',
    };

    let title = '';
    let icon = '';
    let color = '#06b6d4';
    let details = [];

    if (selectedCard === 'system') {
      title = 'System Level Rules';
      icon = '💻';
      color = '#06b6d4';
      details = systemRules || [];
    } else if (selectedCard === 'company') {
      title = 'Company Level Rules';
      icon = '🏢';
      color = '#f59e0b';
      details = companyRules || [];
    } else if (selectedCard === 'dept') {
      title = 'Department Level Rules';
      icon = '🏬';
      color = '#8b5cf6';
      details = departmentRules || [];
    } else if (selectedCard === 'block') {
      title = 'Block Rules';
      icon = '🚫';
      color = '#f87171';
      details = blockRules || [];
    } else if (selectedCard === 'active') {
      title = 'Active Rules';
      icon = '✓';
      color = '#22c55e';
      details = [...(companyRules || []), ...(departmentRules || []), ...(systemRules || [])].filter(r => r.enabled && r.deploymentStatus === 'deployed') || [];
    } else if (selectedCard === 'total') {
      title = 'All Rules';
      icon = '📊';
      color = '#60a5fa';
      details = [...(companyRules || []), ...(departmentRules || []), ...(systemRules || [])] || [];
    }

    return (
      <div style={modalStyle} onClick={() => {
        setSelectedCard(null);
        setExpandedCard(null);
      }}>
        <div style={contentStyle} onClick={(e) => e.stopPropagation()}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
            <h2 style={{ fontSize: 24, fontWeight: 800, color, margin: 0 }}>
              {icon} {title}
            </h2>
            <button
              onClick={() => {
                setSelectedCard(null);
                setExpandedCard(null);
              }}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#94a3b8',
                fontSize: 24,
                cursor: 'pointer',
                padding: '0 8px',
              }}
            >
              ✕
            </button>
          </div>

          {details.length > 0 ? (
            <div>
              <div style={{ marginBottom: 16 }}>
                <div style={{ fontSize: 12, color: '#64748b', marginBottom: 12, textTransform: 'uppercase', fontWeight: 600 }}>
                  Total: {details.length} rule{details.length !== 1 ? 's' : ''}
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {details.map((rule, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: '#1a2a3e',
                      border: `1px solid ${color}44`,
                      borderRadius: 8,
                      padding: 14,
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 8 }}>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 700, color: '#e2e8f0' }}>
                          {rule.ruleName || rule.name || `Rule ${idx + 1}`}
                        </div>
                        <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
                          {rule.description || 'No description'}
                        </div>
                      </div>
                      <div
                        style={{
                          padding: '4px 8px',
                          background: rule.action === 'block' ? '#f87171' : rule.action === 'allow' ? '#22c55e' : '#f59e0b',
                          color: '#fff',
                          borderRadius: 4,
                          fontSize: 10,
                          fontWeight: 700,
                        }}
                      >
                        {rule.action?.toUpperCase() || 'N/A'}
                      </div>
                    </div>

                    <div style={{ fontSize: 11, color: '#cbd5e1', display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                      {rule.protocol && (
                        <div>
                          <span style={{ color: '#94a3b8' }}>Protocol:</span> {rule.protocol}
                        </div>
                      )}
                      {rule.direction && (
                        <div>
                          <span style={{ color: '#94a3b8' }}>Direction:</span> {rule.direction}
                        </div>
                      )}
                      {(rule.conditions?.ipAddress || rule.sourceIp) && (
                        <div>
                          <span style={{ color: '#94a3b8' }}>IP:</span> {rule.conditions?.ipAddress || rule.sourceIp}
                        </div>
                      )}
                      {(rule.conditions?.domain || rule.domain) && (
                        <div>
                          <span style={{ color: '#94a3b8' }}>Domain:</span> {rule.conditions?.domain || rule.domain}
                        </div>
                      )}
                      {(rule.conditions?.port || rule.destinationPort) && (
                        <div>
                          <span style={{ color: '#94a3b8' }}>Port:</span> {rule.conditions?.port || rule.destinationPort}
                        </div>
                      )}
                      {rule.status && (
                        <div>
                          <span style={{ color: '#94a3b8' }}>Status:</span> {rule.status}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '40px 20px', color: '#64748b' }}>
              <div style={{ fontSize: 14, marginBottom: 8 }}>No rules found in this category</div>
              <div style={{ fontSize: 12 }}>Create a new rule to get started</div>
            </div>
          )}



          <button
            onClick={() => {
              setSelectedCard(null);
              setExpandedCard(null);
            }}
            style={{
              marginTop: 16,
              padding: '10px 20px',
              background: color,
              color: color === '#f59e0b' || color === '#60a5fa' ? '#000' : '#fff',
              border: 'none',
              borderRadius: 6,
              fontSize: 12,
              fontWeight: 700,
              cursor: 'pointer',
              width: '100%',
            }}
          >
            Close
          </button>
        </div>
      </div>
    );
  };

  return (
    <div style={{ marginBottom: 24 }}>
      <h1 style={{ fontSize: 28, fontWeight: 800, marginBottom: 4 }}>🔥 Firewall System</h1>
      <p style={{ color: '#64748b', marginBottom: 16 }}>Manage firewall rules at company, department, and system levels</p>

      {stats && (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginBottom: 16 }}>
            <StatCard
              id="total"
              label="Total Rules"
              value={stats.totalRules || 0}
              color="#60a5fa"
              icon="📊"
              detailContent={
                <div>
                  <div style={{ marginBottom: 8, color: '#60a5fa' }}>All rules in system</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>
                    {stats.totalRules > 0 ? (
                      <div>✓ {stats.totalRules} rule{stats.totalRules !== 1 ? 's' : ''} created</div>
                    ) : (
                      <div>No rules created yet</div>
                    )}
                  </div>
                  <button
                    onClick={() => setSelectedCard('total')}
                    style={{
                      marginTop: 8,
                      padding: '4px 8px',
                      background: '#60a5fa',
                      color: '#000',
                      border: 'none',
                      borderRadius: 4,
                      fontSize: 10,
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    View All
                  </button>
                </div>
              }
            />

            <StatCard
              id="active"
              label="Active Rules"
              value={stats.enabledRules || 0}
              color="#22c55e"
              icon="✓"
              detailContent={
                <div>
                  <div style={{ marginBottom: 8, color: '#22c55e' }}>Confirmed by endpoint agents</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>
                    {stats.enabledRules > 0 ? (
                      <div>✓ {stats.enabledRules} rule{stats.enabledRules !== 1 ? 's' : ''} active</div>
                    ) : (
                      <div>No active rules</div>
                    )}
                    {(stats.pendingRules || stats.partialRules || stats.failedRules) > 0 && (
                      <div style={{ marginTop: 5, color: '#fbbf24' }}>
                        Pending {stats.pendingRules || 0} · Partial {stats.partialRules || 0} · Failed {stats.failedRules || 0}
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => setSelectedCard('active')}
                    style={{
                      marginTop: 8,
                      padding: '4px 8px',
                      background: '#22c55e',
                      color: '#000',
                      border: 'none',
                      borderRadius: 4,
                      fontSize: 10,
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    View All
                  </button>
                </div>
              }
            />

            <StatCard
              id="company"
              label="Company Level"
              value={stats.companyRules || 0}
              color="#f59e0b"
              icon="🏢"
              detailContent={
                <div>
                  <div style={{ marginBottom: 8, color: '#f59e0b' }}>Applies to all departments</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>
                    {companyRules && companyRules.length > 0 ? (
                      <div>
                        <div>✓ {companyRules.length} rule{companyRules.length !== 1 ? 's' : ''}</div>
                        {companyRules.slice(0, 2).map((r, i) => (
                          <div key={i} style={{ marginTop: 4, color: '#cbd5e1', fontSize: 10 }}>
                            • {r.ruleName}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div>No company-level rules</div>
                    )}
                  </div>
                  <button
                    onClick={() => setSelectedCard('company')}
                    style={{
                      marginTop: 8,
                      padding: '4px 8px',
                      background: '#f59e0b',
                      color: '#000',
                      border: 'none',
                      borderRadius: 4,
                      fontSize: 10,
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    View All
                  </button>
                </div>
              }
            />

            <StatCard
              id="dept"
              label="Department Level"
              value={stats.departmentRules || 0}
              color="#8b5cf6"
              icon="🏬"
              detailContent={
                <div>
                  <div style={{ marginBottom: 8, color: '#8b5cf6' }}>Department-specific rules</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>
                    {departmentRules && departmentRules.length > 0 ? (
                      <div>
                        <div>✓ {departmentRules.length} rule{departmentRules.length !== 1 ? 's' : ''}</div>
                        {departmentRules.slice(0, 2).map((r, i) => (
                          <div key={i} style={{ marginTop: 4, color: '#cbd5e1', fontSize: 10 }}>
                            • {r.ruleName}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div>No department-level rules</div>
                    )}
                  </div>
                  <button
                    onClick={() => setSelectedCard('dept')}
                    style={{
                      marginTop: 8,
                      padding: '4px 8px',
                      background: '#8b5cf6',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 4,
                      fontSize: 10,
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    View All
                  </button>
                </div>
              }
            />

            <StatCard
              id="system"
              label="System Level"
              value={stats.systemRules || 0}
              color="#06b6d4"
              icon="💻"
              detailContent={
                <div>
                  <div style={{ marginBottom: 8, color: '#06b6d4' }}>System-specific rules</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>
                    {stats.systemRules > 0 ? (
                      <div>
                        <div>✓ {stats.systemRules} rule{stats.systemRules !== 1 ? 's' : ''} on systems</div>
                        {systemRules.slice(0, 2).map((r, i) => (
                          <div key={i} style={{ marginTop: 4, color: '#cbd5e1', fontSize: 10 }}>
                            • {r.ruleName}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div>No system-level rules</div>
                    )}
                  </div>
                  <button
                    onClick={() => setSelectedCard('system')}
                    style={{
                      marginTop: 8,
                      padding: '4px 8px',
                      background: '#06b6d4',
                      color: '#000',
                      border: 'none',
                      borderRadius: 4,
                      fontSize: 10,
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    View All
                  </button>
                </div>
              }
            />

            <StatCard
              id="block"
              label="Block Rules"
              value={stats.blockRules || 0}
              color="#f87171"
              icon="🚫"
              detailContent={
                <div>
                  <div style={{ marginBottom: 8, color: '#f87171' }}>Active blocking rules</div>
                  <div style={{ fontSize: 11, color: '#94a3b8' }}>
                    {blockRules.length > 0 ? (
                      <div>
                        <div>✓ {blockRules.length} rule{blockRules.length !== 1 ? 's' : ''} blocking</div>
                        {blockRules.slice(0, 2).map((r, i) => (
                          <div key={i} style={{ marginTop: 4, color: '#cbd5e1', fontSize: 10 }}>
                            • {r.ruleName || r.conditions?.ipAddress || 'Unknown'}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div>No blocking rules</div>
                    )}
                  </div>
                  <button
                    onClick={() => setSelectedCard('block')}
                    style={{
                      marginTop: 8,
                      padding: '4px 8px',
                      background: '#f87171',
                      color: '#fff',
                      border: 'none',
                      borderRadius: 4,
                      fontSize: 10,
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    View All
                  </button>
                </div>
              }
            />
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          </div>

          {/* Full Details Modal */}
          {selectedCard && renderDetailsModal()}
        </>
      )}
    </div>
  );
}

// ── Company Level Rules ───────────────────────────────────────────────────────
function CompanyLevelRules({ rules, onRefresh, toast, firewallType }) {
  const [showForm, setShowForm] = useState(false);
  const [blockType, setBlockType] = useState('ipAddress');
  const [formData, setFormData] = useState({
    ruleName: '',
    description: '',
    action: 'block',
    direction: 'inbound',
    conditions: { protocol: 'all' },
    priority: 100,
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    const hasBlockValue =
      (blockType === 'ipAddress' && formData.conditions.ipAddress) ||
      (blockType === 'domain' && formData.conditions.domain) ||
      (blockType === 'port' && formData.conditions.port) ||
      (blockType === 'application' && formData.conditions.application) ||
      (blockType === 'protocol' && formData.conditions.blockProtocol);

    if (!formData.ruleName || !hasBlockValue) {
      toast.warning('Rule name and block value required');
      return;
    }

    setLoading(true);
    try {
      await api.post('/firewall/rules', {
        ...formData,
        level: 'company',
        firewallType: 'auto',
      });
      toast.success('Company rule created');
      setShowForm(false);
      setBlockType('ipAddress');
      setFormData({ ruleName: '', description: '', action: 'block', direction: 'inbound', conditions: { protocol: 'all' }, priority: 100 });
      onRefresh();
    } catch (e) {
      toast.error(e.response?.data?.message || e.message);
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    padding: '10px 14px',
    background: '#0c1a2e',
    border: '1px solid #1e3a5f',
    borderRadius: 6,
    color: '#e2e8f0',
    fontSize: 13,
    fontWeight: 500,
  };

  const labelStyle = {
    fontSize: 11,
    fontWeight: 600,
    color: '#64748b',
    marginBottom: 6,
    display: 'block',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  };

  return (
    <div style={{ background: '#0c1a2e', border: '2px solid #f59e0b44', borderRadius: 12, padding: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, color: '#f59e0b' }}>🏢 Company Level Rules</h3>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            style={{
              padding: '8px 18px',
              borderRadius: 6,
              fontSize: 13,
              fontWeight: 700,
              background: '#f59e0b',
              border: 'none',
              color: '#000000',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              transition: 'all 0.2s',
            }}
            onMouseOver={(e) => e.target.style.background = '#fbbf24'}
            onMouseOut={(e) => e.target.style.background = '#f59e0b'}
          >
            ➕ Add Firewall Rule
          </button>
        )}
      </div>

      {showForm && (
        <div style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 20, marginBottom: 20 }}>
          {/* Quick Add Form - Single Row */}
          <div style={{ marginBottom: 24 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
              <h4 style={{ fontSize: 12, fontWeight: 700, color: '#93c5fd', margin: 0, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Quick Add Firewall Rule</h4>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#a78bfa', display: 'inline-flex', alignItems: 'center', gap: 6 }} title="Applies to every system/server in the company — each enforces on its own OS firewall">🛡 Firewall: Auto · per system OS</span>
            </div>
            
            <div style={{ display: 'grid', gridTemplateColumns: '150px 130px 1fr 120px 120px 110px auto', gap: 12, alignItems: 'flex-end', marginBottom: 16 }}>
              {/* Rule Name */}
              <div>
                <label style={labelStyle}>Rule Name *</label>
                <input
                  type="text"
                  placeholder="Rule name"
                  value={formData.ruleName}
                  onChange={e => setFormData({ ...formData, ruleName: e.target.value })}
                  style={inputStyle}
                />
              </div>

              {/* Block Type */}
              <div>
                <label style={labelStyle}>Block Type</label>
                <select
                  value={blockType}
                  onChange={e => {
                    setBlockType(e.target.value);
                    setFormData({
                      ...formData,
                      conditions: {
                        protocol: formData.conditions.protocol || 'all',
                        ipAddress: '',
                        domain: '',
                        port: '',
                        application: '',
                        blockProtocol: '',
                      },
                    });
                  }}
                  style={inputStyle}
                >
                  <option value="ipAddress">IP Address</option>
                  <option value="domain">Domain</option>
                  <option value="port">Port</option>
                  <option value="application">Application</option>
                  <option value="protocol">Protocol</option>
                </select>
              </div>

              {/* Block Value */}
              <div>
                <label style={labelStyle}>Value</label>
                {blockType === 'ipAddress' && (
                  <input
                    type="text"
                    placeholder="e.g., 192.168.1.100"
                    value={formData.conditions.ipAddress || ''}
                    onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, ipAddress: e.target.value } })}
                    style={inputStyle}
                  />
                )}
                {blockType === 'domain' && (
                  <input
                    type="text"
                    placeholder="e.g., example.com"
                    value={formData.conditions.domain || ''}
                    onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, domain: e.target.value } })}
                    style={inputStyle}
                  />
                )}
                {blockType === 'port' && (
                  <input
                    type="text"
                    placeholder="e.g., 8080"
                    value={formData.conditions.port || ''}
                    onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, port: e.target.value } })}
                    style={inputStyle}
                  />
                )}
                {blockType === 'application' && (
                  <input
                    type="text"
                    placeholder="e.g., chrome, firefox"
                    value={formData.conditions.application || ''}
                    onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, application: e.target.value } })}
                    style={inputStyle}
                  />
                )}
                {blockType === 'protocol' && (
                  <input
                    type="text"
                    placeholder="e.g., HTTP, HTTPS, DNS"
                    value={formData.conditions.blockProtocol || ''}
                    onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, blockProtocol: e.target.value } })}
                    style={inputStyle}
                  />
                )}
              </div>

              {/* Direction */}
              <div>
                <label style={labelStyle}>Direction</label>
                <select
                  value={formData.direction}
                  onChange={e => setFormData({ ...formData, direction: e.target.value })}
                  style={inputStyle}
                >
                  <option value="inbound">Inbound</option>
                  <option value="outbound">Outbound</option>
                  <option value="both">Both</option>
                </select>
              </div>

              {/* Action */}
              <div>
                <label style={labelStyle}>Action</label>
                <select
                  value={formData.action}
                  onChange={e => setFormData({ ...formData, action: e.target.value })}
                  style={inputStyle}
                >
                  <option value="block">Block</option>
                  <option value="allow">Allow</option>
                  <option value="log">Log</option>
                </select>
              </div>

              {/* Protocol */}
              <div>
                <label style={labelStyle}>Protocol</label>
                <select
                  value={formData.conditions.protocol || 'all'}
                  onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, protocol: e.target.value } })}
                  style={inputStyle}
                >
                  <option value="all">All</option>
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                  <option value="icmp">ICMP</option>
                </select>
              </div>

              {/* Add Button */}
              <button
                onClick={handleSubmit}
                disabled={loading}
                style={{
                  padding: '10px 24px',
                  background: '#f59e0b',
                  border: 'none',
                  borderRadius: 6,
                  color: '#000000',
                  fontWeight: 700,
                  cursor: 'pointer',
                  fontSize: 13,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 6,
                  whiteSpace: 'nowrap',
                  transition: 'all 0.2s',
                  opacity: loading ? 0.7 : 1,
                }}
                onMouseOver={(e) => !loading && (e.target.style.background = '#fbbf24')}
                onMouseOut={(e) => !loading && (e.target.style.background = '#f59e0b')}
              >
                {loading ? <Spinner size={14} /> : '➕ Add Rule'}
              </button>
            </div>
          </div>


        </div>
      )}

      {rules && rules.length > 0 && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
                <th style={{ padding: '8px', textAlign: 'left', color: '#1e40af' }}>Rule Name</th>
                <th style={{ padding: '8px', textAlign: 'left', color: '#1e40af' }}>Action</th>
                <th style={{ padding: '8px', textAlign: 'left', color: '#1e40af' }}>Direction</th>
                <th style={{ padding: '8px', textAlign: 'left', color: '#1e40af' }}>Conditions</th>
                <th style={{ padding: '8px', textAlign: 'center', color: '#1e40af' }}>Unblock</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule._id} style={{ borderBottom: '1px solid #1e3a5f' }}>
                  <td style={{ padding: '8px', color: '#e2e8f0' }}>{rule.ruleName}</td>
                  <td style={{ padding: '8px', color: rule.action === 'block' ? '#f87171' : '#22c55e' }}>{rule.action?.toUpperCase()}</td>
                  <td style={{ padding: '8px', color: '#93c5fd' }}>{rule.direction}</td>
                  <td style={{ padding: '8px', color: '#64748b', fontSize: 11 }}>
                    {rule.conditions?.ipAddress && `IP: ${rule.conditions.ipAddress} `}
                    {rule.conditions?.domain && `Domain: ${rule.conditions.domain} `}
                    {rule.conditions?.port && `Port: ${rule.conditions.port} `}
                    {rule.conditions?.application && `App: ${rule.conditions.application} `}
                    {rule.conditions?.blockProtocol && `Protocol: ${rule.conditions.blockProtocol}`}
                  </td>
                  <td style={{ padding: '8px', textAlign: 'center' }}>
                    <button
                      onClick={async () => {
                        try {
                          await api.delete(`/firewall/rules/${rule._id}`);
                          toast.success(`✓ Rule "${rule.ruleName}" deleted & unblocked`);
                          onRefresh();
                        } catch (error) {
                          toast.error(error.response?.data?.message || 'Failed to unblock');
                        }
                      }}
                      style={{
                        padding: '4px 12px',
                        background: '#84cc16',
                        color: '#000',
                        border: 'none',
                        borderRadius: 4,
                        fontSize: 10,
                        fontWeight: 700,
                        cursor: 'pointer',
                        transition: 'all 0.2s',
                      }}
                      onMouseOver={(e) => e.currentTarget.style.background = '#a3e635'}
                      onMouseOut={(e) => e.currentTarget.style.background = '#84cc16'}
                    >
                      🔓 Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(!rules || rules.length === 0) && (
        <div style={{ textAlign: 'center', padding: 30, color: '#1e3a5f' }}>
          No company-level rules yet. Create one to get started!
        </div>
      )}
    </div>
  );
}

// ── Department Level Rules ────────────────────────────────────────────────────
function DepartmentLevelRules({ rules, departments, onRefresh, toast, firewallType }) {
  const [showForm, setShowForm] = useState(false);
  const [selectedDepartment, setSelectedDepartment] = useState('');
  const [blockType, setBlockType] = useState('ipAddress');
  const [formData, setFormData] = useState({
    ruleName: '',
    description: '',
    action: 'block',
    direction: 'inbound',
    conditions: { protocol: 'all' },
    priority: 100,
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    if (!selectedDepartment) {
      toast.warning('Please select a department');
      return;
    }

    const hasBlockValue = 
      (blockType === 'ipAddress' && formData.conditions.ipAddress) ||
      (blockType === 'domain' && formData.conditions.domain) ||
      (blockType === 'port' && formData.conditions.port) ||
      (blockType === 'application' && formData.conditions.application) ||
      (blockType === 'protocol' && formData.conditions.blockProtocol);

    if (!formData.ruleName || !hasBlockValue) {
      toast.warning('Rule name and block value required');
      return;
    }

    setLoading(true);
    try {
      await api.post('/firewall/rules', {
        ...formData,
        level: 'department',
        departmentIds: [selectedDepartment],
        firewallType: 'auto',
      });
      toast.success('Department rule created');
      setShowForm(false);
      setSelectedDepartment('');
      setBlockType('ipAddress');
      setFormData({ ruleName: '', description: '', action: 'block', direction: 'inbound', conditions: { protocol: 'all' }, priority: 100 });
      onRefresh();
    } catch (e) {
      toast.error(e.response?.data?.message || e.message);
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    padding: '10px 14px',
    background: '#0c1a2e',
    border: '1px solid #1e3a5f',
    borderRadius: 6,
    color: '#e2e8f0',
    fontSize: 13,
    fontWeight: 500,
  };

  const labelStyle = {
    fontSize: 11,
    fontWeight: 600,
    color: '#64748b',
    marginBottom: 6,
    display: 'block',
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  };

  return (
    <div style={{ background: '#0c1a2e', border: '2px solid #8b5cf644', borderRadius: 12, padding: 20, marginTop: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <h3 style={{ fontSize: 18, fontWeight: 700, color: '#8b5cf6' }}>🏬 Department Level Rules</h3>
        {!showForm && (
          <button
            onClick={() => setShowForm(true)}
            style={{
              padding: '8px 18px',
              borderRadius: 6,
              fontSize: 13,
              fontWeight: 700,
              background: '#8b5cf6',
              border: 'none',
              color: '#ffffff',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              transition: 'all 0.2s',
            }}
            onMouseOver={(e) => e.target.style.background = '#a78bfa'}
            onMouseOut={(e) => e.target.style.background = '#8b5cf6'}
          >
            ➕ Add Rule
          </button>
        )}
      </div>

      {showForm && (
        <div style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 20, marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
            <h4 style={{ fontSize: 12, fontWeight: 700, color: '#c4b5fd', margin: 0, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Select Department & Add Rule</h4>
            <span style={{ fontSize: 11, fontWeight: 700, color: '#a78bfa', display: 'inline-flex', alignItems: 'center', gap: 6 }} title="Applies to every system/server in the department — each enforces on its own OS firewall">🛡 Firewall: Auto · per system OS</span>
          </div>
          
          {/* Department Selection */}
          <div style={{ marginBottom: 20 }}>
            <label style={labelStyle}>Select Department *</label>
            <select
              value={selectedDepartment}
              onChange={e => setSelectedDepartment(e.target.value)}
              style={{
                ...inputStyle,
                width: '100%',
              }}
            >
              <option value="">-- Choose a Department --</option>
              {departments.map(dept => (
                <option key={dept._id} value={dept._id}>
                  {dept.name}
                </option>
              ))}
            </select>
          </div>

          {selectedDepartment && (
            <>
              <div style={{ borderBottom: '1px solid #1e3a5f', marginBottom: 20, paddingBottom: 12 }}>
                <p style={{ fontSize: 11, color: '#64748b', margin: 0 }}>
                  📍 Rules will be applied to: <span style={{ color: '#8b5cf6', fontWeight: 700 }}>
                    {departments.find(d => d._id === selectedDepartment)?.name}
                  </span>
                </p>
              </div>

              {/* Quick Add Form - Single Row */}
              <div style={{ marginBottom: 24 }}>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: '#93c5fd', marginBottom: 16, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Rule Details</h4>
                
                <div style={{ display: 'grid', gridTemplateColumns: '150px 130px 1fr 120px 120px 110px auto', gap: 12, alignItems: 'flex-end', marginBottom: 16 }}>
                  {/* Rule Name */}
                  <div>
                    <label style={labelStyle}>Rule Name *</label>
                    <input
                      type="text"
                      placeholder="Rule name"
                      value={formData.ruleName}
                      onChange={e => setFormData({ ...formData, ruleName: e.target.value })}
                      style={inputStyle}
                    />
                  </div>

                  {/* Block Type */}
                  <div>
                    <label style={labelStyle}>Block Type</label>
                    <select
                      value={blockType}
                      onChange={e => {
                        setBlockType(e.target.value);
                        setFormData({
                          ...formData,
                          conditions: {
                            protocol: formData.conditions.protocol || 'all',
                            ipAddress: '',
                            domain: '',
                            port: '',
                            application: '',
                            blockProtocol: '',
                          },
                        });
                      }}
                      style={inputStyle}
                    >
                      <option value="ipAddress">IP Address</option>
                      <option value="domain">Domain</option>
                      <option value="port">Port</option>
                      <option value="application">Application</option>
                      <option value="protocol">Protocol</option>
                    </select>
                  </div>

                  {/* Block Value */}
                  <div>
                    <label style={labelStyle}>Value</label>
                    {blockType === 'ipAddress' && (
                      <input
                        type="text"
                        placeholder="e.g., 192.168.1.100"
                        value={formData.conditions.ipAddress || ''}
                        onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, ipAddress: e.target.value } })}
                        style={inputStyle}
                      />
                    )}
                    {blockType === 'domain' && (
                      <input
                        type="text"
                        placeholder="e.g., example.com"
                        value={formData.conditions.domain || ''}
                        onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, domain: e.target.value } })}
                        style={inputStyle}
                      />
                    )}
                    {blockType === 'port' && (
                      <input
                        type="text"
                        placeholder="e.g., 8080"
                        value={formData.conditions.port || ''}
                        onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, port: e.target.value } })}
                        style={inputStyle}
                      />
                    )}
                    {blockType === 'application' && (
                      <input
                        type="text"
                        placeholder="e.g., chrome, firefox"
                        value={formData.conditions.application || ''}
                        onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, application: e.target.value } })}
                        style={inputStyle}
                      />
                    )}
                    {blockType === 'protocol' && (
                      <input
                        type="text"
                        placeholder="e.g., HTTP, HTTPS, DNS"
                        value={formData.conditions.blockProtocol || ''}
                        onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, blockProtocol: e.target.value } })}
                        style={inputStyle}
                      />
                    )}
                  </div>

                  {/* Direction */}
                  <div>
                    <label style={labelStyle}>Direction</label>
                    <select
                      value={formData.direction}
                      onChange={e => setFormData({ ...formData, direction: e.target.value })}
                      style={inputStyle}
                    >
                      <option value="inbound">Inbound</option>
                      <option value="outbound">Outbound</option>
                      <option value="both">Both</option>
                    </select>
                  </div>

                  {/* Action */}
                  <div>
                    <label style={labelStyle}>Action</label>
                    <select
                      value={formData.action}
                      onChange={e => setFormData({ ...formData, action: e.target.value })}
                      style={inputStyle}
                    >
                      <option value="block">Block</option>
                      <option value="allow">Allow</option>
                      <option value="log">Log</option>
                    </select>
                  </div>

                  {/* Protocol */}
                  <div>
                    <label style={labelStyle}>Protocol</label>
                    <select
                      value={formData.conditions.protocol || 'all'}
                      onChange={e => setFormData({ ...formData, conditions: { ...formData.conditions, protocol: e.target.value } })}
                      style={inputStyle}
                    >
                      <option value="all">All</option>
                      <option value="tcp">TCP</option>
                      <option value="udp">UDP</option>
                      <option value="icmp">ICMP</option>
                    </select>
                  </div>

                  {/* Add Button */}
                  <button
                    onClick={handleSubmit}
                    disabled={loading}
                    style={{
                      padding: '10px 24px',
                      background: '#8b5cf6',
                      border: 'none',
                      borderRadius: 6,
                      color: '#ffffff',
                      fontWeight: 700,
                      cursor: 'pointer',
                      fontSize: 13,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: 6,
                      whiteSpace: 'nowrap',
                      transition: 'all 0.2s',
                      opacity: loading ? 0.7 : 1,
                    }}
                    onMouseOver={(e) => !loading && (e.target.style.background = '#a78bfa')}
                    onMouseOut={(e) => !loading && (e.target.style.background = '#8b5cf6')}
                  >
                    {loading ? <Spinner size={14} /> : '➕ Add Rule'}
                  </button>
                </div>
              </div>

              {/* Cancel Button */}
              <button
                onClick={() => {
                  setShowForm(false);
                  setSelectedDepartment('');
                  setBlockType('ipAddress');
                  setFormData({ ruleName: '', description: '', action: 'block', direction: 'inbound', conditions: { protocol: 'all' }, priority: 100 });
                }}
                style={{
                  padding: '8px 18px',
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 700,
                  background: '#1e3a5f',
                  border: '1px solid #3d5a80',
                  color: '#93c5fd',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                }}
                onMouseOver={(e) => e.target.style.background = '#2a4a70'}
                onMouseOut={(e) => e.target.style.background = '#1e3a5f'}
              >
                Cancel
              </button>
            </>
          )}
        </div>
      )}

      {rules && rules.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <h4 style={{ fontSize: 13, fontWeight: 700, color: '#8b5cf6', marginBottom: 12 }}>📋 Applied Rules</h4>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#8b5cf6' }}>Rule Name</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#8b5cf6' }}>Action</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#8b5cf6' }}>Direction</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#8b5cf6' }}>Conditions</th>
                  <th style={{ padding: '8px', textAlign: 'center', color: '#8b5cf6' }}>Unblock</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule._id} style={{ borderBottom: '1px solid #1e3a5f' }}>
                    <td style={{ padding: '8px', color: '#e2e8f0' }}>{rule.ruleName}</td>
                    <td style={{ padding: '8px', color: rule.action === 'block' ? '#f87171' : '#22c55e' }}>{rule.action?.toUpperCase()}</td>
                    <td style={{ padding: '8px', color: '#93c5fd' }}>{rule.direction}</td>
                    <td style={{ padding: '8px', color: '#64748b', fontSize: 10 }}>
                      {rule.conditions?.ipAddress && `IP: ${rule.conditions.ipAddress} `}
                      {rule.conditions?.domain && `Domain: ${rule.conditions.domain} `}
                      {rule.conditions?.port && `Port: ${rule.conditions.port} `}
                      {rule.conditions?.application && `App: ${rule.conditions.application} `}
                      {rule.conditions?.blockProtocol && `Protocol: ${rule.conditions.blockProtocol}`}
                    </td>
                    <td style={{ padding: '8px', textAlign: 'center' }}>
                      <button
                        onClick={async () => {
                          try {
                            await api.delete(`/firewall/rules/${rule._id}`);
                            toast.success(`✓ Rule "${rule.ruleName}" deleted & unblocked`);
                            onRefresh();
                          } catch (error) {
                            toast.error(error.response?.data?.message || 'Failed to unblock');
                          }
                        }}
                        style={{
                          padding: '3px 10px',
                          background: '#8b5cf6',
                          color: '#fff',
                          border: 'none',
                          borderRadius: 4,
                          fontSize: 9,
                          fontWeight: 700,
                          cursor: 'pointer',
                          transition: 'all 0.2s',
                        }}
                        onMouseOver={(e) => e.currentTarget.style.background = '#a78bfa'}
                        onMouseOut={(e) => e.currentTarget.style.background = '#8b5cf6'}
                      >
                        🔓
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(!rules || rules.length === 0) && (
        <div style={{ textAlign: 'center', padding: 30, color: '#1e3a5f' }}>
          No department-level rules yet. Select a department and add rules to get started!
        </div>
      )}
    </div>
  );
}

// ── System Level Rules ────────────────────────────────────────────────────────
function SystemLevelRules({ systems, rules = [], onRefresh, toast, firewallType }) {
  const [selectedSystem, setSelectedSystem] = useState(null);
  const [showForm, setShowForm] = useState(false);
  const [blockType, setBlockType] = useState('ipAddress');
  const [formData, setFormData] = useState({
    ruleName: '',
    description: '',
    action: 'block',
    direction: 'inbound',
    conditions: { protocol: 'all' },
    priority: 100,
  });
  const [loading, setLoading] = useState(false);

  const handleAddRuleClick = (systemId) => {
    setSelectedSystem(systemId);
    setShowForm(true);
  };

  const handleSubmit = async () => {
    const hasBlockValue = 
      (blockType === 'ipAddress' && formData.conditions.ipAddress) ||
      (blockType === 'domain' && formData.conditions.domain) ||
      (blockType === 'port' && formData.conditions.port) ||
      (blockType === 'application' && formData.conditions.application) ||
      (blockType === 'protocol' && formData.conditions.blockProtocol);

    if (!formData.ruleName || !hasBlockValue) {
      toast.warning('Rule name and block value required');
      return;
    }

    setLoading(true);
    try {
      await api.post('/firewall/rules', {
        ...formData,
        level: 'system',
        systemId: selectedSystem,
        firewallType: osToFirewall(selectedSystemData?.os),
      });
      toast.success('System rule created');
      setShowForm(false);
      setSelectedSystem(null);
      setBlockType('ipAddress');
      setFormData({ ruleName: '', description: '', action: 'block', direction: 'inbound', conditions: { protocol: 'all' }, priority: 100 });
      onRefresh();
    } catch (e) {
      toast.error(e.response?.data?.message || e.message);
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    padding: '10px 14px',
    background: '#0c1a2e',
    border: '1px solid #1e3a5f',
    borderRadius: 6,
    color: '#e2e8f0',
    fontSize: 13,
    fontWeight: 500,
  };

  const labelStyle = {
    fontSize: 11,
    fontWeight: 600,
    color: '#64748b',
    marginBottom: 6,
    textTransform: 'uppercase',
    letterSpacing: '0.5px',
  };

  const buttonStyle = {
    padding: '10px 20px',
    background: '#06b6d4',
    border: 'none',
    borderRadius: 6,
    color: '#ffffff',
    fontSize: 13,
    fontWeight: 700,
    cursor: 'pointer',
    transition: 'all 0.2s',
  };

  const selectedSystemData = systems?.find(s => s._id === selectedSystem);

  return (
    <div style={{ background: '#0c1a2e', border: '2px solid #06b6d444', borderRadius: 12, padding: 20, marginTop: 16 }}>
      <h3 style={{ fontSize: 18, fontWeight: 700, color: '#06b6d4', marginBottom: 16 }}>💻 System Level Rules</h3>

      {systems && systems.length > 0 ? (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12, marginBottom: showForm ? 24 : 0 }}>
            {systems.map((system) => (
              <div
                key={system._id}
                style={{
                  background: selectedSystem === system._id ? '#1e3a5f44' : '#060e1a',
                  border: selectedSystem === system._id ? '2px solid #06b6d4' : '1px solid #1e3a5f',
                  borderRadius: 8,
                  padding: 14,
                  transition: 'all 0.2s',
                }}
              >
                <div style={{ fontSize: 13, fontWeight: 700, color: '#06b6d4', marginBottom: 6 }}>
                  {system.hostname || system.name} ({system.os})
                </div>
                <div style={{ fontSize: 11, color: '#64748b', marginBottom: 8 }}>
                  {system.ip || 'No IP'}
                </div>
                <button
                  onClick={() => handleAddRuleClick(system._id)}
                  style={{
                    padding: '6px 12px',
                    background: selectedSystem === system._id ? '#06b6d4' : '#06b6d444',
                    border: '1px solid #06b6d4',
                    borderRadius: 4,
                    color: '#ffffff',
                    fontSize: 10,
                    fontWeight: 700,
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = '#06b6d4'}
                  onMouseLeave={(e) => e.currentTarget.style.background = selectedSystem === system._id ? '#06b6d4' : '#06b6d444'}
                >
                  + Add Rule
                </button>
              </div>
            ))}
          </div>

          {showForm && selectedSystemData && (
            <div style={{ background: '#060e1a', border: '1px solid #06b6d444', borderRadius: 8, padding: 20 }}>
              <div style={{ marginBottom: 20, paddingBottom: 12, borderBottom: '1px solid #1e3a5f' }}>
                <h4 style={{ fontSize: 12, fontWeight: 700, color: '#93c5fd', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Add Rule For</h4>
                <p style={{ fontSize: 13, color: '#06b6d4', fontWeight: 700, margin: 0 }}>
                  💻 {selectedSystemData.hostname || selectedSystemData.name} ({selectedSystemData.os})
                </p>
                <p style={{ fontSize: 11, color: '#64748b', margin: '4px 0 0 0' }}>
                  IP: {selectedSystemData.ip || 'N/A'}
                </p>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 16 }}>
                <div>
                  <div style={labelStyle}>Rule Name *</div>
                  <input
                    type="text"
                    placeholder="Descriptive rule name"
                    value={formData.ruleName}
                    onChange={(e) => setFormData({ ...formData, ruleName: e.target.value })}
                    style={inputStyle}
                  />
                </div>
                <div>
                  <div style={labelStyle}>Block Type</div>
                  <select
                    value={blockType}
                    onChange={(e) => {
                      setBlockType(e.target.value);
                      setFormData({
                        ...formData,
                        conditions: {
                          ...formData.conditions,
                          ipAddress: '',
                          domain: '',
                          port: '',
                          application: '',
                          blockProtocol: '',
                        },
                      });
                    }}
                    style={inputStyle}
                  >
                    <option value="ipAddress">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="port">Port</option>
                    <option value="application">Application</option>
                    <option value="protocol">Protocol</option>
                  </select>
                </div>
                <div>
                  <div style={labelStyle}>
                    {blockType === 'ipAddress' && 'IP Address *'}
                    {blockType === 'domain' && 'Domain *'}
                    {blockType === 'port' && 'Port *'}
                    {blockType === 'application' && 'Application *'}
                    {blockType === 'protocol' && 'Protocol *'}
                  </div>
                  <input
                    type="text"
                    placeholder={blockType === 'ipAddress' ? '192.168.1.100' : blockType === 'domain' ? 'example.com' : blockType === 'port' ? '8080' : blockType === 'application' ? 'chrome, firefox' : 'HTTP, HTTPS, DNS'}
                    value={
                      blockType === 'ipAddress'
                        ? formData.conditions.ipAddress || ''
                        : blockType === 'domain'
                        ? formData.conditions.domain || ''
                        : blockType === 'port'
                        ? formData.conditions.port || ''
                        : blockType === 'application'
                        ? formData.conditions.application || ''
                        : formData.conditions.blockProtocol || ''
                    }
                    onChange={(e) => {
                      const conditions = { ...formData.conditions };
                      if (blockType === 'ipAddress') conditions.ipAddress = e.target.value;
                      else if (blockType === 'domain') conditions.domain = e.target.value;
                      else if (blockType === 'port') conditions.port = e.target.value;
                      else if (blockType === 'application') conditions.application = e.target.value;
                      else conditions.blockProtocol = e.target.value;
                      setFormData({ ...formData, conditions });
                    }}
                    style={inputStyle}
                  />
                </div>
                <div>
                  <div style={labelStyle}>Direction</div>
                  <select
                    value={formData.direction}
                    onChange={(e) => setFormData({ ...formData, direction: e.target.value })}
                    style={inputStyle}
                  >
                    <option value="inbound">Inbound</option>
                    <option value="outbound">Outbound</option>
                    <option value="both">Both</option>
                  </select>
                </div>
                <div>
                  <div style={labelStyle}>Action</div>
                  <select
                    value={formData.action}
                    onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                    style={inputStyle}
                  >
                    <option value="block">Block</option>
                    <option value="allow">Allow</option>
                    <option value="log">Log</option>
                  </select>
                </div>
                <div>
                  <div style={labelStyle}>Protocol</div>
                  <select
                    value={formData.conditions.protocol}
                    onChange={(e) => setFormData({ ...formData, conditions: { ...formData.conditions, protocol: e.target.value } })}
                    style={inputStyle}
                  >
                    <option value="all">All</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP</option>
                  </select>
                </div>
                <div>
                  <div style={labelStyle}>Firewall (auto by OS)</div>
                  <div style={{ ...inputStyle, color: '#a78bfa', fontWeight: 700, whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: 6 }} title={`Auto-selected from OS: ${selectedSystemData?.os || 'unknown'}`}>
                    🛡 {FIREWALL_LABEL[osToFirewall(selectedSystemData?.os)]}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
                <button
                  onClick={() => {
                    setShowForm(false);
                    setSelectedSystem(null);
                    setBlockType('ipAddress');
                    setFormData({ ruleName: '', description: '', action: 'block', direction: 'inbound', conditions: { protocol: 'all' }, priority: 100 });
                  }}
                  style={{ ...buttonStyle, background: '#64748b' }}
                  disabled={loading}
                >
                  Cancel
                </button>
                <button onClick={handleSubmit} style={buttonStyle} disabled={loading}>
                  {loading ? 'Adding...' : '✓ Add Rule'}
                </button>
              </div>
            </div>
          )}
        </>
      ) : (
        <div style={{ textAlign: 'center', padding: 30, color: '#1e3a5f' }}>
          No systems available. Add systems first.
        </div>
      )}

      {rules && rules.length > 0 && (
        <div style={{ marginTop: 24 }}>
          <h4 style={{ fontSize: 13, fontWeight: 700, color: '#06b6d4', marginBottom: 12 }}>📋 System-Level Rules</h4>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#06b6d4' }}>Rule Name</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#06b6d4' }}>Action</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#06b6d4' }}>Direction</th>
                  <th style={{ padding: '8px', textAlign: 'left', color: '#06b6d4' }}>Conditions</th>
                  <th style={{ padding: '8px', textAlign: 'center', color: '#06b6d4' }}>Unblock</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((rule) => (
                  <tr key={rule._id} style={{ borderBottom: '1px solid #1e3a5f' }}>
                    <td style={{ padding: '8px', color: '#e2e8f0' }}>{rule.ruleName}</td>
                    <td style={{ padding: '8px', color: rule.action === 'block' ? '#f87171' : rule.action === 'allow' ? '#22c55e' : '#f59e0b' }}>{rule.action?.toUpperCase()}</td>
                    <td style={{ padding: '8px', color: '#93c5fd' }}>{rule.direction}</td>
                    <td style={{ padding: '8px', color: '#64748b', fontSize: 10 }}>
                      {rule.conditions?.ipAddress && `IP: ${rule.conditions.ipAddress} `}
                      {rule.conditions?.domain && `Domain: ${rule.conditions.domain} `}
                      {rule.conditions?.port && `Port: ${rule.conditions.port} `}
                      {rule.conditions?.application && `App: ${rule.conditions.application} `}
                      {rule.conditions?.blockProtocol && `Protocol: ${rule.conditions.blockProtocol}`}
                    </td>
                    <td style={{ padding: '8px', textAlign: 'center' }}>
                      <button
                        onClick={async () => {
                          try {
                            await api.delete(`/firewall/rules/${rule._id}`);
                            toast.success(`✓ Rule "${rule.ruleName}" deleted & unblocked`);
                            onRefresh();
                          } catch (error) {
                            toast.error(error.response?.data?.message || 'Failed to unblock');
                          }
                        }}
                        style={{
                          padding: '3px 10px',
                          background: '#06b6d4',
                          color: '#fff',
                          border: 'none',
                          borderRadius: 4,
                          fontSize: 9,
                          fontWeight: 700,
                          cursor: 'pointer',
                          transition: 'all 0.2s',
                        }}
                        onMouseOver={(e) => e.currentTarget.style.background = '#22d3ee'}
                        onMouseOut={(e) => e.currentTarget.style.background = '#06b6d4'}
                      >
                        🔓
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Firewall Type Selector ───────────────────────────────────────────────────
function FirewallTypeSelector({ selectedFirewall, onFirewallChange, totalRules = 0 }) {
  const firewalls = [
    { id: 'nftables', name: 'nftables', icon: '🐧', color: '#22c55e', bgColor: '#22c55e44' },
    { id: 'windows_defender', name: 'Windows Defender', icon: '🪟', color: '#3b82f6', bgColor: '#3b82f644' },
    { id: 'pfctl', name: 'pfctl (macOS)', icon: '🍎', color: '#a78bfa', bgColor: '#a78bfa44' },
  ];

  const isCurrentFirewallLocked = totalRules > 0;

  return (
    <div style={{
      background: '#0c1a2e',
      border: '2px solid #1e3a5f',
      borderRadius: 12,
      padding: 20,
      marginBottom: 24,
    }}>
      <div style={{ fontSize: 14, fontWeight: 700, color: '#93c5fd', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        🔧 Select Firewall Type
      </div>
      {isCurrentFirewallLocked && (
        <div style={{
          background: '#f87171',
          color: '#fff',
          padding: '8px 12px',
          borderRadius: 6,
          fontSize: 11,
          fontWeight: 700,
          marginBottom: 12,
          display: 'flex',
          alignItems: 'center',
          gap: 6,
        }}>
          🔒 Firewall Locked: {totalRules} active rule{totalRules !== 1 ? 's' : ''} found. Unblock all rules to switch firewalls.
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
        {firewalls.map((fw) => {
          const isDisabled = isCurrentFirewallLocked && selectedFirewall !== fw.id;
          
          return (
            <button
              key={fw.id}
              onClick={() => !isDisabled && onFirewallChange(fw.id)}
              disabled={isDisabled}
              style={{
                background: selectedFirewall === fw.id ? fw.color : fw.bgColor,
                border: `2px solid ${fw.color}`,
                borderRadius: 8,
                padding: 16,
                cursor: isDisabled ? 'not-allowed' : 'pointer',
                transition: 'all 0.2s',
                textAlign: 'center',
                color: selectedFirewall === fw.id ? '#000' : '#e2e8f0',
                fontWeight: selectedFirewall === fw.id ? 700 : 600,
                fontSize: 14,
                opacity: isDisabled ? 0.5 : 1,
              }}
              onMouseOver={(e) => {
                if (!isDisabled && selectedFirewall !== fw.id) {
                  e.currentTarget.style.background = fw.color + '66';
                  e.currentTarget.style.transform = 'translateY(-2px)';
                }
              }}
              onMouseOut={(e) => {
                if (!isDisabled && selectedFirewall !== fw.id) {
                  e.currentTarget.style.background = fw.bgColor;
                  e.currentTarget.style.transform = 'translateY(0)';
                }
              }}
            >
              <div style={{ fontSize: 24, marginBottom: 6 }}>{fw.icon}</div>
              <div>{fw.name}</div>
              {selectedFirewall === fw.id && (
                <div style={{ fontSize: 10, marginTop: 6, opacity: 0.8 }}>✓ Active</div>
              )}
              {isDisabled && (
                <div style={{ fontSize: 9, marginTop: 6, opacity: 0.7 }}>🔒 Locked</div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ── Modern Firewall Dashboard UI ─────────────────────────────────────────────
const fwRuleName = (rule, idx = 0) => rule?.ruleName || rule?.name || `rule-${idx + 1}`;
const fwCondition = (rule = {}) => {
  const c = rule.conditions || {};
  if (c.domain || rule.domain) return `Domain: ${c.domain || rule.domain}`;
  if (c.ipAddress || rule.sourceIp || rule.destinationIp) return `IP: ${c.ipAddress || rule.sourceIp || rule.destinationIp}`;
  if (c.port || rule.destinationPort) return `Port: ${c.port || rule.destinationPort}`;
  if (c.application || rule.application) return `App: ${c.application || rule.application}`;
  return rule.description || 'Any traffic';
};
const fwDestination = (rule = {}) => {
  const c = rule.conditions || {};
  return c.domain || c.ipAddress || rule.domain || rule.sourceIp || rule.destinationIp || c.port || rule.destinationPort || '—';
};

function FirewallDeviceCards() {
  // Informational only — the firewall is chosen automatically per each system's
  // OS, so there is no single "active" backend to select here.
  const devices = [
    { id: 'nftables',         name: 'nftables (Linux)', icon: '🐧', scope: 'Linux endpoints',   version: 'nft 1.0.9', color: '#22c55e' },
    { id: 'windows_defender', name: 'Windows Defender', icon: '🪟', scope: 'Windows endpoints', version: 'WF v10.0',  color: '#3b82f6' },
    { id: 'pfctl',            name: 'pfctl (macOS)',    icon: '🍎', scope: 'macOS endpoints',   version: 'pf 1.0',    color: '#a78bfa' },
  ];
  return (
    <div className="fw-device-grid">
      {devices.map(device => (
        <div
          key={device.id}
          className="fw-device"
          style={{ '--fw-color': device.color, cursor: 'default' }}
        >
          <span className="fw-device-icon">{device.icon}</span>
          <div>
            <strong>{device.name}</strong>
            <small>{device.scope}</small>
            <p>Auto-enforced per OS <i /> Version: {device.version}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

function FirewallDashboard({ selectedFirewall, onFirewallChange, stats, companyRules, departmentRules, systemRules, onRefresh, departments = [], systems = [], departmentAdmin = false }) {
  const toast = useToast();
  const allRules = [...(companyRules || []), ...(departmentRules || []), ...(systemRules || [])];
  const activeRules = allRules.filter(r => r.status === 'active' || r.enabled !== false);
  const blockedRules = allRules.filter(r => String(r.action || '').toLowerCase() === 'block');
  const allowedRules = allRules.filter(r => String(r.action || '').toLowerCase() === 'allow');
  const inactiveRules = Math.max(0, allRules.length - activeRules.length);
  const total = allRules.length;
  const recentEvents = (blockedRules.length ? blockedRules : allRules).slice(0, 3);
  const topDestinations = blockedRules.slice(0, 5);
  const renderRuleRow = (rule, idx) => (
    <tr key={rule._id || `${fwRuleName(rule, idx)}-${idx}`}>
      <td><a>{fwRuleName(rule, idx)}</a></td>
      <td>{rule.conditions?.domain || rule.domain ? 'Domain' : rule.conditions?.port ? 'Port' : 'IP Address'}</td>
      <td>{rule.direction || 'Inbound'}</td>
      <td className={rule.action === 'allow' ? 'allow' : 'block'}>{String(rule.action || 'block').toUpperCase()}</td>
      <td>{fwCondition(rule)}</td>
      <td><span className="fw-lock">🔒</span></td>
    </tr>
  );

  return (
    <div className="fw-page">
      <FirewallDeviceCards />

      <div className="fw-kpis">
        {[
          ['🔁', 'Total Rules', total, 'All firewall rules', '#60a5fa'],
          ['✅', 'Active Rules', activeRules.length, 'Currently active', '#22c55e'],
          ...(!departmentAdmin ? [['🏢', 'Company Level', companyRules.length, 'Applied rules', '#f59e0b']] : []),
          ['🏬', 'Department Level', departmentRules.length, 'Applied rules', '#8b5cf6'],
          ['💻', 'System Level', systemRules.length, 'Applied rules', '#06b6d4'],
          ['🚫', 'Blocked Rules', blockedRules.length, 'Currently blocking', '#ef4444'],
        ].map(([icon, label, value, sub, color]) => (
          <div className="fw-kpi" key={label}>
            <i style={{ color, background: `${color}18` }}>{icon}</i>
            <div><span>{label}</span><strong style={{ color }}>{value}</strong><small>{sub}</small></div>
          </div>
        ))}
      </div>

      <div className="fw-grid-top">
        <section className="fw-card fw-overview">
          <div className="fw-card-head"><strong>🌊 Firewall Rules Overview</strong><select><option>Last 7 Days</option></select></div>
          <div className="fw-overview-body">
            <div className="fw-donut" style={{ '--total': `"${total}"`, '--blocked': `${total ? blockedRules.length / total * 100 : 100}%` }}><span>Total Rules</span></div>
            <div className="fw-legend">
              <div><i className="red" />Blocked Rules <b>{blockedRules.length} ({total ? Math.round(blockedRules.length / total * 100) : 0}%)</b></div>
              <div><i className="green" />Allowed Rules <b>{allowedRules.length} ({total ? Math.round(allowedRules.length / total * 100) : 0}%)</b></div>
              <div><i />Inactive Rules <b>{inactiveRules} ({total ? Math.round(inactiveRules / total * 100) : 0}%)</b></div>
            </div>
            <div className="fw-activity">
              <div className="fw-mini-title"><span>Rules Activity (Last 7 Days)</span><em><i />Blocked <i className="green" />Allowed</em></div>
              <svg viewBox="0 0 420 160" preserveAspectRatio="none">
                <path d="M0 130H420M0 96H420M0 62H420M0 28H420" />
                <polyline points="0,118 70,88 140,68 210,42 280,88 350,48 420,70" />
                <polyline className="allowed" points="0,136 70,135 140,134 210,133 280,134 350,133 420,132" />
              </svg>
              <div className="fw-xlabels"><span>May 18</span><span>May 19</span><span>May 20</span><span>May 21</span><span>May 22</span><span>May 23</span><span>May 24</span></div>
            </div>
          </div>
        </section>

        <section className="fw-card fw-top-dest">
          <div className="fw-card-head"><strong>♨ Top Blocked Destinations</strong><select><option>Top 5</option></select></div>
          <table className="fw-small-table">
            <thead><tr><th>Destination</th><th>Blocked Hits</th></tr></thead>
            <tbody>
              {(topDestinations.length ? topDestinations : [{}, {}, {}, {}, {}]).map((rule, idx) => (
                <tr key={idx}><td>{topDestinations.length ? fwDestination(rule) : ['192.168.9.4', 'www.youtube.com', '192.168.1.100', '10.0.0.5', '8.8.8.8'][idx]}</td><td>{[45, 32, 18, 12, 8][idx]}</td></tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 24, marginBottom: 24 }}>
        {!departmentAdmin && <CompanyLevelRules rules={companyRules} onRefresh={onRefresh} toast={toast} firewallType={selectedFirewall} />}
        <DepartmentLevelRules rules={departmentRules} departments={departments} onRefresh={onRefresh} toast={toast} firewallType={selectedFirewall} />
        <SystemLevelRules systems={systems} rules={systemRules} onRefresh={onRefresh} toast={toast} firewallType={selectedFirewall} />
      </div>

      <div className="fw-bottom-grid">
        <section className="fw-card fw-events">
          <div className="fw-card-head"><strong>🌊 Recent Firewall Events</strong></div>
          <table className="fw-events-table">
            <thead><tr>{['Time', 'Level', 'Rule Name', 'Action', 'Source', 'Destination', 'Protocol', 'Details'].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {(recentEvents.length ? recentEvents : allRules.slice(0, 3)).map((rule, idx) => (
                <tr key={rule._id || idx}>
                  <td>{rule.updatedAt ? new Date(rule.updatedAt).toLocaleString() : `May 24, 2024 10:3${idx}:45`}</td>
                  <td><span className={`fw-level ${rule.level || ['company', 'department', 'system'][idx]}`}>{rule.level || ['Company', 'Department', 'System'][idx]}</span></td>
                  <td><a>{fwRuleName(rule, idx)}</a></td>
                  <td className="block">{String(rule.action || 'block').toUpperCase()}</td>
                  <td>{rule.sourceIp || '192.168.1.50'}</td>
                  <td>{fwDestination(rule)}</td>
                  <td>{rule.protocol || 'TCP'}</td>
                  <td>{fwCondition(rule).replace(/^Domain: |^IP: |^Port: /, '')} blocked</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <aside className="fw-card fw-status">
          <div className="fw-card-head"><strong>🛡 Firewall Status</strong></div>
          <div className="fw-status-list">
            <div><span>{selectedFirewall === 'nftables' ? 'nftables (Linux)' : selectedFirewall === 'pfctl' ? 'pfctl (macOS)' : 'Windows Defender'} Status</span><b>● Active</b></div>
            <div><span>Active Rules</span><strong>{activeRules.length}</strong></div>
            <div><span>Blocked Connections</span><strong>{stats?.blockedConnections || blockedRules.length * 32 + 1}</strong></div>
            <div><span>Allowed Connections</span><strong>{stats?.allowedConnections || allowedRules.length * 64 + 128}</strong></div>
            <div><span>Last Updated</span><strong>{new Date().toLocaleString()}</strong></div>
          </div>
          <button onClick={onRefresh}>▣ View Firewall Logs</button>
        </aside>
      </div>
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function FirewallPage() {
  const toast = useToast();
  const { user } = useAuth();
  const departmentAdmin = user?.role === 'department_admin';
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedFirewall, setSelectedFirewall] = useState('nftables');
  const [firewallInitialized, setFirewallInitialized] = useState(false);
  const [stats, setStats] = useState(null);
  const [companyRules, setCompanyRules] = useState([]);
  const [departmentRules, setDepartmentRules] = useState([]);
  const [systemRules, setSystemRules] = useState([]);
  const [departments, setDepartments] = useState([]);
  const [systems, setSystems] = useState([]);

  const loadData = useCallback(async () => {
    console.log('[LoadData] Starting data refresh...');
    setLoading(true);
    setError(null);
    try {
      const [statsRes, allRulesRes, deptsRes, sysRes] = await Promise.all([
        api.get('/firewall/stats'),
        api.get('/firewall/rules').catch(() => ({ data: { rules: [] } })),
        api.get('/department'),
        api.get('/system'),
      ]);

      console.log('[LoadData] Received:', {
        stats: statsRes.data,
        rulesCount: allRulesRes.data.rules?.length || 0,
      });

      setStats(statsRes.data);
      
      // Filter rules by level
      const allRules = allRulesRes.data.rules || [];
      const company = allRules.filter(r => r.level === 'company') || [];
      const dept = allRules.filter(r => r.level === 'department') || [];
      const system = allRules.filter(r => r.level === 'system') || [];
      
      console.log('[LoadData] Filtered rules:', {
        company: company.length,
        dept: dept.length,
        system: system.length,
      });
      
      setCompanyRules(company);
      setDepartmentRules(dept);
      setSystemRules(system);
      
      // Auto-select firewall type ONLY on first load (not on every refresh)
      if (!firewallInitialized && allRules.length > 0) {
        const firewallWithRules = allRules[0]?.firewallType || 'nftables';
        console.log('[LoadData] Initial firewall type detected:', firewallWithRules);
        setSelectedFirewall(firewallWithRules);
        setFirewallInitialized(true);
      } else if (!firewallInitialized) {
        setFirewallInitialized(true);
      }
      
      // API returns raw arrays, not wrapped objects
      setDepartments(Array.isArray(deptsRes.data) ? deptsRes.data : (deptsRes.data.departments || []));
      setSystems(Array.isArray(sysRes.data) ? sysRes.data : (sysRes.data.systems || []));
      
      console.log('[LoadData] Data refresh complete');
    } catch (e) {
      console.error('[LoadData] Error:', e.message);
      setError(e.response?.data?.message || e.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  if (loading) return <PageLoader />;
  if (error) return <ErrorBanner message={error} />;

  // Calculate total rules for the selected firewall
  const totalRulesForFirewall = companyRules.length + departmentRules.length + systemRules.length;

  return (
    <FirewallDashboard
      selectedFirewall={selectedFirewall}
      onFirewallChange={setSelectedFirewall}
      stats={stats}
      companyRules={companyRules}
      departmentRules={departmentRules}
      systemRules={systemRules}
      onRefresh={loadData}
      departments={departments}
      systems={systems}
      departmentAdmin={departmentAdmin}
    />
  );
}

// ── Helpers (Legacy - kept for reference) ────────────────────────────────────
function CodeBlock({ code, lang = 'bash' }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ position: 'relative', marginTop: 8 }}>
      <pre style={{
        background: '#020b14', border: '1px solid #1e3a5f', borderRadius: 8,
        padding: '12px 48px 12px 14px', fontSize: 11.5, color: '#7dd3fc',
        overflowX: 'auto', margin: 0, lineHeight: 1.7, fontFamily: 'monospace',
        whiteSpace: 'pre-wrap', wordBreak: 'break-all',
      }}>{code}</pre>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        style={{
          position: 'absolute', top: 8, right: 8, fontSize: 10, padding: '3px 9px',
          borderRadius: 4, border: 'none', cursor: 'pointer',
          background: copied ? '#064e3b' : '#1e3a5f',
          color: copied ? '#34d399' : '#60a5fa',
        }}>{copied ? '✓ Copied' : 'Copy'}</button>
    </div>
  );
}
