import React, { useEffect, useState, useCallback } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';

// ── Palette ────────────────────────────────────────────────────────────────────
const SCORE_COLOR = s =>
  s >= 80 ? '#22c55e' : s >= 60 ? '#f59e0b' : s >= 40 ? '#f97316' : '#ef4444';

const STATUS_META = {
  compliant:     { color: '#22c55e', bg: '#14532d22', label: 'COMPLIANT',     icon: '✅' },
  partial:       { color: '#f59e0b', bg: '#78350f22', label: 'PARTIAL',       icon: '⚠️' },
  non_compliant: { color: '#ef4444', bg: '#7f1d1d22', label: 'NON-COMPLIANT', icon: '❌' },
};

// ── Score Ring ─────────────────────────────────────────────────────────────────
function ScoreRing({ score = 0 }) {
  const r = 54, circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color  = SCORE_COLOR(score);
  return (
    <svg width="140" height="140" viewBox="0 0 140 140">
      <circle cx="70" cy="70" r={r} fill="none" stroke="#1e3a5f" strokeWidth="12" />
      <circle cx="70" cy="70" r={r} fill="none" stroke={color} strokeWidth="12"
        strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round" transform="rotate(-90 70 70)"
        style={{ transition: 'stroke-dashoffset 1s ease' }} />
      <text x="70" y="65" textAnchor="middle" fill={color} fontSize="26" fontWeight="700">{score}</text>
      <text x="70" y="85" textAnchor="middle" fill="#64748b" fontSize="11">/100</text>
    </svg>
  );
}

// ── Framework Card ─────────────────────────────────────────────────────────────
function FrameworkCard({ fw, onClick }) {
  const meta = STATUS_META[fw.status] || STATUS_META.partial;
  return (
    <div onClick={onClick} style={{
      background: '#0c1a2e', border: `1px solid ${meta.color}44`,
      borderRadius: 10, padding: '16px 18px', cursor: 'pointer', flex: '1', minWidth: 200,
      transition: 'box-shadow .2s, border-color .2s',
    }}
      onMouseEnter={e => e.currentTarget.style.boxShadow = `0 0 20px ${meta.color}33`}
      onMouseLeave={e => e.currentTarget.style.boxShadow = 'none'}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
        <span style={{ fontSize: 13, color: '#93c5fd', fontWeight: 600 }}>{fw.name?.replace('_', ' ')}</span>
        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 20, fontWeight: 700,
          background: meta.bg, color: meta.color, border: `1px solid ${meta.color}44` }}>
          {meta.icon} {meta.label}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ fontSize: 36, fontWeight: 700, color: SCORE_COLOR(fw.overallScore || 0) }}>
          {fw.overallScore || 0}%
        </div>
        <div style={{ fontSize: 11, color: '#64748b', lineHeight: '20px' }}>
          <div style={{ color: '#22c55e' }}>✓ Pass: {fw.passCount || 0}</div>
          <div style={{ color: '#ef4444' }}>✗ Fail: {fw.failCount || 0}</div>
          <div style={{ color: '#f59e0b' }}>◑ Partial: {fw.partialCount || 0}</div>
        </div>
      </div>
      <div style={{ marginTop: 10 }}>
        <div style={{ height: 6, background: '#1e3a5f', borderRadius: 3, overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${fw.overallScore || 0}%`,
            background: SCORE_COLOR(fw.overallScore || 0), borderRadius: 3,
            transition: 'width 1s ease' }} />
        </div>
      </div>
      <div style={{ marginTop: 8, fontSize: 10, color: '#1e40af' }}>Click to view controls →</div>
    </div>
  );
}

// ── Controls Modal ─────────────────────────────────────────────────────────────
function ControlsModal({ fw, onClose }) {
  if (!fw) return null;
  const statusIcon = { pass: '✅', fail: '❌', partial: '⚠️', na: '—' };
  const statusColor = { pass: '#22c55e', fail: '#ef4444', partial: '#f59e0b', na: '#64748b' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.8)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12,
        width: 'min(860px, 96vw)', maxHeight: '88vh', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '16px 22px', borderBottom: '1px solid #1e3a5f' }}>
          <div>
            <h3 style={{ margin: 0, color: '#e0f2fe', fontSize: 16 }}>{fw.name?.replace('_', ' ')} Controls</h3>
            <div style={{ fontSize: 11, color: '#1e40af', marginTop: 3 }}>
              Overall Score: <span style={{ color: SCORE_COLOR(fw.overallScore || 0), fontWeight: 700 }}>{fw.overallScore}%</span>
              &nbsp;·&nbsp; Pass: {fw.passCount} &nbsp;·&nbsp; Fail: {fw.failCount} &nbsp;·&nbsp; Partial: {fw.partialCount}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 22, cursor: 'pointer' }}>✕</button>
        </div>
        <div style={{ overflowY: 'auto', padding: 20 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
                {['ID', 'Control Name', 'Status', 'Score', 'Evidence'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '8px 12px', color: '#1e40af', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(fw.controls || []).map((c, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #060e1a' }}>
                  <td style={{ padding: '9px 12px', color: '#93c5fd', fontFamily: 'monospace', fontSize: 11 }}>{c.id}</td>
                  <td style={{ padding: '9px 12px', color: '#e2e8f0', maxWidth: 240 }}>{c.name}</td>
                  <td style={{ padding: '9px 12px' }}>
                    <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 20, fontWeight: 600,
                      color: statusColor[c.status] || '#64748b',
                      background: `${statusColor[c.status] || '#64748b'}18`,
                      border: `1px solid ${statusColor[c.status] || '#64748b'}44` }}>
                      {statusIcon[c.status] || '—'} {(c.status || 'na').toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '9px 12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ color: SCORE_COLOR(c.score || 0), fontWeight: 700 }}>{c.score ?? '—'}{c.score != null ? '%' : ''}</span>
                      <div style={{ width: 60, height: 4, background: '#1e3a5f', borderRadius: 2 }}>
                        <div style={{ height: '100%', width: `${c.score || 0}%`,
                          background: SCORE_COLOR(c.score || 0), borderRadius: 2 }} />
                      </div>
                    </div>
                  </td>
                  <td style={{ padding: '9px 12px', color: '#64748b', fontSize: 11, maxWidth: 280 }}>{c.evidence || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Score Breakdown Table ──────────────────────────────────────────────────────
function ScoreBreakdown({ breakdown, deductions }) {
  if (!breakdown) return null;
  const rows = [
    { label: 'File Violations',     key: 'fileViolations',    icon: '📁' },
    { label: 'USB Violations',      key: 'usbViolations',     icon: '🔌' },
    { label: 'Network Attacks',     key: 'networkAttacks',    icon: '🌐' },
    { label: 'Malware Events',      key: 'malwareEvents',     icon: '🦠' },
    { label: 'Login Failures',      key: 'loginFailures',     icon: '🔐' },
    { label: 'Unresolved Critical', key: 'unresolvedCritical',icon: '🚨' },
  ];
  return (
    <div style={{ background: '#060e1a', borderRadius: 10, padding: '16px 20px', border: '1px solid #1e3a5f' }}>
      <h4 style={{ margin: '0 0 12px', color: '#93c5fd', fontSize: 13 }}>Score Deductions (Logarithmic)</h4>
      <div style={{ fontSize: 10, color: '#64748b', marginBottom: 10 }}>
        Formula: min(cap, weight × log₂(1 + count)) — gradual scaling
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
            {['Category', 'Count', 'Deduction'].map(h => (
              <th key={h} style={{ textAlign: 'left', padding: '6px 8px', color: '#1e40af' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map(r => {
            const count     = breakdown[r.key] || 0;
            const deduction = deductions?.[r.key] || 0;
            return (
              <tr key={r.key} style={{ borderBottom: '1px solid #060e1a' }}>
                <td style={{ padding: '7px 8px', color: '#e2e8f0' }}>{r.icon} {r.label}</td>
                <td style={{ padding: '7px 8px', color: count > 0 ? '#f87171' : '#34d399', fontWeight: 700 }}>{count}</td>
                <td style={{ padding: '7px 8px', color: deduction > 0 ? '#f87171' : '#34d399', fontWeight: 700 }}>
                  {deduction > 0 ? `-${deduction}` : '0'}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}


// ── Main Page ──────────────────────────────────────────────────────────────────
export default function CompliancePage() {
  const { company } = useAuth();
  const [frameworks, setFrameworks] = useState([]);
  const [score,      setScore]      = useState(null);
  const [scoreData,  setScoreData]  = useState(null);
  const [report,     setReport]     = useState(null);
  const [history,    setHistory]    = useState([]);
  const [loading,    setLoading]    = useState(true);
  const [generating, setGenerating] = useState(false);
  const [selectedFw, setSelectedFw] = useState(null);
  const [activeTab,  setActiveTab]  = useState('overview');
  const [error,      setError]      = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [fwRes, scoreRes, histRes] = await Promise.all([
        api.get('/compliance/frameworks'),
        api.get('/compliance/score'),
        api.get('/compliance/history?limit=10'),
      ]);
      setFrameworks(fwRes.data.frameworks || []);
      setScore(fwRes.data.securityScore);
      setReport({ id: fwRes.data.reportId, generatedAt: fwRes.data.generatedAt });
      setScoreData(scoreRes.data);
      setHistory(histRes.data.reports || []);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load compliance data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const generate = async () => {
    setGenerating(true);
    try {
      await api.post('/compliance/generate', {
        reportType: 'manual',
        frameworks: ['ISO_27001', 'PCI_DSS', 'GDPR', 'HIPAA'],
      });
      await loadData();
    } catch (err) {
      alert(err.response?.data?.message || 'Generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const downloadReport = async (reportId, fmt) => {
    try {
      const res = await api.get(`/compliance/${fmt}/${reportId}`, { responseType: 'blob' });
      const ext = fmt === 'csv' ? 'csv' : 'html';
      const url = URL.createObjectURL(new Blob([res.data], { type: fmt === 'csv' ? 'text/csv' : 'text/html' }));
      const a = document.createElement('a'); a.href = url;
      a.download = `compliance_report_${new Date().toISOString().slice(0,10)}.${ext}`;
      a.click(); URL.revokeObjectURL(url);
    } catch { alert('Download failed'); }
  };

  const tabs = ['overview', 'frameworks', 'history'];

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, color: '#1e40af' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 32, marginBottom: 10 }}>🛡️</div>
        <div>Loading compliance data…</div>
      </div>
    </div>
  );

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 22, color: '#e0f2fe' }}>🛡️ Compliance & Security</h2>
          <div style={{ fontSize: 12, color: '#1e40af', marginTop: 4 }}>
            ISO 27001 · PCI-DSS · GDPR · HIPAA · Auto-generated reports
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={loadData} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 6,
            border: '1px solid #1e3a5f', background: 'none', color: '#60a5fa', cursor: 'pointer' }}>
            ↺ Refresh
          </button>
          <button onClick={generate} disabled={generating} style={{
            fontSize: 11, padding: '6px 16px', borderRadius: 6, cursor: 'pointer',
            background: generating ? '#1e3a5f' : '#1d4ed8', border: 'none', color: '#fff', fontWeight: 600,
          }}>
            {generating ? '⏳ Generating…' : '⚡ Generate Report'}
          </button>
          {report?.id && (
            <>
              <button onClick={() => downloadReport(report.id, 'pdf')} style={{ fontSize: 11, padding: '6px 12px',
                borderRadius: 6, border: '1px solid #1e3a5f', background: 'none', color: '#93c5fd', cursor: 'pointer' }}>
                ⬇ PDF
              </button>
              <button onClick={() => downloadReport(report.id, 'csv')} style={{ fontSize: 11, padding: '6px 12px',
                borderRadius: 6, border: '1px solid #1e3a5f', background: 'none', color: '#86efac', cursor: 'pointer' }}>
                ⬇ CSV
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '10px 14px',
          borderRadius: 6, marginBottom: 16, fontSize: 13 }}>⚠ {error}</div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid #1e3a5f' }}>
        {tabs.map(t => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: '9px 18px', fontSize: 12, cursor: 'pointer', border: 'none',
            background: 'none', fontWeight: activeTab === t ? 700 : 400,
            color: activeTab === t ? '#60a5fa' : '#64748b',
            borderBottom: activeTab === t ? '2px solid #3b82f6' : '2px solid transparent',
            marginBottom: -1, textTransform: 'capitalize',
          }}>{t}</button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <>
          {/* Score + Breakdown */}
          <div style={{ display: 'flex', gap: 16, marginBottom: 20, flexWrap: 'wrap', alignItems: 'flex-start' }}>
            <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12,
              padding: '24px 28px', display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 200 }}>
              <div style={{ fontSize: 13, color: '#1e40af', marginBottom: 12, fontWeight: 600 }}>Security Score</div>
              <ScoreRing score={scoreData?.score ?? score ?? 0} />
              <div style={{ marginTop: 12, fontSize: 12, fontWeight: 700,
                color: SCORE_COLOR(scoreData?.score ?? score ?? 0) }}>
                {(scoreData?.score ?? score ?? 0) >= 80 ? '✅ GOOD' : (scoreData?.score ?? score ?? 0) >= 60 ? '⚠️ NEEDS ATTENTION' : '🔴 CRITICAL'}
              </div>
              {report?.generatedAt && (
                <div style={{ fontSize: 10, color: '#64748b', marginTop: 8 }}>
                  Last generated: {new Date(report.generatedAt).toLocaleString()}
                </div>
              )}
            </div>
            <div style={{ flex: 1, minWidth: 240 }}>
              <ScoreBreakdown breakdown={scoreData?.breakdown} deductions={scoreData?.deductions} />
            </div>
          </div>

          {/* Framework overview cards */}
          {frameworks.length === 0 ? (
            <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10,
              padding: '32px', textAlign: 'center', color: '#1e40af', fontSize: 14 }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>📊</div>
              <div>No compliance report generated yet.</div>
              <div style={{ fontSize: 12, color: '#64748b', marginTop: 8 }}>
                Click <strong style={{ color: '#60a5fa' }}>Generate Report</strong> to run a full compliance assessment.
              </div>
            </div>
          ) : (
            <div>
              <div style={{ fontSize: 12, color: '#1e40af', marginBottom: 10, fontWeight: 600 }}>
                Framework Compliance Status
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                {frameworks.map(fw => (
                  <FrameworkCard key={fw.name} fw={fw} onClick={() => setSelectedFw(fw)} />
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Frameworks Tab (full controls) */}
      {activeTab === 'frameworks' && (
        <div>
          {frameworks.length === 0 ? (
            <div style={{ color: '#1e40af', textAlign: 'center', padding: 40, fontSize: 14 }}>
              Generate a compliance report first.
            </div>
          ) : (
            frameworks.map(fw => {
              const statusIcon = { pass: '✅', fail: '❌', partial: '⚠️', na: '—' };
              const statusColor = { pass: '#22c55e', fail: '#ef4444', partial: '#f59e0b', na: '#64748b' };
              const meta = STATUS_META[fw.status] || STATUS_META.partial;
              return (
                <div key={fw.name} style={{ background: '#0c1a2e', border: `1px solid ${meta.color}33`,
                  borderRadius: 10, marginBottom: 16, overflow: 'hidden' }}>
                  <div style={{ padding: '14px 18px', borderBottom: '1px solid #1e3a5f',
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <span style={{ fontWeight: 700, color: '#93c5fd', fontSize: 14 }}>{fw.name?.replace('_', ' ')}</span>
                      <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 20, fontWeight: 600,
                        color: meta.color, background: meta.bg, border: `1px solid ${meta.color}44` }}>
                        {meta.icon} {meta.label}
                      </span>
                    </div>
                    <span style={{ fontSize: 22, fontWeight: 700, color: SCORE_COLOR(fw.overallScore || 0) }}>
                      {fw.overallScore || 0}%
                    </span>
                  </div>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid #1e3a5f', background: '#060e1a' }}>
                        {['ID', 'Control Name', 'Status', 'Score', 'Evidence'].map(h => (
                          <th key={h} style={{ textAlign: 'left', padding: '8px 14px', color: '#1e40af', fontWeight: 600 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(fw.controls || []).map((c, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid #060e1a' }}>
                          <td style={{ padding: '9px 14px', color: '#93c5fd', fontFamily: 'monospace', fontSize: 11 }}>{c.id}</td>
                          <td style={{ padding: '9px 14px', color: '#e2e8f0' }}>{c.name}</td>
                          <td style={{ padding: '9px 14px' }}>
                            <span style={{ color: statusColor[c.status] || '#64748b', fontWeight: 600 }}>
                              {statusIcon[c.status] || '—'} {(c.status || 'na').toUpperCase()}
                            </span>
                          </td>
                          <td style={{ padding: '9px 14px', color: SCORE_COLOR(c.score || 0), fontWeight: 700 }}>
                            {c.score != null ? `${c.score}%` : '—'}
                          </td>
                          <td style={{ padding: '9px 14px', color: '#64748b', fontSize: 11 }}>{c.evidence || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div>
          {history.length === 0 ? (
            <div style={{ color: '#1e40af', textAlign: 'center', padding: 40, fontSize: 14 }}>
              No compliance reports generated yet.
            </div>
          ) : (
            history.map((r, i) => {
              const bestFw    = (r.frameworks || []).sort((a, b) => b.overallScore - a.overallScore)[0];
              const worstFw   = (r.frameworks || []).sort((a, b) => a.overallScore - b.overallScore)[0];
              return (
                <div key={i} style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10,
                  padding: '14px 18px', marginBottom: 10,
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 13, color: '#e2e8f0', fontWeight: 600 }}>
                      {r.reportType?.toUpperCase()} Report
                    </div>
                    <div style={{ fontSize: 11, color: '#1e40af', marginTop: 2 }}>
                      {new Date(r.periodStart).toLocaleDateString()} → {new Date(r.periodEnd).toLocaleDateString()}
                      &nbsp;·&nbsp;Generated: {new Date(r.createdAt).toLocaleString()}
                    </div>
                    {bestFw && (
                      <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                        Best: <span style={{ color: '#22c55e' }}>{bestFw.name?.replace('_',' ')} {bestFw.overallScore}%</span>
                        &nbsp;·&nbsp; Worst: <span style={{ color: '#f87171' }}>{worstFw?.name?.replace('_',' ')} {worstFw?.overallScore}%</span>
                      </div>
                    )}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ fontSize: 28, fontWeight: 700, color: SCORE_COLOR(r.securityScore || 0) }}>
                      {r.securityScore || 0}
                      <span style={{ fontSize: 12, color: '#64748b' }}>/100</span>
                    </div>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => downloadReport(r._id, 'pdf')} style={{ fontSize: 10, padding: '4px 10px',
                        borderRadius: 4, border: '1px solid #1e3a5f', background: 'none',
                        color: '#93c5fd', cursor: 'pointer' }}>⬇ PDF</button>
                      <button onClick={() => downloadReport(r._id, 'csv')} style={{ fontSize: 10, padding: '4px 10px',
                        borderRadius: 4, border: '1px solid #1e3a5f', background: 'none',
                        color: '#86efac', cursor: 'pointer' }}>⬇ CSV</button>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Controls Modal */}
      {selectedFw && <ControlsModal fw={selectedFw} onClose={() => setSelectedFw(null)} />}
    </div>
  );
}
