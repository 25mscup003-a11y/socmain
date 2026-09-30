import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import api from '../../../api/axios';
import { useAuth } from '../../../context/AuthContext';

export default function AlertDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  
  const [alert, setAlert] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('overview');

  // AI Analysis States
  const [aiReport, setAiReport] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState('');

  // Forensics States
  const [forensicLoading, setForensicLoading] = useState(false);
  const [forensicSuccess, setForensicSuccess] = useState('');
  const [forensicError, setForensicError] = useState('');
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.System.Processes');
  const [huntName, setHuntName] = useState('Alert Forensic Investigation');
  const [recentHunts, setRecentHunts] = useState([]);

  // Notes States
  const [noteText, setNoteText] = useState('');
  const [noteLoading, setNoteLoading] = useState(false);

  // Load Alert Details
  const loadAlert = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.get(`/alerts/${id}`);
      setAlert(res.data);
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load alert details');
    } finally {
      setLoading(false);
    }
  }, [id]);

  // Load Latest AI Report
  const loadAiReport = useCallback(async () => {
    try {
      const res = await api.get(`/ai/alerts/${id}/latest`);
      if (res.data) {
        setAiReport(res.data);
      }
    } catch (err) {
      console.warn('Failed to load latest AI report:', err.message);
    }
  }, [id]);

  // Load Recent Hunts for this system
  const loadRecentHunts = useCallback(async () => {
    if (!alert?.companyId || !alert?.systemId?._id) return;
    try {
      const res = await api.get('/forensics/dashboard', {
        params: { companyId: alert.companyId }
      });
      const hunts = res.data?.hunts || [];
      // Filter hunts belonging to this system
      const systemHunts = hunts.filter(
        h => String(h.systemId?._id || h.systemId) === String(alert.systemId?._id)
      );
      setRecentHunts(systemHunts);
    } catch (err) {
      console.warn('Failed to load recent forensics hunts:', err.message);
    }
  }, [alert]);

  useEffect(() => {
    loadAlert();
  }, [loadAlert]);

  useEffect(() => {
    if (alert) {
      loadAiReport();
      loadRecentHunts();
    }
  }, [alert, loadAiReport, loadRecentHunts]);

  // Trigger AI Analysis
  const runAiAnalysis = async () => {
    setAiLoading(true);
    setAiError('');
    try {
      const res = await api.post(`/ai/alerts/${id}/analyze`, {
        companyId: alert.companyId,
        force: true
      });
      const jobId = res.data?.job?._id;
      if (jobId) {
        // Poll for completion
        let attempts = 0;
        const interval = setInterval(async () => {
          attempts++;
          try {
            const check = await api.get(`/ai/jobs/${jobId}`);
            if (check.data.status === 'completed') {
              clearInterval(interval);
              setAiReport(check.data);
              setAiLoading(false);
            } else if (check.data.status === 'failed') {
              clearInterval(interval);
              setAiError(check.data.error || 'AI analysis job failed.');
              setAiLoading(false);
            }
          } catch (e) {
            clearInterval(interval);
            setAiError('Failed checking AI analysis status.');
            setAiLoading(false);
          }
          if (attempts > 30) {
            clearInterval(interval);
            setAiError('AI analysis request timed out.');
            setAiLoading(false);
          }
        }, 2000);
      } else {
        setAiLoading(false);
        loadAiReport();
      }
    } catch (err) {
      setAiError(err.response?.data?.message || 'Failed to request AI analysis');
      setAiLoading(false);
    }
  };

  // Launch Forensic Hunt
  const runForensicHunt = async (e) => {
    e.preventDefault();
    setForensicLoading(true);
    setForensicError('');
    setForensicSuccess('');
    try {
      const payload = {
        name: huntName,
        artifactName: selectedArtifact,
        systemId: alert.systemId?._id,
        companyId: alert.companyId,
      };
      await api.post('/forensics/hunts', payload);
      setForensicSuccess('Forensic hunt launched successfully! Collecting evidence in background.');
      loadRecentHunts();
    } catch (err) {
      setForensicError(err.response?.data?.message || 'Failed to start forensic hunt');
    } finally {
      setForensicLoading(false);
    }
  };

  // Update Alert Status
  const updateAlertStatus = async (statusAction) => {
    try {
      setError('');
      await api.post(`/soc-dashboard/alerts/${id}/action`, { action: statusAction });
      loadAlert();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update alert status');
    }
  };

  // Add Note
  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!noteText.trim()) return;
    setNoteLoading(true);
    try {
      await api.post(`/soc-dashboard/alerts/${id}/action`, { action: 'note', note: noteText });
      setNoteText('');
      loadAlert();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to add note');
    } finally {
      setNoteLoading(false);
    }
  };

  if (loading) {
    return <div style={container}><div style={loadingText}>Loading alert details...</div></div>;
  }

  if (error || !alert) {
    return (
      <div style={container}>
        <div style={errorBox}>{error || 'Alert not found.'}</div>
        <button onClick={() => navigate(-1)} style={btn}>Back to Queue</button>
      </div>
    );
  }

  const prefix = {
    soc_manager: '/soc-manager',
    l1_analyst: '/l1',
    l2_analyst: '/l2',
    l3_analyst: '/l3'
  }[user?.role] || '/l1';

  const severityColor = { critical: '#fb7185', high: '#fb923c', medium: '#facc15', low: '#38bdf8' };

  return (
    <div style={container}>
      {/* Header section */}
      <div style={header}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <button onClick={() => navigate(-1)} style={backBtn}>&larr; Back</button>
            <h1 style={titleStyle}>{alert.signatureName || alert.ruleId || alert.eventId}</h1>
            <span style={{ ...badge, background: severityColor[alert.severity] + '20', color: severityColor[alert.severity], border: `1px solid ${severityColor[alert.severity]}` }}>
              {alert.severity?.toUpperCase()}
            </span>
            <span style={{ ...badge, background: '#0e243a', color: '#60a5fa', border: '1px solid #1d4ed8' }}>
              {alert.status?.toUpperCase()}
            </span>
          </div>

          <div style={{ display: 'flex', gap: 8 }}>
            {alert.status === 'open' && (
              <button onClick={() => updateAlertStatus('acknowledge')} style={actionButton}>Acknowledge</button>
            )}
            {['open', 'investigating'].includes(alert.status) && (
              <>
                <button onClick={() => updateAlertStatus('false_positive')} style={{ ...actionButton, background: '#7f1d1d', borderColor: '#b91c1c', color: '#fca5a5' }}>False Positive</button>
                <button onClick={() => updateAlertStatus('resolve')} style={{ ...actionButton, background: '#064e3b', borderColor: '#047857', color: '#6ee7b7' }}>Resolve Alert</button>
              </>
            )}
            {['resolved', 'false_positive'].includes(alert.status) && (
              <button onClick={() => updateAlertStatus('investigate')} style={actionButton}>Re-open Alert</button>
            )}
          </div>
        </div>
        <div style={headerMeta}>
          <span><b>Company:</b> {alert.companyId?.name || 'Unknown'}</span>
          <span><b>Host:</b> {alert.systemId?.hostname || alert.agentName || 'Endpoint'}</span>
          <span><b>Time:</b> {new Date(alert.createdAt).toLocaleString()}</span>
        </div>
      </div>

      {/* Tabs */}
      <div style={tabContainer}>
        <button onClick={() => setActiveTab('overview')} style={activeTab === 'overview' ? activeTabStyle : tabStyle}>
          Alert Overview
        </button>
      </div>

      {/* Tab content area */}
      <div style={tabContent}>
        {activeTab === 'overview' && (
          <>
            <div style={contentGrid}>
            <div style={card}>
              <h3 style={cardTitle}>Details Information</h3>
              <div style={detailList}>
                <div style={detailRow}>
                  <span style={detailLabel}>Signature / Rule:</span>
                  <span style={detailValue}>{alert.ruleId || 'N/A'}</span>
                </div>
                <div style={detailRow}>
                  <span style={detailLabel}>Description:</span>
                  <span style={detailValue}>{alert.description || 'No description provided.'}</span>
                </div>
                <div style={detailRow}>
                  <span style={detailLabel}>Event Category:</span>
                  <span style={detailValue}>{alert.eventCategory || 'system'}</span>
                </div>
                <div style={detailRow}>
                  <span style={detailLabel}>Assigned Analyst:</span>
                  <span style={detailValue}>{alert.assignedTo?.name || 'Unassigned'}</span>
                </div>
                <div style={detailRow}>
                  <span style={detailLabel}>Source:</span>
                  <span style={detailValue}>{alert.source || 'agent'}</span>
                </div>
                <div style={detailRow}>
                  <span style={detailLabel}>Source IP Address:</span>
                  <span style={detailValue}>{alert.srcip || '—'}</span>
                </div>
                {alert.filePath && (
                  <div style={detailRow}>
                    <span style={detailLabel}>File Path:</span>
                    <span style={detailValue}>{alert.filePath}</span>
                  </div>
                )}
                {alert.processName && (
                  <div style={detailRow}>
                    <span style={detailLabel}>Trigger Process:</span>
                    <span style={detailValue}>{alert.processName} (PID: {alert.pid})</span>
                  </div>
                )}
              </div>
            </div>

            <div style={card}>
              <h3 style={cardTitle}>Raw JSON Log Data</h3>
              <pre style={rawJson}>
                {JSON.stringify(alert.rawEvent || alert, null, 2)}
              </pre>
            </div>
          </div>
          

        </>
      )}


      </div>
    </div>
  );
}

// Styling tokens
const container = { padding: 20, background: '#070e17', minHeight: '85vh', color: '#f1f5f9' };
const header = { padding: 20, background: '#0c192c', border: '1px solid #1e3a5f', borderRadius: 12, marginBottom: 20 };
const titleStyle = { margin: 0, fontSize: 24, fontWeight: 700, color: '#f8fafc' };
const backBtn = { padding: '6px 12px', border: '1px solid #334155', background: 'transparent', color: '#cbd5e1', borderRadius: 6, cursor: 'pointer', fontSize: 12, fontWeight: 600 };
const headerMeta = { display: 'flex', gap: 20, marginTop: 14, fontSize: 13, color: '#94a3b8' };

const tabContainer = { display: 'flex', gap: 10, borderBottom: '1px solid #1e3a5f', marginBottom: 20 };
const tabStyle = { padding: '10px 16px', background: 'transparent', border: 0, color: '#94a3b8', cursor: 'pointer', fontSize: 13, fontWeight: 600 };
const activeTabStyle = { padding: '10px 16px', background: 'transparent', border: 0, borderBottom: '2px solid #2563eb', color: '#38bdf8', cursor: 'pointer', fontSize: 13, fontWeight: 700 };
const tabContent = { animation: 'fadeIn 0.2s ease-in-out' };

const contentGrid = { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20 };
const card = { background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, padding: 20, position: 'relative' };
const cardTitle = { margin: '0 0 16px 0', fontSize: 16, color: '#7dd3fc', fontWeight: 700 };

const detailList = { display: 'flex', flexDirection: 'column', gap: 10 };
const detailRow = { display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #152e4d', paddingBottom: 8, fontSize: 13 };
const detailLabel = { color: '#94a3b8', fontWeight: 500 };
const detailValue = { color: '#cbd5e1', textAlign: 'right', maxWidth: '70%' };

const rawJson = { background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 12, fontSize: 11, fontFamily: 'monospace', maxHeight: 380, overflow: 'auto', color: '#34d399' };

const glowGradiant = { position: 'absolute', top: 0, right: 0, width: '25%', height: '100%', background: 'linear-gradient(90deg, transparent, rgba(37,99,235,0.05))', pointerEvents: 'none' };
const reportContainer = { display: 'flex', flexDirection: 'column', gap: 16, marginTop: 12, borderTop: '1px solid #1e3a5f', paddingTop: 16 };
const reportMetaHeader = { display: 'flex', gap: 16, flexWrap: 'wrap' };
const metaCard = { background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: '10px 16px', minWidth: 120, display: 'flex', flexDirection: 'column', gap: 4 };
const metaLabel = { fontSize: 11, color: '#64748b' };
const metaVal = { fontSize: 15, fontWeight: 'bold', color: '#e2e8f0' };

const sectionBox = { background: '#071222', border: '1px solid #152d4b', borderRadius: 8, padding: 14 };
const sectionHeader = { margin: '0 0 8px 0', fontSize: 13, color: '#38bdf8', fontWeight: 700 };
const paragraph = { margin: 0, fontSize: 13, color: '#cbd5e1', lineHeight: 1.5 };
const list = { margin: 0, paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 6 };
const listItem = { fontSize: 13, color: '#cbd5e1' };
const codeBlock = { fontFamily: 'monospace', background: '#060e1a', padding: '2px 6px', borderRadius: 4, color: '#fca5a5' };
const numberedList = { margin: 0, paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 8 };
const numberedListItem = { fontSize: 13, color: '#cbd5e1', lineHeight: 1.4 };

const huntItem = { background: '#060e1a', border: '1px solid #152d4b', borderRadius: 8, padding: 10 };
const navLink = { display: 'block', fontSize: 11, color: '#38bdf8', textDecoration: 'none', marginTop: 8, fontWeight: 600 };

const label = { display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 4 };
const inputStyle = { width: '100%', boxSizing: 'border-box', border: '1px solid #1e3a5f', background: '#060e1a', color: '#e2e8f0', borderRadius: 7, padding: 9, fontSize: 12 };
const badge = { padding: '4px 8px', borderRadius: 6, fontSize: 11, fontWeight: 700 };
const loadingText = { color: '#94a3b8', fontSize: 14, textAlign: 'center', padding: 40 };

const errorBox = { padding: 12, background: '#350d16', color: '#fca5a5', borderRadius: 7, fontSize: 12 };
const successBox = { padding: 12, background: '#064e3b', color: '#6ee7b7', borderRadius: 7, fontSize: 12 };
const btn = { padding: '8px 12px', border: 0, borderRadius: 6, background: '#1d4ed8', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 600 };
const btnPrimary = { padding: '8px 14px', border: 0, borderRadius: 6, background: '#2563eb', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 700 };
const btnDisabled = { padding: '8px 14px', border: 0, borderRadius: 6, background: '#1e293b', color: '#64748b', cursor: 'not-allowed', fontSize: 12, fontWeight: 700 };
const actionButton = { padding: '6px 12px', border: '1px solid #1d4ed8', background: '#1d4ed8', color: '#fff', borderRadius: 6, cursor: 'pointer', fontSize: 12, fontWeight: 600 };
