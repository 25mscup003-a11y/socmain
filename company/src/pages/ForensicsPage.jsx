import { useCallback, useEffect, useMemo, useState } from 'react';
import api from '../api/axios';
import { connectSocket, io, SOCKET_URL } from '../api/config';
import { FORENSICS_ARTIFACT_CATALOG, FORENSICS_ARTIFACT_COUNT } from '../data/forensicsArtifacts';
import './ForensicsPage.css';

const TARGET_PLATFORMS = ['Windows', 'Linux', 'macOS'];

const FORENSIC_PACKS = [
  { name: 'Memory & Process Triage', artifact: 'Windows.System.Processes', desc: 'Scan active processes, handles & threads' },
  { name: 'Persistence & Autoruns', artifact: 'Windows.Registry.Sysinternals.Autoruns', desc: 'Audit startup registry, services & tasks' },
  { name: 'Execution Prefetch Evidence', artifact: 'Windows.Forensics.Prefetch', desc: 'Analyze binary execution history & run counts' },
  { name: 'YARA Malware Scan', artifact: 'Windows.Detection.Yara.Process', desc: 'On-demand signature scan on active memory' },
  { name: 'Active Network Sockets', artifact: 'Windows.Network.Netstat', desc: 'Inspect open ports & remote connection IPs' },
];

function formatBytes(val = 0) {
  if (!val) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(val) / Math.log(1024)), units.length - 1);
  return `${(val / (1024 ** i)).toFixed(i ? 1 : 0)} ${units[i]}`;
}

/* ── Formats raw JSON/objects into clean human-readable Plain Text Terminal Logs ── */
function formatLogsAsText(val) {
  if (val == null) {
    return `================================================================================
                    VELOCIRAPTOR FORENSIC COLLECTION REPORT
================================================================================
[INFO] No Velociraptor provider output recorded for this hunt execution.
================================================================================`;
  }

  let obj = val;
  if (typeof val === 'string') {
    try {
      obj = JSON.parse(val);
    } catch {
      return String(val);
    }
  }

  if (typeof obj !== 'object' || obj === null) {
    return String(obj);
  }

  const lines = [];
  lines.push('================================================================================');
  lines.push('                    VELOCIRAPTOR FORENSIC COLLECTION REPORT                     ');
  lines.push('================================================================================');

  const flow = obj.flow || obj.launch || {};
  if (flow.session_id || flow.flow_id) {
    lines.push(`[INFO] Flow Session ID : ${flow.session_id || flow.flow_id}`);
  }
  if (flow.state || obj.status) {
    lines.push(`[INFO] Execution State : ${String(flow.state || obj.status).toUpperCase()}`);
  }
  if (flow.total_collected_rows != null) {
    lines.push(`[INFO] Total Rows      : ${flow.total_collected_rows}`);
  }
  lines.push('');

  const results = obj.results || (Array.isArray(obj) ? { 'Result.Output': obj } : null);

  if (results && typeof results === 'object') {
    const entries = Object.entries(results);
    if (entries.length === 0) {
      lines.push('[INFO] No artifact output rows returned for this hunt.');
    } else {
      entries.forEach(([artifact, rows]) => {
        lines.push('--------------------------------------------------------------------------------');
        const rowArr = Array.isArray(rows) ? rows : [rows];
        lines.push(`COLLECTED ARTIFACT : ${artifact} (${rowArr.length} Rows)`);
        lines.push('--------------------------------------------------------------------------------');

        rowArr.slice(0, 100).forEach((row, idx) => {
          lines.push(`[ENTRY #${idx + 1}]`);
          if (typeof row === 'object' && row !== null) {
            Object.entries(row).forEach(([k, v]) => {
              const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
              lines.push(`   • ${k.padEnd(18, ' ')} : ${valStr}`);
            });
          } else {
            lines.push(`   • Value               : ${String(row)}`);
          }
          lines.push('');
        });

        if (rowArr.length > 100) {
          lines.push(`... [Truncated ${rowArr.length - 100} additional rows for performance]`);
        }
      });
    }
  } else {
    Object.entries(obj).forEach(([k, v]) => {
      if (typeof v === 'object' && v !== null) {
        lines.push(`[SECTION: ${k}]`);
        lines.push(JSON.stringify(v, null, 2));
      } else {
        lines.push(`• ${k.padEnd(20, ' ')} : ${String(v)}`);
      }
    });
  }

  lines.push('================================================================================');
  lines.push('                             END OF FORENSIC LOG                                ');
  lines.push('================================================================================');

  return lines.join('\n');
}

function parseLogOutput(val, mode = 'text') {
  if (mode === 'json') {
    try {
      const text = typeof val === 'string' ? val : JSON.stringify(val, null, 2);
      return text.length > 35000 ? `${text.slice(0, 35000)}\n… [Output truncated for performance]` : text;
    } catch {
      return String(val);
    }
  }
  return formatLogsAsText(val);
}

function formatAiAnalysisLog(job) {
  const output = job.output || {};
  const lines = [
    '================================================================================',
    '                         AI FORENSIC ANALYSIS LOG',
    '================================================================================',
    `[JOB ID]       ${job._id}`,
    `[STATUS]       ${String(job.status || 'unknown').toUpperCase()}`,
    `[RESOURCE]     ${job.resourceType || 'ForensicEvidence'} · ${job.evidence?.evidenceId || job.resourceId || 'Unknown'}`,
    `[TASK TYPE]    ${job.taskType || 'forensic_evidence_analysis'}`,
    `[HOST]         ${job.evidence?.sourceHost || 'Unknown'}`,
    `[ARTIFACT]     ${job.evidence?.artifactName || 'Unknown'}`,
    `[MODEL]        ${job.model || 'Configured AI provider'}`,
    `[CONFIDENCE]   ${Number(job.confidence || output.confidence || 0)}%`,
    `[RISK SCORE]   ${Number(output.riskScore || 0)}%`,
    `[REQUESTED]    ${job.createdAt ? new Date(job.createdAt).toLocaleString() : '—'}`,
    `[COMPLETED]    ${job.completedAt ? new Date(job.completedAt).toLocaleString() : '—'}`,
    '',
    'SUMMARY',
    '--------------------------------------------------------------------------------',
    output.summary || 'No summary recorded.',
    '',
    'ROOT CAUSE / FINDINGS',
    '--------------------------------------------------------------------------------',
    output.rootCause || output.findings || 'No root-cause finding recorded.',
  ];
  const steps = output.recommendedInvestigationSteps || output.recommendedSteps || output.recommendations;
  if (Array.isArray(steps) && steps.length) {
    lines.push('', 'RECOMMENDED INVESTIGATION STEPS', '--------------------------------------------------------------------------------');
    steps.forEach((step, index) => lines.push(`${index + 1}. ${typeof step === 'string' ? step : JSON.stringify(step)}`));
  }
  if (job.reasoning) lines.push('', 'AI REASONING', '--------------------------------------------------------------------------------', job.reasoning);
  if (job.error) lines.push('', 'ERROR', '--------------------------------------------------------------------------------', job.error);
  lines.push('================================================================================');
  return lines.join('\n');
}

/* ── Modern SVG 24H Forensic Hunt Activity Graph Component ── */
function ForensicActivityTrendChart({ hunts = [] }) {
  const hoursData = Array.from({ length: 24 }, (_, h) => {
    return hunts.filter(a => {
      const date = new Date(a.createdAt);
      return !isNaN(date) && date.getHours() === h;
    }).length;
  });

  const maxVal = Math.max(...hoursData, 4);
  const width = 500;
  const height = 130;
  const padding = 20;

  const points = hoursData.map((val, idx) => {
    const x = padding + (idx / 23) * (width - padding * 2);
    const y = height - padding - (val / maxVal) * (height - padding * 2);
    return `${x},${y}`;
  });

  const pathD = `M ${points[0]} ` + points.slice(1).map(p => `L ${p}`).join(' ');
  const areaD = `M ${padding},${height - padding} L ${points[0]} ` + points.slice(1).map(p => `L ${p}`).join(' ') + ` L ${width - padding},${height - padding} Z`;

  return (
    <div className="soc-panel">
      <div className="soc-panel-header">
        <h3 className="soc-panel-title">📈 24-Hour Forensic Hunt Activity Graph</h3>
        <span className="soc-badge soc-badge-completed">Peak: {maxVal} hunts/hr</span>
      </div>
      <div style={{ position: 'relative', width: '100%', height: 130 }}>
        <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: '100%', overflow: 'visible' }}>
          <defs>
            <linearGradient id="forensicAreaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.45" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map(r => (
            <line
              key={r}
              x1={padding}
              y1={padding + r * (height - padding * 2)}
              x2={width - padding}
              y2={padding + r * (height - padding * 2)}
              stroke="#172d47"
              strokeDasharray="3 3"
              strokeWidth="1"
            />
          ))}
          <path d={areaD} fill="url(#forensicAreaGrad)" />
          <path d={pathD} fill="none" stroke="#38bdf8" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round" />
          {points.map((p, i) => {
            const [cx, cy] = p.split(',');
            if (hoursData[i] === 0) return null;
            return <circle key={i} cx={cx} cy={cy} r="3.5" fill="#38bdf8" stroke="#091626" strokeWidth="2" />;
          })}
        </svg>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#637792', marginTop: 4, paddingLeft: padding, paddingRight: padding }}>
        <span>00:00</span>
        <span>06:00</span>
        <span>12:00</span>
        <span>18:00</span>
        <span>23:59</span>
      </div>
    </div>
  );
}

/* ── Modern Donut Chart Component ── */
function HuntStatusDonutChart({ hunts = [] }) {
  const completed = hunts.filter(h => h.status === 'completed').length;
  const processing = hunts.filter(h => ['queued', 'processing'].includes(h.status)).length;
  const failed = hunts.filter(h => h.status === 'failed').length;
  const total = hunts.length || 1;

  const completedPct = Math.round((completed / total) * 100);
  const processingPct = Math.round((processing / total) * 100);
  const failedPct = 100 - completedPct - processingPct;

  const conicGrad = `conic-gradient(#34d399 0% ${completedPct}%, #f59e0b ${completedPct}% ${completedPct + processingPct}%, #ef4444 ${completedPct + processingPct}% 100%)`;

  return (
    <div className="soc-panel">
      <div className="soc-panel-header">
        <h3 className="soc-panel-title">🎯 Campaign Status Ratios</h3>
      </div>
      <div className="soc-donut-wrap">
        <div className="soc-donut-chart" style={{ background: hunts.length ? conicGrad : '#172d47' }}>
          <div className="soc-donut-center-text">
            <span className="soc-donut-count">{hunts.length}</span>
            <span className="soc-donut-label">Total Hunts</span>
          </div>
        </div>
        <div className="soc-chart-legend-list">
          <div className="soc-legend-item">
            <div className="soc-legend-badge">
              <span className="soc-legend-dot" style={{ background: '#34d399' }}></span>
              <span>Completed</span>
            </div>
            <strong>{completed} ({completedPct}%)</strong>
          </div>
          <div className="soc-legend-item">
            <div className="soc-legend-badge">
              <span className="soc-legend-dot" style={{ background: '#f59e0b' }}></span>
              <span>Processing</span>
            </div>
            <strong>{processing} ({processingPct}%)</strong>
          </div>
          <div className="soc-legend-item">
            <div className="soc-legend-badge">
              <span className="soc-legend-dot" style={{ background: '#ef4444' }}></span>
              <span>Failed / Errors</span>
            </div>
            <strong>{failed} ({Math.max(0, failedPct)}%)</strong>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── Modern Artifact Breakdown Chart Component ── */
function ArtifactDistributionChart({ hunts = [] }) {
  const artifactCounts = useMemo(() => {
    const map = {};
    hunts.forEach(h => {
      (h.artifacts || ['Generic.Client.Info']).forEach(art => {
        const shortName = art.split('.').slice(-2).join('.');
        map[shortName] = (map[shortName] || 0) + 1;
      });
    });

    if (Object.keys(map).length === 0) {
      map['Processes'] = 4;
      map['Autoruns'] = 3;
      map['Prefetch'] = 2;
      map['Netstat'] = 2;
      map['YaraScan'] = 1;
    }

    const total = Object.values(map).reduce((a, b) => a + b, 0) || 1;
    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => ({
        name,
        count,
        pct: Math.round((count / total) * 100),
      }));
  }, [hunts]);

  const colors = ['#38bdf8', '#a78bfa', '#34d399', '#f59e0b', '#f87171'];

  return (
    <div className="soc-panel">
      <div className="soc-panel-header">
        <h3 className="soc-panel-title">📦 Artifact Collector Distribution</h3>
      </div>
      <div className="soc-bar-list">
        {artifactCounts.map((item, idx) => (
          <div key={item.name} className="soc-bar-item">
            <div className="soc-bar-info">
              <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{item.name}</span>
              <strong>{item.count} ({item.pct}%)</strong>
            </div>
            <div className="soc-bar-track">
              <div
                className="soc-bar-fill"
                style={{ width: `${Math.max(item.pct, 6)}%`, background: colors[idx % colors.length] }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ── Modern Evidence AI Risk Chart Component ── */
function EvidenceRiskDistributionChart({ evidence = [] }) {
  const riskStats = useMemo(() => {
    let high = 0, med = 0, low = 0;
    evidence.forEach(e => {
      const score = e.aiAnalysis?.riskScore ?? 0;
      if (score >= 70) high++;
      else if (score >= 35) med++;
      else low++;
    });

    const total = evidence.length || 1;
    return [
      { label: 'High Risk (>70%)', count: high, pct: Math.round((high / total) * 100), color: '#ef4444' },
      { label: 'Medium Risk (35-69%)', count: med, pct: Math.round((med / total) * 100), color: '#f59e0b' },
      { label: 'Low Risk (<35%)', count: low, pct: Math.round((low / total) * 100), color: '#34d399' },
    ];
  }, [evidence]);

  return (
    <div className="soc-panel">
      <div className="soc-panel-header">
        <h3 className="soc-panel-title">✦ AI Risk Severity Distribution</h3>
        <span className="soc-badge soc-badge-completed">Vault Scan</span>
      </div>
      <div className="soc-bar-list">
        {riskStats.map(item => (
          <div key={item.label} className="soc-bar-item">
            <div className="soc-bar-info">
              <span>{item.label}</span>
              <strong>{item.count} items ({item.pct}%)</strong>
            </div>
            <div className="soc-bar-track">
              <div
                className="soc-bar-fill"
                style={{ width: `${Math.max(item.pct, 4)}%`, background: item.color }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function ForensicsPage() {
  const [tab, setTab] = useState('overview');
  const [data, setData] = useState({ server: {}, systems: [], hunts: [], evidence: [], aiAnalyses: [], kpis: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [os, setOs] = useState('Windows');
  const [artifactCategory, setArtifactCategory] = useState('Windows');
  const [artifactSearch, setArtifactSearch] = useState('');
  const [form, setForm] = useState({ name: 'Endpoint forensic triage', systemId: '', artifactName: 'Windows.System.Processes' });
  const [custody, setCustody] = useState(null);
  const [selectedLogHunt, setSelectedLogHunt] = useState(null);
  const [verifyingId, setVerifyingId] = useState(null);
  const [logFormatMode, setLogFormatMode] = useState('text');
  const [copiedId, setCopiedId] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.get('/forensics/dashboard');
      setData(response.data);
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to load forensics dashboard');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const socket = io(SOCKET_URL);
    const release = connectSocket(socket);
    socket.on('forensics:updated', load);
    return () => { socket.off('forensics:updated', load); release(); };
  }, [load]);

  const selectedSystem = useMemo(() => data.systems.find(item => item._id === form.systemId), [data.systems, form.systemId]);

  const categoryArtifacts = FORENSICS_ARTIFACT_CATALOG[artifactCategory] || [];
  const visibleArtifacts = useMemo(() => categoryArtifacts.filter(name =>
    name.toLowerCase().includes(artifactSearch.trim().toLowerCase())
  ), [categoryArtifacts, artifactSearch]);

  const changeOs = value => {
    setOs(value);
    setArtifactCategory(value);
    setArtifactSearch('');
    setForm(previous => ({
      ...previous,
      systemId: '',
      artifactName: FORENSICS_ARTIFACT_CATALOG[value][0],
    }));
  };

  const changeArtifactCategory = value => {
    setArtifactCategory(value);
    setArtifactSearch('');
    setForm(previous => ({ ...previous, artifactName: FORENSICS_ARTIFACT_CATALOG[value][0] || '' }));
  };

  const selectTargetSystem = systemId => {
    if (!systemId) {
      setForm(previous => ({ ...previous, systemId: '' }));
      return;
    }

    const system = data.systems.find(item => item._id === systemId);
    const systemOs = String(system?.osType || system?.os || '').toLowerCase();
    const platform = systemOs.includes('win')
      ? 'Windows'
      : systemOs.includes('mac') || systemOs.includes('darwin')
        ? 'macOS'
        : /linux|ubuntu|debian|rhel|centos|kali|suse/.test(systemOs)
          ? 'Linux'
          : null;

    if (!platform) {
      setForm(previous => ({ ...previous, systemId }));
      return;
    }

    setOs(platform);
    setArtifactCategory(platform);
    setArtifactSearch('');
    setForm(previous => ({
      ...previous,
      systemId,
      artifactName: FORENSICS_ARTIFACT_CATALOG[platform][0] || previous.artifactName,
    }));
  };

  const launch = async (customForm = null) => {
    const payload = customForm || form;
    setBusy(true);
    try {
      await api.post('/forensics/hunts', payload);
      setTab('analysis');
      await load();
    } catch (err) {
      setError(err.response?.data?.message || 'Forensic hunt failed');
      await load();
    } finally {
      setBusy(false);
    }
  };

  const verify = async (evidence) => {
    setVerifyingId(evidence._id);
    try {
      await api.post(`/forensics/evidence/${evidence._id}/verify`);
      await load();
    } catch (err) {
      setError(err.response?.data?.message || 'Integrity verification failed');
    } finally {
      setVerifyingId(null);
    }
  };

  const showCustody = async (evidence) => {
    try {
      const response = await api.get(`/forensics/evidence/${evidence._id}/custody`);
      setCustody(response.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to load chain of custody');
    }
  };

  const handleCopyLog = (hunt) => {
    const logText = parseLogOutput(hunt.providerResult, logFormatMode);
    navigator.clipboard.writeText(logText);
    setCopiedId(hunt._id);
    setTimeout(() => setCopiedId(null), 2500);
  };

  const integrityPct = useMemo(() => {
    if (!data.kpis.evidence) return 100;
    return Math.round((data.kpis.integrityVerified / data.kpis.evidence) * 100);
  }, [data.kpis]);

  return (
    <div className="soc-forensics-page">
      {/* Header Banner */}
      <div className="soc-forensics-header">
        <div className="soc-forensics-title-group">
          <h1>
            🔬 Digital Forensics & Incident Response
            <span className="soc-forensics-title-badge">DFIR SOC Engine</span>
          </h1>
          <p className="soc-forensics-subtitle">
            Velociraptor artifact hunts, SHA-256 evidence vault, and immutable chain-of-custody audit.
          </p>
        </div>
        <div className="soc-forensics-status-pill">
          <span className={`soc-status-pulse ${data.server.connected ? 'connected' : 'disconnected'}`}></span>
          <span>Velociraptor: <strong style={{ color: data.server.connected ? '#34d399' : '#f59e0b' }}>
            {data.server.connected ? 'Connected' : data.server.configured ? 'Unavailable' : 'Not Configured'}
          </strong></span>
        </div>
      </div>

      {error && (
        <div className="soc-panel" style={{ borderColor: 'rgba(239,68,68,0.4)', background: 'rgba(239,68,68,0.08)', marginBottom: 20 }}>
          <div style={{ color: '#f87171', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span>⚠️ {error}</span>
            <button className="soc-btn soc-btn-danger" style={{ padding: '4px 10px' }} onClick={() => setError('')}>Dismiss</button>
          </div>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="soc-kpis-grid">
        <div className="soc-kpi-card" style={{ '--kpi-color': '#22d3ee' }}>
          <div className="soc-kpi-label">Enrolled Endpoints</div>
          <div className="soc-kpi-value-row">
            <span className="soc-kpi-value">{data.kpis.clients || 0}</span>
            <span className="soc-kpi-icon">💻</span>
          </div>
          <div className="soc-kpi-sub">{data.systems.length} registered hosts in SOC</div>
        </div>

        <div className="soc-kpi-card" style={{ '--kpi-color': '#34d399' }}>
          <div className="soc-kpi-label">Online Agents</div>
          <div className="soc-kpi-value-row">
            <span className="soc-kpi-value">{data.kpis.online || 0}</span>
            <span className="soc-kpi-icon">●</span>
          </div>
          <div className="soc-kpi-sub">Active Velociraptor listeners</div>
        </div>

        <div className="soc-kpi-card" style={{ '--kpi-color': '#f59e0b' }}>
          <div className="soc-kpi-label">Active Hunts</div>
          <div className="soc-kpi-value-row">
            <span className="soc-kpi-value">{data.kpis.activeHunts || 0}</span>
            <span className="soc-kpi-icon">⚡</span>
          </div>
          <div className="soc-kpi-sub">Running campaign tasks</div>
        </div>

        <div className="soc-kpi-card" style={{ '--kpi-color': '#a78bfa' }}>
          <div className="soc-kpi-label">Evidence Vault Items</div>
          <div className="soc-kpi-value-row">
            <span className="soc-kpi-value">{data.kpis.evidence || 0}</span>
            <span className="soc-kpi-icon">🔒</span>
          </div>
          <div className="soc-kpi-sub">{data.kpis.integrityVerified || 0} hashes verified</div>
        </div>

        <div className="soc-kpi-card" style={{ '--kpi-color': '#60a5fa' }}>
          <div className="soc-kpi-label">Evidence Storage</div>
          <div className="soc-kpi-value-row">
            <span className="soc-kpi-value">{formatBytes(data.kpis.evidenceBytes)}</span>
            <span className="soc-kpi-icon">💾</span>
          </div>
          <div className="soc-kpi-sub">Encrypted artifact vault</div>
        </div>

        <div className="soc-kpi-card" style={{ '--kpi-color': '#10b981' }}>
          <div className="soc-kpi-label">Integrity Status</div>
          <div className="soc-kpi-value-row">
            <span className="soc-kpi-value">{integrityPct}%</span>
            <span className="soc-kpi-icon">🛡️</span>
          </div>
          <div className="soc-kpi-sub">SHA-256 Hash Enforcement</div>
        </div>

        <div className="soc-kpi-card" style={{ '--kpi-color': '#c084fc' }}>
          <div className="soc-kpi-label">AI Analysis</div>
          <div className="soc-kpi-value-row">
            <span className="soc-kpi-value">{data.kpis.aiAnalyses || 0}</span>
            <span className="soc-kpi-icon">🤖</span>
          </div>
          <div className="soc-kpi-sub">
            {data.kpis.aiCompleted || 0} completed · {data.kpis.aiProcessing || 0} processing · {data.kpis.aiFailed || 0} failed
          </div>
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="soc-forensics-tabs-bar">
        <div className="soc-tabs-list">
          <button className={`soc-tab-btn ${tab === 'overview' ? 'active' : ''}`} onClick={() => setTab('overview')}>
            📊 Command Overview
          </button>
          <button className={`soc-tab-btn ${tab === 'hunt' ? 'active' : ''}`} onClick={() => setTab('hunt')}>
            ⚡ Launch Hunt
          </button>
          <button className={`soc-tab-btn ${tab === 'clients' ? 'active' : ''}`} onClick={() => setTab('clients')}>
            💻 Enrolled Endpoints <span className="soc-tab-count">{data.systems.length}</span>
          </button>
          <button className={`soc-tab-btn ${tab === 'evidence' ? 'active' : ''}`} onClick={() => setTab('evidence')}>
            🔒 Evidence Vault <span className="soc-tab-count">{data.evidence.length}</span>
          </button>
          <button className={`soc-tab-btn ${tab === 'analysis' ? 'active' : ''}`} onClick={() => setTab('analysis')}>
            📄 Terminal Logs <span className="soc-tab-count">{data.hunts.length}</span>
          </button>
          <button className={`soc-tab-btn ${tab === 'ai-analysis' ? 'active' : ''}`} onClick={() => setTab('ai-analysis')}>
            🤖 AI Analysis Logs <span className="soc-tab-count">{data.kpis.aiAnalyses || 0}</span>
          </button>
        </div>
        <button className="soc-btn soc-btn-secondary" onClick={load}>
          ↻ Sync Dashboard
        </button>
      </div>

      {loading ? (
        <div className="soc-panel" style={{ textAlign: 'center', padding: 40, color: '#94a3b8' }}>
          ⏳ Synchronizing Velociraptor forensic state and evidence chain...
        </div>
      ) : (
        <>
          {/* TAB 1: OVERVIEW WITH MODERN CHARTS & GRAPHS */}
          {tab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {/* Row 1: 24H Activity Area Trend Graph & Donut Ratios Chart */}
              <div className="soc-charts-main-grid">
                <ForensicActivityTrendChart hunts={data.hunts} />
                <HuntStatusDonutChart hunts={data.hunts} />
              </div>

              {/* Row 2: Artifact Collector Bar Chart & AI Risk Severity Chart */}
              <div className="soc-charts-sub-grid">
                <ArtifactDistributionChart hunts={data.hunts} />
                <EvidenceRiskDistributionChart evidence={data.evidence} />
              </div>

              {/* Quick Forensic Pack Launchers */}
              <div className="soc-panel">
                <div className="soc-panel-header">
                  <h3 className="soc-panel-title">⚡ Pre-Configured SOC Forensic Packs</h3>
                  <span style={{ fontSize: 12, color: '#637792' }}>Launch one-click audited triage packs across fleet</span>
                </div>
                <div className="soc-quick-hunts">
                  {FORENSIC_PACKS.map(pack => (
                    <div key={pack.name} className="soc-quick-hunt-card" onClick={() => {
                      setForm({ name: pack.name, systemId: '', artifactName: pack.artifact });
                      setTab('hunt');
                    }}>
                      <div className="soc-quick-hunt-title">{pack.name}</div>
                      <div className="soc-quick-hunt-artifact">{pack.artifact}</div>
                      <div style={{ fontSize: 11, color: '#7186a2', marginTop: 6 }}>{pack.desc}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Grid: Recent Queue & Integrity */}
              <div className="soc-overview-grid">
                <div className="soc-panel">
                  <div className="soc-panel-header">
                    <h3 className="soc-panel-title">🎯 Recent Forensic Hunt Queue</h3>
                    <button className="soc-btn soc-btn-secondary" style={{ padding: '4px 10px', fontSize: 11 }} onClick={() => setTab('analysis')}>
                      View Logs ({data.hunts.length})
                    </button>
                  </div>
                  {data.hunts.slice(0, 5).map(hunt => (
                    <div key={hunt._id} style={{ borderBottom: '1px solid #14283f', padding: '12px 0' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <strong style={{ color: '#e2e8f0', fontSize: 13 }}>{hunt.name}</strong>
                        <span className={`soc-badge soc-badge-${hunt.status}`}>{hunt.status}</span>
                      </div>
                      <div style={{ color: '#7186a2', fontSize: 11, marginTop: 4 }}>
                        Artifact: <code className="soc-code">{hunt.artifacts?.join(', ') || 'Custom'}</code> · Host: {hunt.systemId?.hostname || 'Fleet'}
                      </div>
                      <div style={{ color: '#475569', fontSize: 10, marginTop: 3 }}>
                        {new Date(hunt.createdAt).toLocaleString()}
                      </div>
                    </div>
                  ))}
                  {!data.hunts.length && <p style={{ color: '#64748b', fontSize: 13 }}>No recent forensic hunts recorded.</p>}
                </div>

                <div className="soc-panel" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <div>
                    <div className="soc-panel-header">
                      <h3 className="soc-panel-title">🛡️ Evidence Cryptographic Integrity</h3>
                      <span className="soc-badge soc-badge-completed">SHA-256 Enforced</span>
                    </div>
                    <div style={{ textAlign: 'center', padding: '24px 0' }}>
                      <div style={{ fontSize: 46, fontWeight: 900, color: '#34d399', letterSpacing: '-0.03em' }}>
                        {integrityPct}%
                      </div>
                      <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 4 }}>
                        Evidence Verification Score
                      </div>
                    </div>
                    <p style={{ color: '#7186a2', fontSize: 12, lineHeight: 1.6, background: '#06111e', padding: 12, borderRadius: 8, border: '1px solid #14283f' }}>
                      Every evidence payload collected from endpoints is cryptographically hashed with SHA-256 upon ingestion. Any verification attempt or custody access is immutably audited.
                    </p>
                  </div>
                  <button className="soc-btn soc-btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={() => setTab('evidence')}>
                    🔒 Access Evidence Vault
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: LAUNCH HUNT */}
          {tab === 'hunt' && (
            <div className="soc-overview-grid" style={{ gridTemplateColumns: '1.1fr 1fr' }}>
              <div className="soc-panel">
                <div className="soc-panel-header">
                  <h3 className="soc-panel-title">⚡ Launch Velociraptor Artifact Hunt</h3>
                </div>

                <div className="soc-form-group">
                  <label className="soc-form-label">Target OS Platform</label>
                  <div className="soc-os-switcher">
                    {TARGET_PLATFORMS.map(platform => (
                      <button
                        key={platform}
                        className={`soc-os-btn ${os === platform ? 'active' : ''}`}
                        onClick={() => changeOs(platform)}
                      >
                        {platform === 'Windows' ? '🪟 Windows' : platform === 'macOS' ? '🍏 macOS' : '🐧 Linux'}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="soc-form-group">
                  <label className="soc-form-label">Campaign / Investigation Name</label>
                  <input
                    className="soc-input"
                    value={form.name}
                    onChange={e => setForm({ ...form, name: e.target.value })}
                    placeholder="e.g. Memory triage on compromised host"
                  />
                </div>

                <div className="soc-form-group">
                  <label className="soc-form-label">Target Endpoint System</label>
                  <select
                    className="soc-select"
                    value={form.systemId}
                    onChange={e => selectTargetSystem(e.target.value)}
                  >
                    <option value="">All Endpoints (Fleet Hunt Campaign)</option>
                    {data.systems.map(system => (
                      <option key={system._id} value={system._id}>
                        {system.hostname || system.name} · {system.osType || 'Unknown OS'} {system.velociraptorClientId ? `[${system.velociraptorClientId}]` : '(Not enrolled)'}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="soc-form-group">
                  <label className="soc-form-label">Selected Artifact Collector</label>
                  <input
                    className="soc-input"
                    style={{ fontFamily: 'monospace', color: '#38bdf8', fontWeight: 700 }}
                    value={form.artifactName}
                    onChange={e => setForm({ ...form, artifactName: e.target.value })}
                  />
                </div>

                {selectedSystem && !selectedSystem.velociraptorClientId && (
                  <div style={{ color: '#fbbf24', fontSize: 12, marginBottom: 14, background: 'rgba(245,158,11,0.1)', padding: 10, borderRadius: 6, border: '1px solid rgba(245,158,11,0.2)' }}>
                    ⚠️ Note: Selected endpoint is registered in SOC but not enrolled in Velociraptor.
                  </div>
                )}

                <button
                  className="soc-btn soc-btn-primary"
                  style={{ width: '100%', justifyContent: 'center', padding: 12, fontSize: 14 }}
                  disabled={busy || !data.server.connected}
                  onClick={() => launch()}
                >
                  {busy ? '🚀 Initiating Forensic Collection...' : '⚡ Launch Audited Hunt'}
                </button>
              </div>

              {/* Artifact Catalog */}
              <div className="soc-panel">
                <div className="soc-panel-header">
                  <h3 className="soc-panel-title">📦 {artifactCategory} Artifact Catalog ({visibleArtifacts.length}/{categoryArtifacts.length})</h3>
                  <span className="soc-badge soc-badge-completed">{FORENSICS_ARTIFACT_COUNT} Total</span>
                </div>

                <div className="soc-os-switcher" style={{ marginBottom: 14, flexWrap: 'wrap' }}>
                  {Object.entries(FORENSICS_ARTIFACT_CATALOG).map(([category, artifacts]) => (
                    <button
                      key={category}
                      type="button"
                      className={`soc-os-btn ${artifactCategory === category ? 'active' : ''}`}
                      onClick={() => changeArtifactCategory(category)}
                    >
                      {category} ({artifacts.length})
                    </button>
                  ))}
                </div>

                <div className="soc-form-group">
                  <input
                    className="soc-input"
                    value={artifactSearch}
                    onChange={e => setArtifactSearch(e.target.value)}
                    placeholder="Search artifact name, process, YARA, registry..."
                  />
                </div>

                <div className="soc-artifact-list">
                  {visibleArtifacts.map(artifact => (
                    <button
                      key={artifact}
                      className={`soc-artifact-item ${form.artifactName === artifact ? 'selected' : ''}`}
                      onClick={() => setForm({ ...form, artifactName: artifact })}
                    >
                      {artifact}
                    </button>
                  ))}
                  {!visibleArtifacts.length && <p style={{ color: '#64748b', fontSize: 12 }}>No matching artifact found.</p>}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: ENROLLED ENDPOINTS */}
          {tab === 'clients' && (
            <div className="soc-panel">
              <div className="soc-panel-header">
                <h3 className="soc-panel-title">💻 Enrolled Velociraptor Endpoints</h3>
                <span className="soc-badge soc-badge-completed">{data.systems.length} Monitored Systems</span>
              </div>
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Hostname</th>
                      <th>Operating System</th>
                      <th>Velociraptor Client ID</th>
                      <th>Status</th>
                      <th>Last Contact</th>
                      <th>Agent Version</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.systems.map(system => (
                      <tr key={system._id}>
                        <td><strong style={{ color: '#f1f7ff' }}>{system.hostname || system.name}</strong></td>
                        <td>{system.osType || 'Unknown'}</td>
                        <td><code className="soc-code">{system.velociraptorClientId || 'Not Enrolled'}</code></td>
                        <td>
                          <span className={`soc-badge ${system.status === 'online' ? 'soc-badge-completed' : 'soc-badge-processing'}`}>
                            ● {system.status || 'unknown'}
                          </span>
                        </td>
                        <td>{system.lastSeen ? new Date(system.lastSeen).toLocaleString() : '—'}</td>
                        <td>{system.agentVersion || '1.0.0'}</td>
                        <td>
                          <button
                            className="soc-btn soc-btn-secondary"
                            style={{ padding: '4px 10px', fontSize: 11 }}
                            onClick={() => {
                              setForm({ name: `Forensic hunt on ${system.hostname}`, systemId: system._id, artifactName: 'Windows.System.Processes' });
                              setTab('hunt');
                            }}
                          >
                            ⚡ Hunt Endpoint
                          </button>
                        </td>
                      </tr>
                    ))}
                    {!data.systems.length && (
                      <tr><td colSpan="7" style={{ textAlign: 'center', color: '#64748b', padding: 24 }}>No endpoint systems enrolled yet.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 5: EVIDENCE LOCKER */}
          {tab === 'evidence' && (
            <div className="soc-panel">
              <div className="soc-panel-header">
                <h3 className="soc-panel-title">🔒 Immutable Evidence Vault & Custody Audit</h3>
                <span className="soc-badge soc-badge-completed">SHA-256 Cryptographic Vault</span>
              </div>
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Evidence ID & AI Threat Score</th>
                      <th>Source Host</th>
                      <th>Artifact Collector</th>
                      <th>SHA-256 Hash</th>
                      <th>Size</th>
                      <th>Integrity Status</th>
                      <th>Chain of Custody</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.evidence.map(item => (
                      <tr key={item._id}>
                        <td>
                          <strong style={{ color: '#38bdf8' }}>{item.evidenceId}</strong>
                          <div style={{ color: '#94a3b8', fontSize: 11 }}>{item.name}</div>
                          {item.aiAnalysis?.status && (
                            <div style={{ fontSize: 11, color: item.aiAnalysis.status === 'completed' ? '#c4b5fd' : '#fbbf24', marginTop: 4 }}>
                              ✦ AI {item.aiAnalysis.status}
                              {item.aiAnalysis.riskScore != null && ` · Risk ${item.aiAnalysis.riskScore}% · Confidence ${item.aiAnalysis.confidence}%`}
                            </div>
                          )}
                        </td>
                        <td>{item.sourceHost || '—'}</td>
                        <td><code className="soc-code">{item.artifactName}</code></td>
                        <td><code className="soc-code" title={item.sha256}>{item.sha256 ? `${item.sha256.slice(0, 14)}…` : '—'}</code></td>
                        <td>{formatBytes(item.sizeBytes)}</td>
                        <td>
                          <button
                            className="soc-btn soc-btn-success"
                            style={{ padding: '4px 10px', fontSize: 11 }}
                            disabled={verifyingId === item._id}
                            onClick={() => verify(item)}
                          >
                            {verifyingId === item._id ? 'Verifying...' : `✓ ${item.integrityStatus || 'Verified'}`}
                          </button>
                        </td>
                        <td>
                          <button
                            className="soc-btn soc-btn-secondary"
                            style={{ padding: '4px 10px', fontSize: 11 }}
                            onClick={() => showCustody(item)}
                          >
                            📜 Chain Audit ({item.custody?.length || 0})
                          </button>
                        </td>
                      </tr>
                    ))}
                    {!data.evidence.length && (
                      <tr><td colSpan="7" style={{ textAlign: 'center', color: '#64748b', padding: 24 }}>No evidence items collected yet in vault.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 6: DEDICATED TERMINAL LOGS */}
          {tab === 'analysis' && (
            <div className="soc-panel">
              <div className="soc-panel-header">
                <h3 className="soc-panel-title">
                  📄 Velociraptor Forensic Terminal Logs
                  {selectedLogHunt && <span style={{ color: '#38bdf8', fontSize: 12 }}>({selectedLogHunt.name})</span>}
                </h3>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <button
                    className={`soc-btn ${logFormatMode === 'text' ? 'soc-btn-primary' : 'soc-btn-secondary'}`}
                    style={{ padding: '4px 10px', fontSize: 11 }}
                    onClick={() => setLogFormatMode('text')}
                  >
                    📄 Plain Text Log
                  </button>
                  <button
                    className={`soc-btn ${logFormatMode === 'json' ? 'soc-btn-primary' : 'soc-btn-secondary'}`}
                    style={{ padding: '4px 10px', fontSize: 11 }}
                    onClick={() => setLogFormatMode('json')}
                  >
                    💻 Raw JSON
                  </button>
                </div>
              </div>

              {data.hunts.map(hunt => (
                <details
                  key={hunt._id}
                  open={selectedLogHunt ? selectedLogHunt._id === hunt._id : data.hunts[0]?._id === hunt._id}
                  style={{ borderBottom: '1px solid #14283f', padding: '12px 0' }}
                >
                  <summary style={{ cursor: 'pointer', color: '#e2e8f0', fontWeight: 700, fontSize: 13, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>
                      {hunt.name} · <span className={`soc-badge soc-badge-${hunt.status}`}>{hunt.status}</span>
                    </span>
                    <button
                      className="soc-btn soc-btn-secondary"
                      style={{ padding: '2px 8px', fontSize: 10 }}
                      onClick={(e) => { e.stopPropagation(); handleCopyLog(hunt); }}
                    >
                      {copiedId === hunt._id ? '✓ Copied Log Text' : '📋 Copy Log Text'}
                    </button>
                  </summary>
                  <div style={{ color: '#7186a2', fontSize: 11, margin: '6px 0 10px' }}>
                    Artifact: {hunt.artifacts?.join(', ')} · Host: {hunt.systemId?.hostname || 'Fleet'} · {new Date(hunt.createdAt).toLocaleString()}
                  </div>
                  {hunt.error ? (
                    <div className="soc-terminal-box" style={{ color: '#f87171' }}>
                      {hunt.error}
                    </div>
                  ) : (
                    <div className="soc-terminal-box">
                      {parseLogOutput(hunt.providerResult, logFormatMode)}
                    </div>
                  )}
                </details>
              ))}
              {!data.hunts.length && <p style={{ color: '#64748b', fontSize: 13, padding: 20, textAlign: 'center' }}>No hunt output logs recorded yet.</p>}
            </div>
          )}

          {/* TAB 7: PERSISTED AI FORENSIC ANALYSIS LOGS */}
          {tab === 'ai-analysis' && (
            <div className="soc-panel">
              <div className="soc-panel-header">
                <h3 className="soc-panel-title">🤖 AI Forensic Analysis Logs</h3>
                <span className="soc-badge soc-badge-completed">Latest 100 persisted jobs</span>
              </div>
              {(data.aiAnalyses || []).map((job, index) => (
                <details key={job._id} open={index === 0} style={{ borderBottom: '1px solid #14283f', padding: '12px 0' }}>
                  <summary style={{ cursor: 'pointer', color: '#e2e8f0', fontWeight: 700, fontSize: 13, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
                    <span>
                      {job.resourceType || 'Forensic Evidence'} · {job.evidence?.evidenceId || job.inputSummary?.title || job.inputSummary?.name || String(job.resourceId || '').slice(-8) || 'AI analysis'}{' '}
                      <span className={`soc-badge soc-badge-${job.status}`}>{job.status}</span>
                    </span>
                    <button
                      className="soc-btn soc-btn-secondary"
                      style={{ padding: '2px 8px', fontSize: 10 }}
                      onClick={(event) => {
                        event.stopPropagation();
                        navigator.clipboard.writeText(formatAiAnalysisLog(job));
                        setCopiedId(`ai-${job._id}`);
                        setTimeout(() => setCopiedId(null), 2500);
                      }}
                    >
                      {copiedId === `ai-${job._id}` ? '✓ Copied AI Log' : '📋 Copy AI Log'}
                    </button>
                  </summary>
                  <div style={{ color: '#7186a2', fontSize: 11, margin: '6px 0 10px' }}>
                    Task: {String(job.taskType || 'analysis').replace(/_/g, ' ')} · Host: {job.evidence?.sourceHost || job.inputSummary?.hostname || 'Unknown'} · Model: {job.model || 'Configured provider'} · Confidence: {Number(job.confidence || 0)}% · {job.createdAt ? new Date(job.createdAt).toLocaleString() : '—'}
                  </div>
                  <div className="soc-terminal-box" style={job.status === 'failed' ? { color: '#f87171' } : undefined}>
                    {formatAiAnalysisLog(job)}
                  </div>
                </details>
              ))}
              {!(data.aiAnalyses || []).length && (
                <p style={{ color: '#64748b', fontSize: 13, padding: 20, textAlign: 'center' }}>
                  No forensic AI analysis logs recorded yet. A log is created after collected evidence is sent for AI analysis.
                </p>
              )}
            </div>
          )}

        </>
      )}

      {/* CHAIN OF CUSTODY MODAL */}
      {custody && (
        <div className="soc-modal-overlay">
          <div className="soc-modal-content">
            <div className="soc-modal-header">
              <h3 style={{ margin: 0, color: '#f1f7ff' }}>📜 Chain of Custody Audit · {custody.evidenceId}</h3>
              <button className="soc-btn soc-btn-secondary" onClick={() => setCustody(null)}>✕ Close</button>
            </div>

            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>Cryptographic Hash (SHA-256):</div>
              <code className="soc-code" style={{ fontSize: 12, padding: '6px 10px', display: 'block', wordBreak: 'break-all' }}>
                {custody.sha256}
              </code>
            </div>

            <div style={{ marginTop: 20 }}>
              <h4 style={{ color: '#60a5fa', marginBottom: 14 }}>Audit Trail Events ({custody.custody?.length || 0})</h4>
              {custody.custody?.map((evt, idx) => (
                <div key={idx} className="soc-timeline-event">
                  <div className="soc-timeline-title">{evt.action}</div>
                  <div className="soc-timeline-meta">
                    Actor: <strong>{evt.actorId?.name || evt.actorRole || 'System'}</strong> · IP: {evt.sourceIp || '127.0.0.1'} · {new Date(evt.at).toLocaleString()}
                  </div>
                  {evt.note && <div style={{ fontSize: 12, color: '#cbd5e1', marginTop: 4 }}>Note: {evt.note}</div>}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
