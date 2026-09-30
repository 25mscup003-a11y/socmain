import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import api from '../../../api/axios';

const severityColor = { critical: '#fb7185', high: '#fb923c', medium: '#facc15', low: '#38bdf8' };
const tabs = ['Overview', 'AI Analysis', 'Timeline', 'Network Evidence', 'Velociraptor', 'IOC Analysis', 'Chain of Custody'];

const safeDate = value => value ? new Date(value).toLocaleString() : '—';

const isNetworkEvidence = item => Boolean(
  item?.srcip || item?.destip || item?.domain || item?.dnsQuery || item?.protocol
  || ['network', 'dns', 'connection'].includes(String(item?.eventCategory || '').toLowerCase())
  || ['ids', 'ips', 'zeek'].includes(String(item?.sourceType || '').toLowerCase())
  || /^(network|ids|ips|zeek|firewall|suricata)$/i.test(String(item?.source || ''))
);

export default function IncidentDetailPage({ resourceType = 'incident' }) {
  const { id } = useParams();
  const navigate = useNavigate();
  const isTicket = resourceType === 'ticket';
  const [incident, setIncident] = useState(null);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('Overview');
  const [status, setStatus] = useState('investigating');
  const [note, setNote] = useState('');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [aiRunning, setAiRunning] = useState(false);
  const [aiMessage, setAiMessage] = useState('');

  const loadIncident = useCallback(async () => {
    try {
      const { data } = await api.get(`/soc-dashboard/${isTicket ? 'tickets' : 'incidents'}/${id}`, { skipCache: true });
      setIncident(data);
      setStatus(data.status || 'investigating');
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Incident could not be loaded.');
    }
  }, [id, isTicket]);

  useEffect(() => { loadIncident(); }, [loadIncident]);

  const runAiAnalysis = async () => {
    if (aiRunning) return;
    setAiRunning(true);
    setAiMessage('Submitting incident evidence for AI analysis…');
    try {
      const { data } = await api.post(isTicket ? `/ai/alerts/${id}/analyze` : `/ai/edr-incidents/${id}/analyze`, isTicket ? { force: true } : undefined);
      const jobId = data?.job?._id;
      if (!jobId) throw new Error('AI backend did not return a job ID.');

      setIncident(current => current ? {
        ...current,
        aiInvestigation: { ...(current.aiInvestigation || {}), status: 'queued', jobId },
      } : current);

      for (let attempt = 0; attempt < 150; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        const { data: job } = await api.get(`/ai/jobs/${jobId}`, { skipCache: true });
        const jobStatus = String(job?.status || 'processing').toLowerCase();
        setAiMessage(`AI analysis ${jobStatus.replace(/_/g, ' ')}…`);

        if (jobStatus === 'failed') throw new Error(job?.error || 'AI analysis failed.');
        if (jobStatus !== 'completed') continue;

        await loadIncident();
        setAiMessage('AI analysis completed successfully.');
        return;
      }

      setAiMessage('AI analysis is still processing. Reopen this incident shortly to view the result.');
    } catch (err) {
      setAiMessage(err.response?.data?.message || err.message || 'AI analysis failed.');
    } finally {
      setAiRunning(false);
    }
  };

  const evidence = useMemo(() => incident?.alertIds || [], [incident]);
  const networkEvidence = useMemo(() => {
    const related = Array.isArray(incident?.networkEvidence) ? incident.networkEvidence : [];
    return related.length ? related : evidence.filter(isNetworkEvidence);
  }, [incident, evidence]);
  const iocs = useMemo(() => incident?.iocs || [], [incident]);
  const confidence = Math.max(0, Math.min(100, Number(incident?.confidenceScore || 0)));
  const risk = Math.max(0, Math.min(100, Number(incident?.riskScore ?? confidence)));
  const endpoint = incident?.affectedEndpoint || incident?.agentName || 'Unknown endpoint';
  const mitre = [incident?.mitreTechnique, ...(incident?.mitreTactics || [])].filter(Boolean);

  const submitUpdate = async () => {
    setSaving(true); setMessage('');
    try {
      const action = status === 'resolved' ? 'resolve' : status === 'false_positive' ? 'false_positive' : 'investigate';
      await api.post(isTicket ? `/soc-dashboard/alerts/${id}/action` : `/soc-dashboard/work-items/incident/${id}/action`, { action, note: note.trim() });
      setNote('');
      setMessage(status === 'resolved'
        ? 'Case resolved across the incident, correlation, alerts, and escalation queues.'
        : status === 'false_positive'
          ? 'Case marked false positive across all linked SOC records.'
          : 'Case moved to investigating across all linked SOC records.');
      await loadIncident();
    } catch (err) {
      setMessage(err.response?.data?.message || 'Update failed.');
    } finally { setSaving(false); }
  };

  const exportReport = () => {
    const blob = new Blob([JSON.stringify(incident, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = `incident-${id}.json`; link.click();
    URL.revokeObjectURL(url);
  };

  if (error) return <div className="forensic-state"><div>{error}</div><button onClick={() => navigate(-1)}>← Back</button></div>;
  if (!incident) return <div className="forensic-state">Loading incident workspace…</div>;

  return (
    <div className="forensic-workspace">
      <header className="forensic-header">
        <div className="forensic-title-area">
          <button className="back-link" onClick={() => navigate(-1)}>← {isTicket ? 'Ticket Queue' : 'Incident Queue'}</button>
          <span className="eyebrow">{isTicket ? 'SOAR Ticket Forensic Investigation' : 'Forensic Investigation'}</span>
          <div className="title-line">
            <h1>{incident.title || 'Correlation Incident'}</h1>
            <span className="severity-pill" style={{ color: severityColor[incident.severity], borderColor: `${severityColor[incident.severity]}66`, background: `${severityColor[incident.severity]}18` }}>● {incident.severity}</span>
            <select className="status-pill header-status" value={status} onChange={event => setStatus(event.target.value)}>
              <option value="investigating">Status: Investigating</option>
              <option value="resolved">Status: Resolved</option>
              <option value="false_positive">Status: False Positive</option>
            </select>
          </div>
          <div className="case-meta">
            <span>▣ Case ID: {incident.correlationId || incident._id}</span>
            <span>▥ Company: {incident.companyId?.name || 'Company'}</span>
            <span>▦ Department: {incident.departmentId?.name || 'All'}</span>
            <span>♙ Assigned: {incident.assignedTo?.name || 'Unassigned'}</span>
            <span>◷ Opened: {safeDate(incident.createdAt)}</span>
            <span>✦ Analysis Added: {safeDate(incident.aiInvestigation?.completedAt)}</span>
            <span>✓ Closed: {safeDate(incident.resolvedAt)}</span>
          </div>
        </div>
        <div className="header-actions">
          <button className="primary-action" onClick={() => setActiveTab('AI Analysis')}>✦ AI Analyze</button>
          <button className="cyan-action" onClick={() => setActiveTab('Velociraptor')}>▽ Velociraptor</button>
          <button onClick={() => window.print()}>▣ Preserve Evidence</button>
          <button onClick={exportReport}>⇩ Export Report</button>
        </div>
      </header>

      <section className="metric-grid">
        <Metric icon="□" label="Evidence Items" value={evidence.length} color="#38bdf8" />
        <Metric icon="⌁" label={isTicket ? 'Ticket Evidence' : 'Source Alerts'} value={incident.sourceAlertCount ?? evidence.length} color="#22d3ee" />
        <Metric icon="ϟ" label="MITRE Records" value={mitre.length} color="#c084fc" />
        <Metric icon="◎" label="IOC Matches" value={iocs.length} color="#fb7185" />
        <Metric icon="▣" label="Affected Assets" value={endpoint === 'Unknown endpoint' ? 0 : 1} color="#4ade80" />
        <Metric icon="♢" label="Case Integrity" value="Verified" color="#4ade80" />
      </section>

      <nav className="forensic-tabs">
        {tabs.map(tab => <button key={tab} className={activeTab === tab ? 'active' : ''} onClick={() => setActiveTab(tab)}>{tab}</button>)}
      </nav>

      <main className={`forensic-main ${activeTab === 'AI Analysis' ? 'without-side-rail' : ''}`}>
        <section className="analysis-board">
          {activeTab === 'AI Analysis' && <AIAnalysis incident={incident} onRun={runAiAnalysis} running={aiRunning} message={aiMessage} />}
          {activeTab === 'Overview' && <Overview incident={incident} evidence={evidence} endpoint={endpoint} mitre={mitre} />}
          {activeTab === 'Timeline' && <EvidenceTable evidence={evidence} />}
          {activeTab === 'Network Evidence' && <NetworkEvidenceTable evidence={networkEvidence} scope={incident.networkEvidenceScope} error={incident.networkEvidenceError} networkInvolved={incident.networkInvolved} />}
          {activeTab === 'Velociraptor' && <EndpointCollection endpoint={endpoint} incident={incident} />}
          {activeTab === 'IOC Analysis' && <IOCPanel iocs={iocs} />}
          {activeTab === 'Chain of Custody' && <CustodyPanel incident={incident} />}
        </section>

        {activeTab !== 'AI Analysis' && <aside className="side-rail">
        <div className="status-panel">
          <div className="panel-heading"><span>Update Case Status</span><span>×</span></div>
          <label>Current Status</label>
          <div className="current-status">{incident.status?.replace(/_/g, ' ')}</div>
          <label>Select New Status</label>
          {[
            ['investigating', 'Analyzing'], ['resolved', 'Resolved'], ['false_positive', 'False Positive'],
          ].map(([value, text]) => <label className="status-choice" key={value}><input type="radio" checked={status === value} onChange={() => setStatus(value)} /> <span>{text}</span></label>)}
          <label>Reason / Analyst Note</label>
          <textarea value={note} onChange={event => setNote(event.target.value)} placeholder="Enter reason or investigation notes" maxLength={2500} />
          <small>{note.length}/2500</small>
          {message && <div className={/failed|error|not found|not permitted/i.test(message) ? 'save-message' : 'save-message ok'}>{message}</div>}
          <button className="update-button" disabled={saving} onClick={submitUpdate}>{saving ? 'Updating all linked records…' : status === 'resolved' ? 'Resolve Case Everywhere' : status === 'false_positive' ? 'Mark False Positive Everywhere' : 'Update Investigation Status'}</button>
        </div>

        </aside>}
      </main>

      <footer className="forensic-footer">
        <button onClick={() => document.querySelector('.status-panel textarea')?.focus()}>▤ Add Analyst Note</button>
        <button onClick={() => setActiveTab('IOC Analysis')}>◇ Tag Evidence</button>
        <button onClick={() => window.print()}>▣ Create Snapshot</button>
        <button onClick={() => setActiveTab('Timeline')}>⇧ Escalate Case</button>
        <button onClick={exportReport} className="report-button">▤ Generate Forensic Report ›</button>
      </footer>

      <style>{styles}</style>
    </div>
  );
}

function Metric({ icon, label, value, color }) {
  return <div className="metric-card"><span className="metric-icon" style={{ color }}>{icon}</span><div><span>{label}</span><strong style={{ color }}>{value}</strong></div></div>;
}

function AIAnalysis({ incident, onRun, running, message }) {
  const investigation = incident?.aiInvestigation || {};
  const summary = String(investigation.summary || incident?.aiAnalysis || '').trim();
  const rootCause = String(investigation.rootCause || '').trim();
  const reasoning = String(investigation.reasoning || '').trim();
  const recommendations = (
    Array.isArray(investigation.recommendedSteps) && investigation.recommendedSteps.length
      ? investigation.recommendedSteps
      : incident?.recommendedActions
  ) || [];
  const aiConfidence = Math.max(0, Math.min(100, Number(investigation.confidence || 0)));
  const hasAnalysis = Boolean(summary || rootCause || reasoning || recommendations.length || aiConfidence);
  const status = String(investigation.status || (hasAnalysis ? 'completed' : 'not_generated')).replace(/_/g, ' ');

  return <div className="ai-grid without-collection">
    <article className="forensic-card summary-card">
      <div className="card-title ai-analysis-heading">
        <div>AI Forensic Analysis <span>{status}</span></div>
        <button type="button" className="ai-run-button" onClick={onRun} disabled={running}>
          {running ? '✦ Analyzing…' : '✦ Run AI Analysis'}
        </button>
      </div>
      {message && <div className={`ai-run-message ${/failed|error|not configured/i.test(message) ? 'error' : ''}`}>{message}</div>}
      {hasAnalysis ? <>
        {summary && <><h3>Executive Summary</h3><p>{summary}</p></>}
        {rootCause && <><h3>Root Cause</h3><p>{rootCause}</p></>}
        {reasoning && <><h3>Analysis Reasoning</h3><p>{reasoning}</p></>}
        {aiConfidence > 0 && <>
          <h3>AI Confidence <span className="info-dot">i</span></h3>
          <div className="confidence-number">{aiConfidence}%</div>
          <div className="progress"><i style={{ width: `${aiConfidence}%` }} /></div>
        </>}
      </> : <div className="ai-empty-state">
        <strong>No AI analysis returned by the backend</strong>
        <p>This incident does not currently contain an AI summary, root cause, reasoning, or confidence result.</p>
      </div>}
    </article>
    <div className="ai-stack"><article className="forensic-card"><div className="card-title">AI Recommended Actions</div>{recommendations.length
      ? recommendations.map((text, index) => <div className="recommendation" key={`${text}-${index}`}><b>{index + 1}</b><div><strong>{text}</strong></div></div>)
      : <div className="ai-empty-state compact"><strong>No recommended actions returned</strong><p>The backend recommendation list is empty.</p></div>}
    </article>
    </div>
  </div>;
}

const VELOCIRAPTOR_ARTIFACT_SETS = {
  'Endpoint overview': ['Generic.Client.Info'],
};

function incidentArtifactPlan(incident, osType = '') {
  const evidence = Array.isArray(incident?.alertIds) ? incident.alertIds : [];
  const signal = [
    incident?.title, incident?.description, incident?.patternCode,
    incident?.eventCategory, incident?.sourceType, incident?.source,
    incident?.mitreTechnique, ...(incident?.mitreTactics || []),
    ...evidence.flatMap(item => [
      item?.title, item?.description, item?.eventCategory, item?.sourceType,
      item?.source, item?.type, item?.ruleId, item?.signatureName,
    ]),
  ].filter(Boolean).join(' ').toLowerCase();
  const windows = /windows/i.test(String(osType));
  const processArtifact = windows ? 'Windows.System.Pslist' : 'Linux.Sys.Pslist';
  const networkArtifact = windows ? 'Windows.Network.Netstat' : 'Linux.Network.Netstat';
  const network = Boolean(incident?.networkInvolved)
    || evidence.some(isNetworkEvidence)
    || /\b(network|ids|ips|firewall|zeek|suricata|dns|ioc|c2|connection|port scan|lateral)\b/.test(signal);
  const process = /\b(edr|process|command|execution|script|powershell|malware|ransomware|binary|executable|persistence|privilege|root login|ssh|brute force)\b/.test(signal);
  const platform = windows ? 'Windows' : 'Linux';

  if (network && process) return {
    name: `Mixed endpoint + network triage (${platform})`,
    artifacts: ['Generic.Client.Info', processArtifact, networkArtifact],
    reason: 'Process and network signals both participated in this incident.',
  };
  if (network) return {
    name: `Network / IDS / IPS triage (${platform})`,
    artifacts: ['Generic.Client.Info', networkArtifact],
    reason: 'Network, IDS, IPS, firewall, DNS, or threat-intelligence evidence was detected.',
  };
  if (process) return {
    name: `Process / EDR triage (${platform})`,
    artifacts: ['Generic.Client.Info', processArtifact],
    reason: 'Endpoint process, execution, authentication, or malware activity was detected.',
  };
  return {
    name: 'Endpoint overview',
    artifacts: VELOCIRAPTOR_ARTIFACT_SETS['Endpoint overview'],
    reason: 'No specialized evidence type was detected; endpoint identity collection is sufficient.',
  };
}

function EndpointCollection({ endpoint, incident, compact = false }) {
  const companyId = incident?.companyId?._id || incident?.companyId;
  const systemId = incident?.systemId?._id || incident?.systemId;
  const [workspace, setWorkspace] = useState(null);
  const [loading, setLoading] = useState(true);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [selectedJobId, setSelectedJobId] = useState('');
  const [selectedJobOutput, setSelectedJobOutput] = useState(null);
  const [outputLoading, setOutputLoading] = useState(false);

  const loadWorkspace = useCallback(async ({ quiet = false } = {}) => {
    if (!companyId) {
      setError('Incident company scope is missing.');
      setLoading(false);
      return null;
    }
    if (!systemId || !/^[a-f\d]{24}$/i.test(String(systemId))) {
      setWorkspace(null);
      setError('This incident is not mapped to a valid endpoint yet. Linked alert and hostname evidence could not identify a system.');
      setLoading(false);
      return null;
    }
    if (!quiet) setLoading(true);
    try {
      const { data } = await api.get('/forensics/endpoint', {
        params: { companyId, systemId }, skipCache: true,
      });
      setWorkspace(data);
      setError(data?.server?.error || '');
      return data;
    } catch (err) {
      setError(err.response?.data?.message || 'Velociraptor workspace could not be loaded.');
      return null;
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [companyId, systemId]);

  useEffect(() => { loadWorkspace(); }, [loadWorkspace]);

  const target = useMemo(() => {
    const systems = workspace?.system ? [workspace.system] : (workspace?.systems || []);
    return systems.find(item => String(item._id) === String(systemId))
      || systems.find(item => [item.hostname, item.name].some(value => String(value || '').toLowerCase() === String(endpoint || '').toLowerCase()))
      || null;
  }, [workspace, systemId, endpoint]);
  const clients = workspace?.client ? [workspace.client] : (workspace?.clients || []);
  const storedClient = clients.find(item => item.clientId === target?.velociraptorClientId);
  const targetNames = [target?.hostname, target?.name, endpoint].filter(Boolean).map(value => String(value).toLowerCase());
  const hostnameClient = clients.find(item => targetNames.includes(String(item.hostname || '').toLowerCase()));
  const liveClient = storedClient || hostnameClient;
  const clientId = liveClient?.clientId || target?.velociraptorClientId || '';
  const artifactPlan = useMemo(
    () => incidentArtifactPlan(incident, target?.osType || liveClient?.os),
    [incident, target?.osType, liveClient?.os],
  );
  const incidentJobKeys = [
    incident?._id,
    incident?.correlationId,
    incident?.incidentId,
  ].filter(Boolean).map(value => String(value).toLowerCase());
  const jobs = (workspace?.hunts || []).filter(item => {
    const sameIncident = item.incidentId && String(item.incidentId?._id || item.incidentId) === String(incident?._id);
    const legacyNameMatch = incidentJobKeys.length && incidentJobKeys.some(key => String(item.name || '').toLowerCase().includes(key));
    if (!sameIncident && !legacyNameMatch) return false;
    return (target?._id && String(item.systemId?._id || item.systemId) === String(target._id))
      || (clientId && item.clientId === clientId);
  });
  const activeJobKey = jobs.filter(item => ['queued', 'running'].includes(String(item.status))).map(item => item._id).join(',');
  const selectedJob = jobs.find(item => String(item._id) === String(selectedJobId));
  useEffect(() => {
    if (!activeJobKey) return undefined;
    const timer = window.setInterval(() => loadWorkspace({ quiet: true }), 2000);
    return () => window.clearInterval(timer);
  }, [activeJobKey, loadWorkspace]);
  const selectedArtifacts = artifactPlan.artifacts;
  const serverReady = Boolean(workspace?.server?.configured && workspace?.server?.connected);
  const endpointReady = Boolean(serverReady && target && clientId && liveClient);

  const toggleJobOutput = async item => {
    if (String(selectedJobId) === String(item._id)) {
      setSelectedJobId('');
      setSelectedJobOutput(null);
      return;
    }
    setSelectedJobId(item._id);
    setSelectedJobOutput(item.error ? item : null);
    if (item.error) return;
    setOutputLoading(true);
    try {
      const { data } = await api.get(`/forensics/hunts/${item._id}/output`, {
        params: { companyId }, skipCache: true,
      });
      setSelectedJobOutput(data?.hunt || null);
    } catch (err) {
      setSelectedJobOutput({ ...item, error: err.response?.data?.message || 'Velociraptor output could not be loaded.' });
    } finally {
      setOutputLoading(false);
    }
  };

  const launchCollection = async label => {
    if (!endpointReady || launching) return;
    setLaunching(true); setError(''); setNotice('');
    try {
      const { data } = await api.post('/forensics/hunts', {
        companyId,
        systemId: target._id,
        ...(incident?.resourceType === 'ticket' ? {} : { incidentId: incident?._id }),
        clientId,
        name: `${label}: ${incident?.correlationId || incident?._id}`,
        artifacts: selectedArtifacts,
      });
      setNotice(`Real Velociraptor collection queued: ${data?.hunt?._id || 'job created'}`);
      for (let attempt = 0; attempt < 15; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        const next = await loadWorkspace({ quiet: true });
        const job = (next?.hunts || []).find(item => String(item._id) === String(data?.hunt?._id));
        if (['completed', 'failed', 'cancelled'].includes(String(job?.status))) break;
      }
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Velociraptor collection failed.');
    } finally { setLaunching(false); }
  };

  const lastSeen = liveClient?.lastSeenAt
    ? safeDate(Number(liveClient.lastSeenAt) > 1e13 ? Number(liveClient.lastSeenAt) / 1000 : liveClient.lastSeenAt)
    : safeDate(target?.lastSeen);

  return <div className={`collection-stack ${compact ? 'compact' : ''}`}>
    <article className="forensic-card collection-card">
      <div className="card-title"><span className="collection-title">▽ Velociraptor Endpoint Collection</span></div>
      <div className="endpoint-summary">
        <div><span>Endpoint</span><strong>{target?.hostname || target?.name || endpoint}</strong></div>
        <div><span>Client ID</span><strong>{clientId || 'Not mapped'}</strong></div>
        <div><span>Server / Client</span><strong className={endpointReady ? 'online-dot' : 'offline-dot'}>● {endpointReady ? 'Connected' : loading ? 'Checking…' : 'Offline'}</strong></div>
        <div><span>Last Seen</span><strong>{lastSeen}</strong></div>
      </div>
      <label>Artifact Set <span className="auto-plan-label">AUTO · INCIDENT-AWARE</span></label>
      <div className="artifact-select auto-artifact-set"><strong>{artifactPlan.name}</strong><span>Automatically selected</span></div>
      <div className="artifact-plan-reason">{artifactPlan.reason}</div>
      <label>Selected Artifacts</label><div className="artifact-tags">{selectedArtifacts.map(name => <span key={name}>{name}</span>)}</div>
      {error && <div className="collection-message error">{error}</div>}
      {notice && <div className="collection-message ok">{notice}</div>}
      {!error && !notice && <div className="approval-note">{endpointReady ? '● Live Velociraptor API and endpoint verified' : '▲ A connected server and mapped client are required'}</div>}
      <div className="collection-actions">
        <button disabled={!endpointReady || launching} onClick={() => launchCollection(incident?.resourceType === 'ticket' ? 'Ticket collection' : 'Incident collection')}>{launching ? 'Collecting…' : '▶ Start Collection'}</button>
        <button disabled={!endpointReady || launching} onClick={() => launchCollection(incident?.resourceType === 'ticket' ? 'Ticket hunt' : 'Incident hunt')}>⌁ Run Hunt</button>
        <button disabled={loading} onClick={() => loadWorkspace()}>↻ Refresh</button>
      </div>
    </article>
    <article className="forensic-card jobs-card">
      <div className="card-title">Real Collection Jobs</div>
      <div className="jobs-head"><span>Job ID</span><span>Artifact</span><span>Status</span><span>Result</span><span>Output</span></div>
      {jobs.length ? jobs.slice(0, 8).map(item => {
        const hasOutput = Number(item.providerResult?.flow?.total_collected_rows || 0) > 0
          || (item.providerResult?.flow?.artifacts_with_results || []).length > 0;
        return <div className="job-row" key={item._id}>
          <span title={item._id}>{String(item._id).slice(-8)}</span>
          <span title={(item.artifacts || []).join(', ')}>{(item.artifacts || []).join(', ')}</span>
          <span className={`job-status ${item.status}`}>{item.status}</span>
          <span>{item.error ? 'Error' : item.providerResult ? `${item.providerResult?.flow?.total_collected_rows ?? 0} rows` : 'Pending'}</span>
          <span><button className="view-output-button" disabled={outputLoading || (!hasOutput && !item.error)} onClick={() => toggleJobOutput(item)}>{String(selectedJobId) === String(item._id) ? (outputLoading ? 'Loading…' : 'Hide') : item.error ? 'View Error' : hasOutput ? 'View Output' : 'Waiting'}</button></span>
        </div>;
      }) : <div className="empty-job">No real Velociraptor collection has been launched for this {incident?.resourceType === 'ticket' ? 'ticket' : 'incident'}.</div>}
      {selectedJob && outputLoading && <div className="empty-job">Loading real Velociraptor output…</div>}
      {selectedJob && selectedJobOutput && !outputLoading && <VelociraptorOutput job={{ ...selectedJob, ...selectedJobOutput }} />}
    </article>
  </div>;
}

function outputCell(value) {
  if (value == null || value === '') return '—';
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

function VelociraptorOutput({ job, rowLimit = 100 }) {
  const flow = job.providerResult?.flow || {};
  const resultEntries = Object.entries(job.providerResult?.results || {});
  return <div className="velociraptor-output">
    <div className="output-summary">
      <div><span>Flow ID</span><b>{flow.session_id || job.providerResult?.launch?.flow_id || '—'}</b></div>
      <div><span>State</span><b className={job.status === 'completed' ? 'ok' : 'bad'}>{flow.state || job.status}</b></div>
      <div><span>Collected Rows</span><b>{flow.total_collected_rows ?? 0}</b></div>
      <div><span>Completed</span><b>{safeDate(job.completedAt)}</b></div>
    </div>
    {job.error && <div className="output-error">{job.error}</div>}
    {!job.error && !resultEntries.length && <div className="empty-job">The collection has not returned output rows yet.</div>}
    {resultEntries.map(([artifact, rows]) => {
      const safeRows = Array.isArray(rows) ? rows.slice(0, rowLimit) : [];
      const columns = [...new Set(safeRows.flatMap(row => Object.keys(row || {})))].slice(0, 12);
      return <section className="artifact-output" key={artifact}>
        <div className="artifact-output-title"><b>{artifact}</b><span>{Array.isArray(rows) ? rows.length : 0} row(s){rows?.length > rowLimit ? ` · showing first ${rowLimit}` : ''}</span></div>
        {safeRows.length ? <div className="output-table-wrap"><table><thead><tr>{columns.map(column => <th key={column}>{column}</th>)}</tr></thead><tbody>{safeRows.map((row, index) => <tr key={index}>{columns.map(column => <td key={column} title={outputCell(row?.[column])}>{outputCell(row?.[column])}</td>)}</tr>)}</tbody></table></div> : <div className="empty-artifact-output">No rows returned for this artifact.</div>}
      </section>;
    })}
  </div>;
}

function Overview({ incident, evidence, endpoint, mitre }) {
  const company = typeof incident.companyId === 'object' ? incident.companyId : null;
  const companyId = company?._id || incident.companyId || '—';
  const networkCount = Array.isArray(incident.networkEvidence) ? incident.networkEvidence.length : 0;
  const iocCount = Array.isArray(incident.iocs) ? incident.iocs.length : 0;
  const outputItems = [
    ['Severity', incident.severity || '—'],
    ['Status', String(incident.status || '—').replace(/_/g, ' ')],
    ['Category', String(incident.category || 'other').replace(/_/g, ' ')],
    ['Confidence', `${Number(incident.confidenceScore || 0)}%`],
    ['Correlated Events', evidence.length],
    ['Network Evidence', networkCount],
    ['IOC Matches', iocCount],
    ['Incident Source', String(incident.incidentSource || 'edr').replace(/_/g, ' ')],
  ];

  return <div className="overview-page">
    <section className="overview-context-grid">
      <article className="forensic-card company-overview-card">
        <div className="card-title">Company Overview</div>
        <div className="company-name">{company?.name || 'Company'}</div>
        <div className="company-details">
          <div><span>Company ID</span><b title={companyId}>{companyId}</b></div>
          <div><span>Department</span><b>{incident.departmentId?.name || 'All Departments'}</b></div>
          <div><span>Industry</span><b>{company?.industry || 'Not configured'}</b></div>
          <div><span>Country</span><b>{company?.country || 'Not configured'}</b></div>
          <div><span>Company Size</span><b>{company?.companySize || 'Not configured'}</b></div>
          <div><span>Company Status</span><b className="company-active">{company?.status || 'active'}</b></div>
          <div><span>Assigned Analyst</span><b>{incident.assignedTo?.name || 'Unassigned'}</b></div>
          <div><span>Affected Endpoint</span><b>{endpoint}</b></div>
        </div>
      </article>

      <article className="forensic-card incident-output-card">
        <div className="card-title">Incident Output</div>
        <div className="incident-output-grid">
          {outputItems.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
        </div>
      </article>
    </section>

    <section className="overview-context-grid overview-lower-grid">
      <article className="forensic-card">
        <div className="card-title">What Happened</div>
        <p>{incident.description || 'No description available.'}</p>
        <div className="card-title">MITRE ATT&amp;CK</div>
        <div className="tag-list">{mitre.length ? mitre.map(item => <span key={item}>{item}</span>) : <span>Not mapped</span>}</div>
      </article>
      <article className="forensic-card">
        <div className="card-title">Incident Timing</div>
        <p>First observed: {safeDate(incident.firstEventAt)}</p>
        <p>Last activity: {safeDate(incident.lastEventAt)}</p>
        <p>Created: {safeDate(incident.createdAt)}</p>
      </article>
    </section>
    <CombinedForensicOutput incident={incident} />
  </div>;
}

function CombinedForensicOutput({ incident }) {
  const companyId = incident?.companyId?._id || incident?.companyId;
  const systemId = incident?.systemId?._id || incident?.systemId;
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(Boolean(companyId && systemId));
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    if (!companyId || !systemId) {
      setLoading(false);
      return () => { active = false; };
    }
    (async () => {
      try {
        const { data: workspace } = await api.get('/forensics/endpoint', {
          params: { companyId, systemId }, skipCache: true,
        });
        const incidentKeys = [incident?._id, incident?.correlationId, incident?.incidentId]
          .filter(Boolean)
          .map(value => String(value).toLowerCase());
        const latest = (workspace?.hunts || []).find(item => {
          const linkedIncidentId = item.incidentId?._id || item.incidentId;
          const exactIncidentMatch = linkedIncidentId && String(linkedIncidentId) === String(incident?._id);
          const legacyNameMatch = !linkedIncidentId && incidentKeys.some(key => String(item.name || '').toLowerCase().includes(key));
          return (exactIncidentMatch || legacyNameMatch)
            && item.status === 'completed'
            && Number(item.providerResult?.flow?.total_collected_rows || 0) > 0;
        });
        if (!latest) {
          if (active) setError('No completed Velociraptor collection output is available for this incident.');
          return;
        }
        const { data } = await api.get(`/forensics/hunts/${latest._id}/output`, {
          params: { companyId }, skipCache: true,
        });
        if (active) setJob(data?.hunt || null);
      } catch (err) {
        if (active) setError(err.response?.data?.message || 'Combined Velociraptor output could not be loaded.');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, [companyId, systemId, incident?._id, incident?.correlationId, incident?.incidentId]);

  return <article className="forensic-card combined-output-card">
    <div className="card-title">
      <span className="combined-output-title">Combined Velociraptor Output</span>
      {job?._id && <small>Latest job · {String(job._id).slice(-8)}</small>}
    </div>
    {loading && <div className="combined-output-state">Loading latest completed collection…</div>}
    {!loading && error && <div className="combined-output-state">{error}</div>}
    {!loading && job && <VelociraptorOutput job={job} rowLimit={10} />}
  </article>;
}

function EvidenceTable({ evidence, empty = 'No correlated evidence is linked to this incident.' }) { return evidence.length ? <div className="evidence-table"><div className="evidence-row header"><span>Time</span><span>Source</span><span>Evidence</span><span>Severity</span></div>{evidence.map((item, index) => <div className="evidence-row" key={item._id || index}><span>{item.createdAt ? new Date(item.createdAt).toLocaleTimeString() : '—'}</span><span>{item.source || item.sourceType || item.eventCategory || 'Alert'}</span><span title={item.description}>{item.description || item.signatureName || item.ruleId || 'Security event'}</span><span style={{ color: severityColor[item.severity] }}>{item.severity || '—'}</span></div>)}</div> : <div className="empty-panel">{empty}</div>; }

function NetworkEvidenceTable({ evidence = [], scope, error, networkInvolved }) {
  if (!evidence.length) return <div className="empty-panel">{error || (networkInvolved
    ? 'Network telemetry participated in correlation, but its evidence records are no longer available.'
    : 'Network telemetry did not participate in this EDR correlation incident.')}</div>;
  return <div className="network-evidence-panel">
    <div className="network-scope-note">
      <b>{evidence.length} real network event(s)</b>
      <span>Same endpoint · {scope?.startAt ? safeDate(scope.startAt) : 'incident start'} to {scope?.endAt ? safeDate(scope.endAt) : 'incident end'}</span>
    </div>
    <div className="network-evidence-table">
      <div className="network-evidence-row header"><span>Time</span><span>Source</span><span>Source → Destination</span><span>Domain / DNS</span><span>Protocol</span><span>Evidence</span><span>Severity</span></div>
      {evidence.map((item, index) => {
        const sourceIp = item.srcip || '—';
        const destination = item.destip || '—';
        const sourcePort = item.srcport ? `:${item.srcport}` : '';
        const destinationPort = item.destport ? `:${item.destport}` : '';
        return <div className="network-evidence-row" key={item._id || item.eventId || index}>
          <span>{item.createdAt ? new Date(item.createdAt).toLocaleTimeString() : '—'}</span>
          <span><b>{item.sourceType || item.source || item.eventCategory || 'network'}</b><small>{item.ruleId || item.type || ''}</small></span>
          <span className="mono">{sourceIp}{sourcePort} → {destination}{destinationPort}</span>
          <span className="mono">{item.domain || item.dnsQuery || '—'}</span>
          <span>{item.protocol || '—'}</span>
          <span title={item.description}>{item.description || item.normalizedEventType || 'Network telemetry'}</span>
          <span style={{ color: severityColor[item.severity] || '#cbd5e1' }}>{item.severity || '—'}</span>
        </div>;
      })}
    </div>
  </div>;
}

function IOCPanel({ iocs }) { return <article className="forensic-card"><div className="card-title">Indicators of Compromise ({iocs.length})</div>{iocs.length ? iocs.map((ioc, index) => <div className="ioc-row" key={`${ioc.value}-${index}`}><span>{ioc.type || 'indicator'}</span><strong>{ioc.value || ioc.indicator}</strong><p>{ioc.context || 'Threat-intelligence evidence'}</p></div>) : <div className="empty-panel">No IOC evidence is attached.</div>}</article>; }
function custodyIcon(action = '') {
  if (/failed|warning/i.test(action)) return '!';
  if (/ai analysis|ai_analysis/i.test(action)) return '✦';
  if (/integrity|verified|sealed|collected/i.test(action)) return '✓';
  if (/velociraptor|collection|hunt/i.test(action)) return '▽';
  if (/note/i.test(action)) return '▤';
  if (/assign/i.test(action)) return '♙';
  if (/resolve|close/i.test(action)) return '◆';
  return '●';
}

function evidenceBytes(value) {
  const size = Number(value || 0);
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function CustodyPanel({ incident }) {
  const fallback = [{
    id: `incident-created-${incident._id}`,
    action: 'incident_created', title: 'Incident created and registered',
    at: incident.createdAt, actor: { name: 'SOC Correlation Engine', role: 'system' },
    details: `${incident.alertIds?.length || 0} correlated alert(s) linked to this case.`,
    integrityStatus: 'verified',
  }];
  const events = Array.isArray(incident.chainOfCustody) && incident.chainOfCustody.length
    ? incident.chainOfCustody : fallback;
  const evidenceIds = new Set(events.map(item => item.evidence?.evidenceId).filter(Boolean));
  const verified = events.filter(item => item.integrityStatus === 'verified').length;
  const lastEvent = events[events.length - 1];

  return <div className="custody-page">
    <section className="custody-summary">
      <div><span>Total Audit Events</span><strong>{events.length}</strong></div>
      <div><span>Forensic Evidence</span><strong>{evidenceIds.size}</strong></div>
      <div><span>Integrity Verified</span><strong className="verified">{verified}/{events.length}</strong></div>
      <div><span>Last Custody Activity</span><strong className="last-activity">{safeDate(lastEvent?.at)}</strong></div>
    </section>

    <article className="forensic-card custody-card">
      <div className="card-title">
        <span className="custody-title">Immutable Chain of Custody</span>
        <small>Chronological · company scoped · evidence linked</small>
      </div>
      <div className="custody-timeline">
        {events.map((event, index) => {
          const warning = event.integrityStatus === 'warning' || event.integrityStatus === 'mismatch' || /failed/i.test(event.action || '');
          return <div className={`custody-timeline-event ${warning ? 'warning' : ''}`} key={event.id || index}>
            <div className="custody-marker"><i>{custodyIcon(`${event.action} ${event.title}`)}</i>{index < events.length - 1 && <span />}</div>
            <div className="custody-event-body">
              <div className="custody-event-heading">
                <div><b>{event.title || String(event.action || 'Custody event').replace(/[._]/g, ' ')}</b><em>{String(event.action || 'audit_event').replace(/[._]/g, ' ')}</em></div>
                <time>{safeDate(event.at)}</time>
              </div>
              <div className="custody-actor-row">
                <span>Actor <b>{event.actor?.name || 'System'}</b></span>
                <span>Role <b>{String(event.actor?.role || 'system').replace(/_/g, ' ')}</b></span>
                {event.sourceIp && <span>Source IP <b className="mono">{event.sourceIp}</b></span>}
                <span className={warning ? 'custody-warning' : 'custody-verified'}>{warning ? '⚠ Review required' : '✓ Verified'}</span>
              </div>
              {event.details && <p>{event.details}</p>}
              {event.evidence && <div className="custody-evidence">
                <div><span>Evidence ID</span><b>{event.evidence.evidenceId}</b></div>
                <div><span>SHA-256</span><code title={event.evidence.sha256}>{event.evidence.sha256}</code></div>
                <div><span>Size</span><b>{evidenceBytes(event.evidence.sizeBytes)}</b></div>
                <div><span>Integrity</span><b className={event.evidence.integrityStatus === 'verified' ? 'ok' : 'bad'}>{event.evidence.integrityStatus}</b></div>
              </div>}
            </div>
          </div>;
        })}
      </div>
    </article>
  </div>;
}

const styles = `
.forensic-workspace{min-width:0;color:#dbeafe;background:radial-gradient(circle at 24% 20%,rgba(0,132,172,.16),transparent 38%),linear-gradient(180deg,#061726,#06111f 65%,#04101b);border:1px solid #1d4560;border-radius:3px;padding:7px;box-shadow:0 18px 52px rgba(0,0,0,.34);font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
.forensic-header{display:flex;justify-content:space-between;gap:16px;padding:5px 7px 8px}.forensic-title-area{min-width:0}.back-link{display:inline-flex!important;align-items:center;justify-content:center;height:31px;margin:0 0 9px;padding:0 14px!important;border:1px solid #ef4444!important;border-radius:5px!important;background:linear-gradient(135deg,#dc2626,#991b1b)!important;color:#fff!important;font-size:11px!important;font-weight:850!important;line-height:1!important;cursor:pointer;box-shadow:0 5px 16px rgba(220,38,38,.28);transition:transform .15s ease,filter .15s ease,box-shadow .15s ease}.back-link:hover{filter:brightness(1.15);transform:translateY(-1px);box-shadow:0 7px 20px rgba(239,68,68,.35)}.back-link:active{transform:translateY(0)}.eyebrow{display:block;color:#8aa1b5;font-size:9px;margin:0 0 3px}.title-line{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.title-line h1{margin:0;color:#eef7ff;font-size:19px;line-height:1.05;font-weight:800}.severity-pill,.status-pill{height:25px;padding:5px 9px;border:1px solid #315977;border-radius:4px;font-size:10px;text-transform:capitalize}.status-pill{color:#93c5fd;background:#071c2e}.header-status{appearance:auto;min-width:142px}.case-meta{display:flex;gap:18px;flex-wrap:wrap;margin-top:8px;color:#8fa4b8;font-size:9px}.header-actions{display:flex;gap:8px;align-items:flex-start;flex-wrap:wrap}.header-actions button,.forensic-footer button{height:32px;padding:0 18px;border:1px solid #17608a;border-radius:4px;background:#071b2d;color:#7dd3fc;font-size:10px;cursor:pointer}.header-actions .primary-action{min-width:116px;background:linear-gradient(90deg,#6d4df3,#2563eb);color:#fff;border-color:#755cff;box-shadow:0 0 18px rgba(99,102,241,.18)}.header-actions .cyan-action{min-width:116px;border-color:#00c7d8;color:#67e8f9;background:#072132}
.metric-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:6px}.metric-card{display:flex;align-items:center;gap:13px;min-height:50px;padding:7px 14px;border:1px solid #173a52;border-radius:4px;background:linear-gradient(145deg,#0c2132,#0a1a2b)}.metric-icon{font-size:24px}.metric-card span:not(.metric-icon){display:block;color:#8398ab;font-size:9px}.metric-card strong{display:block;margin-top:3px;font-size:16px;line-height:1}
.forensic-tabs{display:flex;margin-top:6px;border:1px solid #12344c;border-radius:4px;overflow:auto;background:#061827}.forensic-tabs button{flex:1;min-width:95px;height:25px;padding:0 6px;border:0;border-bottom:2px solid transparent;background:transparent;color:#7f94a7;font-size:8px;cursor:pointer}.forensic-tabs button.active{color:#60a5fa;border-bottom-color:#3b82f6;background:#0a2033}
.forensic-main{display:grid;grid-template-columns:minmax(0,1fr) 224px;gap:6px;margin-top:6px;align-items:stretch}.forensic-main.without-side-rail{grid-template-columns:minmax(0,1fr)}.analysis-board{min-width:0;height:100%}.ai-grid{display:grid;grid-template-columns:.92fr .76fr 1.18fr;gap:6px;align-items:stretch;height:100%;min-height:568px}.ai-grid.without-collection{grid-template-columns:minmax(0,1.25fr) minmax(280px,.75fr)}.ai-stack,.collection-stack{display:grid;gap:6px;min-width:0;height:100%}.forensic-card,.status-panel,.risk-strip,.review-strip{border:1px solid #163a52;border-radius:4px;background:linear-gradient(145deg,rgba(9,28,44,.96),rgba(7,23,37,.96));padding:9px;min-width:0}.summary-card{height:100%;display:flex;flex-direction:column}.ai-stack>.forensic-card,.status-panel{height:100%;box-sizing:border-box}.collection-stack{grid-template-rows:auto auto;align-content:start;align-self:start;height:auto}.collection-card,.jobs-card{height:auto;box-sizing:border-box}.card-title,.panel-heading{display:flex;justify-content:space-between;align-items:center;color:#d8e9f7;font-size:11px;font-weight:700;margin-bottom:8px}.card-title span{padding:2px 5px;border:1px solid #6549a4;border-radius:3px;color:#c4b5fd;font-size:7px;font-weight:600}.card-title .collection-title{padding:0;border:0;color:#67e8f9;font-size:11px}.forensic-card h3{margin:9px 0 5px;color:#c9d9e6;font-size:9px}.forensic-card p,.forensic-card li{color:#9aafc0;font-size:8px;line-height:1.48}.forensic-card ul{padding-left:0;margin:0 0 8px}.finding-list{list-style:none}.finding-list li{position:relative;padding-left:15px;margin:4px 0}.finding-list li:before{content:"✓";position:absolute;left:0;top:0;color:#4ade80;border:1px solid rgba(74,222,128,.65);border-radius:50%;width:9px;height:9px;display:grid;place-items:center;font-size:6px;line-height:1}.info-dot{display:inline-grid;place-items:center;width:9px;height:9px;border:1px solid #7890a3;border-radius:50%;font-size:7px;color:#9fb4c7}.confidence-number{color:#4ade80;font-size:20px;line-height:1}.progress{height:4px;background:#18374b;margin:4px 0 10px}.progress i{display:block;height:100%;background:#4ade80}.tag-list{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:5px}.tag-list span{min-width:0;padding:6px 7px;border:1px solid #1b4c6b;background:#0a2236;color:#9bc9ea;font-size:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.mitre-tiles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:5px}.mitre-tiles span{min-width:0;padding:7px 7px;border:1px solid #1b4c6b;background:#0a2236;border-radius:3px}.mitre-tiles b{display:block;color:#60a5fa;font-size:9px;line-height:1}.mitre-tiles small{display:block;margin-top:4px;color:#9aafc0;font-size:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.summary-actions{display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px;margin-top:auto;padding-top:10px}.summary-actions button{height:25px;border-radius:3px;background:#081c2d;border:1px solid #2a5f89;color:#60a5fa;font-size:7px;cursor:pointer}.summary-actions button:first-child{border-color:#6d4df3;color:#c4b5fd}.summary-actions button:nth-child(2){border-color:#2f7d48;color:#86efac;background:#092718}.recommendation{display:grid;grid-template-columns:19px minmax(0,1fr) 39px;gap:7px;padding:8px 0;border-bottom:1px solid #143248}.recommendation:first-of-type{padding-top:2px}.recommendation>b{display:grid;place-items:center;width:17px;height:17px;background:#44318d;color:#ddd6fe;font-size:8px;border-radius:3px}.recommendation strong{color:#cbd8e3;font-size:9px}.recommendation p{margin:3px 0 0}.recommendation button{align-self:center;height:22px;padding:0 6px;border:1px solid #25608a;background:#081c2d;color:#60a5fa;border-radius:3px;font-size:7px}.evidence-card{overflow:hidden}.evidence-table{min-width:0}.evidence-row{display:grid;grid-template-columns:48px 55px minmax(80px,1fr) 43px;gap:5px;padding:5px 2px;border-bottom:1px solid #133249;color:#91a8ba;font-size:7px}.evidence-row span{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}.evidence-row.header{color:#c2d3df;font-weight:700}.empty-panel{padding:24px;text-align:center;color:#64748b;font-size:10px}.overview-grid{display:grid;grid-template-columns:1.3fr .7fr;gap:6px}.ioc-row,.custody-event{padding:9px;border-bottom:1px solid #15354b}.ioc-row span{display:inline-block;width:90px;color:#60a5fa;font-size:9px}.ioc-row strong{color:#e2e8f0;font-size:10px}.ioc-row p,.custody-event p{margin-bottom:0}.custody-event{display:flex;gap:20px;flex-wrap:wrap;font-size:10px}.custody-event span{color:#71869a}
.endpoint-summary{display:grid;grid-template-columns:1.1fr 1.15fr .8fr 1fr;gap:6px;padding:7px;border:1px solid #183a51;background:#081929}.endpoint-summary span,.collection-card>label{display:block;color:#7e94a7;font-size:7px}.endpoint-summary strong{display:block;margin-top:3px;color:#d2e0ea;font-size:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.endpoint-summary .online-dot{color:#4ade80}.endpoint-summary .offline-dot{color:#fb7185}.collection-card>label{margin:8px 0 4px}.artifact-select{display:flex;justify-content:space-between;padding:7px;border:1px solid #1b4b6a;color:#9fb5c6;font-size:8px}.real-select{display:block;width:100%;box-sizing:border-box;background:#081929;appearance:auto}.real-select option{background:#081929;color:#dbeafe}.artifact-tags{display:flex;gap:4px;flex-wrap:wrap}.artifact-tags span{padding:4px;border:1px solid #1a4967;color:#8faabd;font-size:7px}.approval-note{margin:8px 0;color:#facc15;font-size:7px}.collection-message{margin:8px 0;padding:7px 9px;border:1px solid #235575;border-radius:3px;background:#092237;color:#7dd3fc;font-size:9px;font-weight:700}.collection-message.error{border-color:#7f1d1d;background:#2a1018;color:#fca5a5}.collection-message.ok{border-color:#166534;background:#082819;color:#86efac}.collection-actions{display:flex;gap:8px}.collection-actions button{height:25px;padding:0 15px;border:1px solid #176080;background:#08304a;color:#4dd9ee;font-size:8px}.collection-actions button:not(:disabled){cursor:pointer}.collection-actions button:disabled{opacity:.45}.jobs-head,.job-row{display:grid;grid-template-columns:70px minmax(140px,1fr) 70px 70px 82px;gap:7px;padding:7px 5px;border-bottom:1px solid #15354a;color:#8da3b4;font-size:8px;align-items:center}.jobs-head{color:#c1d2df;font-weight:800}.job-row>span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.job-status.queued{color:#facc15!important}.job-status.running{color:#38bdf8!important}.job-status.completed{color:#4ade80!important}.job-status.failed,.job-status.cancelled{color:#fb7185!important}.view-output-button{width:78px;padding:5px 6px;border:1px solid #256b96;border-radius:4px;background:#0a2940;color:#7dd3fc;font-size:8px;cursor:pointer}.view-output-button:disabled{opacity:.45;cursor:default}.velociraptor-output{margin-top:12px;border:1px solid #205170;border-radius:5px;background:#061624;padding:10px;overflow:hidden}.output-summary{display:grid;grid-template-columns:1.1fr .7fr .7fr 1fr;gap:8px;padding:9px;border:1px solid #173c55;background:#0a2032}.output-summary span{display:block;color:#7f94a7;font-size:8px}.output-summary b{display:block;margin-top:4px;color:#d9e7f2;font-size:10px;overflow:hidden;text-overflow:ellipsis}.output-summary b.ok{color:#4ade80}.output-summary b.bad{color:#fb7185}.output-error{margin-top:9px;padding:10px;border:1px solid #7f1d1d;background:#2a1018;color:#fca5a5;font-size:10px}.artifact-output{margin-top:11px;border:1px solid #17384f;border-radius:4px;overflow:hidden}.artifact-output-title{display:flex;justify-content:space-between;gap:10px;padding:9px 11px;background:#0c263b}.artifact-output-title b{color:#67e8f9;font-size:10px}.artifact-output-title span{color:#91a6b8;font-size:9px}.output-table-wrap{max-height:330px;overflow:auto}.output-table-wrap table{width:max-content;min-width:100%;border-collapse:collapse;font-size:9px}.output-table-wrap th{position:sticky;top:0;z-index:1;padding:8px;text-align:left;background:#102d43;color:#bae6fd;border-bottom:1px solid #27516b;white-space:nowrap}.output-table-wrap td{max-width:340px;padding:7px 8px;border-bottom:1px solid #15354a;color:#b5c6d5;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.output-table-wrap tr:nth-child(even) td{background:#091d2e}.empty-artifact-output{padding:15px;text-align:center;color:#71869a;font-size:9px}.empty-job{display:grid;place-items:center;height:118px;color:#64748b;text-align:center;font-size:8px}.side-rail{display:grid;grid-template-rows:1fr;gap:6px;align-content:stretch;min-width:0;height:100%;min-height:568px}
.status-panel label{display:block;margin:10px 0 5px;color:#8da3b5;font-size:8px}.current-status{padding:6px;border:1px solid #20557a;border-radius:3px;color:#60a5fa;font-size:9px;text-transform:capitalize}.status-panel .status-choice{display:flex;align-items:center;gap:5px;margin:5px 0;color:#9cafbe}.status-choice input{accent-color:#8b5cf6}.status-panel textarea{width:100%;height:78px;box-sizing:border-box;resize:vertical;padding:8px;border:1px solid #183b54;background:#081827;color:#dbeafe;font-size:9px}.status-panel small{display:block;text-align:right;color:#60778a;font-size:7px}.update-button{width:100%;margin-top:9px;height:31px;border:0;border-radius:2px;background:#2563eb;color:#fff;font-size:9px;cursor:pointer}.update-button:disabled{opacity:.5}.save-message{margin-top:7px;color:#fca5a5;font-size:8px}.save-message.ok{color:#4ade80}
.risk-strip{display:grid;grid-template-columns:.8fr .75fr 1fr;gap:0;padding:8px}.risk-strip div,.review-strip div{padding:0 8px;border-right:1px solid #15374e}.risk-strip div:last-child,.review-strip div:last-child{border:0}.risk-strip span,.review-strip span{display:block;color:#8398aa;font-size:8px}.risk-strip strong{display:block;margin-top:3px;font-size:14px;line-height:1}.review-strip{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:0;padding:8px}.review-strip strong{display:block;margin-top:3px;color:#93c5fd;font-size:8px;line-height:1.25}.review-strip div:first-child strong{color:#facc15}.forensic-footer{display:flex;gap:43px;margin-top:6px;padding:8px;border:1px solid #16384f;border-radius:4px;background:rgba(7,24,39,.72)}.forensic-footer button{flex:1}.forensic-footer .report-button{flex:1.6;background:#2563eb;color:white;margin-left:auto;font-weight:700}
.forensic-state{padding:42px;border:1px solid #1e3a5f;border-radius:10px;background:#0c192c;color:#fca5a5}.forensic-state button{margin-top:12px}

/* Readable SOC typography */
.forensic-workspace{font-size:13px}.back-link{font-size:11px!important;font-weight:800!important;color:#9fb8cc!important}.eyebrow{font-size:11px;font-weight:700;color:#9fb8cc}.title-line h1{font-size:22px;font-weight:900}.severity-pill,.status-pill{font-size:11px;font-weight:800}.case-meta{font-size:11px;font-weight:650;color:#aebfd0}.header-actions button,.forensic-footer button{font-size:11px;font-weight:750}.metric-card span:not(.metric-icon){font-size:10px;font-weight:700;color:#9fb2c5}.metric-card strong{font-size:18px;font-weight:900}.forensic-tabs button{height:34px;font-size:11px;font-weight:750}.card-title,.panel-heading{font-size:14px;font-weight:850;color:#edf6ff}.card-title span{font-size:9px;font-weight:750}.ai-analysis-heading>div{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.ai-run-button{min-width:150px;height:34px;padding:0 16px;border:1px solid #7657ff;border-radius:5px;background:linear-gradient(90deg,#6d4df3,#2563eb);color:#fff;font-size:11px;font-weight:850;cursor:pointer;box-shadow:0 0 18px rgba(99,102,241,.2)}.ai-run-button:disabled{cursor:wait;opacity:.65}.ai-run-message{margin:4px 0 12px;padding:9px 11px;border:1px solid #245b78;border-radius:4px;background:#092338;color:#7dd3fc;font-size:11px;font-weight:700}.ai-run-message.error{border-color:#7f1d1d;background:#2a1018;color:#fca5a5}.forensic-card h3{font-size:12px;font-weight:850;color:#e2edf7;margin:13px 0 7px}.forensic-card p,.forensic-card li{font-size:11px;line-height:1.58;color:#b7c7d8;font-weight:500}.finding-list li{margin:7px 0;padding-left:19px}.finding-list li:before{width:12px;height:12px;font-size:8px}.confidence-number{font-size:26px;font-weight:900}.mitre-tiles b{font-size:11px;font-weight:850}.mitre-tiles small{font-size:9px;color:#b3c3d2}.recommendation{padding:12px 2px;grid-template-columns:24px minmax(0,1fr)}.recommendation>b{width:22px;height:22px;font-size:10px;font-weight:900}.recommendation strong{font-size:11px;font-weight:850;color:#e1ebf4}.recommendation button{height:27px;font-size:9px;font-weight:750}.ai-empty-state{margin:auto 0;padding:28px;border:1px dashed #31516a;border-radius:6px;background:#071827}.ai-empty-state.compact{margin:12px 0;padding:18px}.ai-empty-state strong{display:block;color:#dbe7f1;font-size:13px;font-weight:850}.ai-empty-state p{margin:8px 0 0;color:#91a6b8}.evidence-row{grid-template-columns:76px 80px minmax(120px,1fr) 60px;gap:8px;padding:9px 5px;font-size:10px;color:#b2c3d2}.evidence-row.header{font-size:10px;font-weight:850;color:#e0eaf2}.network-evidence-panel{border:1px solid #173a52;border-radius:5px;background:#081827;overflow:hidden}.network-scope-note{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border-bottom:1px solid #173a52;background:#0b2135}.network-scope-note b{color:#67e8f9;font-size:12px}.network-scope-note span{color:#9fb2c5;font-size:10px}.network-evidence-table{overflow:auto;max-height:570px}.network-evidence-row{display:grid;grid-template-columns:86px 115px minmax(190px,1.1fr) minmax(145px,.8fr) 70px minmax(260px,1.6fr) 70px;gap:10px;min-width:1050px;padding:11px 13px;border-bottom:1px solid #15354b;color:#b7c7d8;font-size:10px;align-items:center}.network-evidence-row.header{position:sticky;top:0;z-index:1;background:#10283d;color:#e0edf7;font-weight:850}.network-evidence-row>span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.network-evidence-row span b{display:block;color:#dce9f4;font-weight:850}.network-evidence-row span small{display:block;margin-top:3px;color:#7890a4;font-size:8px}.network-evidence-row .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#8dd8ff}.overview-grid .card-title,.ioc-row .card-title{font-size:13px}.ioc-row span{font-size:11px;font-weight:750}.ioc-row strong{font-size:12px;font-weight:850}.custody-event{font-size:11px}.empty-panel,.empty-job{font-size:11px;font-weight:600;color:#8298aa}.endpoint-summary span,.collection-card>label{font-size:9px;font-weight:700}.endpoint-summary strong{font-size:11px;font-weight:800}.artifact-select,.artifact-tags span,.approval-note,.jobs-head,.job-row{font-size:9px}.status-panel label{font-size:10px;font-weight:700;color:#a5b7c7}.current-status{font-size:11px;font-weight:800}.status-panel .status-choice{font-size:11px;font-weight:650}.status-panel textarea{font-size:11px;line-height:1.45}.update-button{font-size:11px;font-weight:800}.risk-strip span,.review-strip span{font-size:10px;font-weight:700}.risk-strip strong{font-size:17px;font-weight:900}.review-strip strong{font-size:10px;font-weight:800}
.custody-page{display:grid;gap:8px}.custody-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px}.custody-summary>div{padding:13px 15px;border:1px solid #1b4662;border-radius:5px;background:linear-gradient(145deg,#0c263a,#081a2a)}.custody-summary span{display:block;color:#8ba1b3;font-size:9px;font-weight:750}.custody-summary strong{display:block;margin-top:6px;color:#7dd3fc;font-size:19px;font-weight:900}.custody-summary strong.verified{color:#4ade80}.custody-summary strong.last-activity{font-size:11px;color:#d8e7f2}.custody-card{overflow:hidden}.card-title .custody-title{padding:0;border:0;color:#67e8f9;font-size:14px}.custody-card .card-title small{color:#8298aa;font-size:9px}.custody-timeline{padding:4px 2px}.custody-timeline-event{display:grid;grid-template-columns:30px minmax(0,1fr);gap:8px}.custody-marker{position:relative;display:flex;justify-content:center}.custody-marker i{position:relative;z-index:1;display:grid;place-items:center;width:22px;height:22px;border:1px solid #1486a5;border-radius:50%;background:#08283a;color:#67e8f9;font-size:10px;font-style:normal;font-weight:900}.custody-marker span{position:absolute;top:22px;bottom:0;width:1px;background:#1b4a63}.custody-timeline-event.warning .custody-marker i{border-color:#b45309;background:#351c0b;color:#fbbf24}.custody-event-body{min-width:0;margin-bottom:9px;padding:11px 13px;border:1px solid #183c53;border-radius:5px;background:#081b2b}.custody-event-heading{display:flex;justify-content:space-between;gap:15px;align-items:flex-start}.custody-event-heading b{display:block;color:#e2edf6;font-size:12px}.custody-event-heading em{display:block;margin-top:4px;color:#67e8f9;font-size:8px;font-style:normal;text-transform:uppercase}.custody-event-heading time{flex:none;color:#91a6b8;font-size:9px}.custody-actor-row{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:9px;padding:7px 0;border-top:1px solid #13354b;border-bottom:1px solid #13354b;color:#8096a9;font-size:8px}.custody-actor-row span b{margin-left:4px;color:#c7d8e5;text-transform:capitalize}.custody-actor-row .custody-verified{margin-left:auto;color:#4ade80;font-weight:800}.custody-actor-row .custody-warning{margin-left:auto;color:#fbbf24;font-weight:800}.custody-event-body>p{margin:8px 0 0;color:#aabccc;font-size:10px}.custody-evidence{display:grid;grid-template-columns:1fr 2.5fr .65fr .65fr;gap:7px;margin-top:9px;padding:9px;border:1px solid #20526e;border-radius:4px;background:#071624}.custody-evidence>div{min-width:0}.custody-evidence span{display:block;color:#71889b;font-size:8px}.custody-evidence b,.custody-evidence code{display:block;margin-top:4px;color:#c9dbe8;font-size:9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.custody-evidence code{color:#7dd3fc}.custody-evidence b.ok{color:#4ade80;text-transform:capitalize}.custody-evidence b.bad{color:#fb7185;text-transform:capitalize}
.overview-page{display:grid;gap:8px}.overview-context-grid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(360px,.85fr);gap:8px}.company-name{margin:-1px 0 12px;color:#67e8f9;font-size:20px;font-weight:900}.company-details{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.company-details>div{min-width:0;padding:10px;border:1px solid #1a4059;border-radius:4px;background:#081c2d}.company-details span,.incident-output-grid span{display:block;color:#8399ab;font-size:9px;font-weight:700}.company-details b{display:block;margin-top:5px;color:#dceaf5;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.company-details .company-active{color:#4ade80;text-transform:capitalize}.incident-output-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.incident-output-grid>div{padding:12px;border:1px solid #1a4059;border-radius:4px;background:linear-gradient(145deg,#0b2438,#081a2b)}.incident-output-grid strong{display:block;margin-top:6px;color:#7dd3fc;font-size:15px;font-weight:900;text-transform:capitalize}.overview-lower-grid{grid-template-columns:minmax(0,1.4fr) minmax(300px,.6fr)}.combined-output-card{overflow:hidden}.card-title .combined-output-title{padding:0;border:0;color:#67e8f9;font-size:14px}.combined-output-card .card-title small{color:#8298aa;font-size:9px}.combined-output-card .velociraptor-output{margin-top:0}.combined-output-state{padding:24px;text-align:center;color:#8298aa;font-size:10px;font-weight:650}
.auto-plan-label{display:inline-block!important;margin-left:7px;padding:2px 6px;border:1px solid #155e75;border-radius:10px;background:#083344;color:#67e8f9!important;font-size:7px!important;font-weight:850!important}.auto-artifact-set{align-items:center;background:#081f31;border-color:#167092}.auto-artifact-set strong{color:#d8f5ff;font-size:10px}.auto-artifact-set span{padding:2px 6px;border-radius:10px;background:#123c4f;color:#67e8f9;font-size:8px;font-weight:750}.artifact-plan-reason{margin:5px 0 8px;color:#8faabd;font-size:8px;line-height:1.45}
.back-link{color:#fff!important;font-weight:850!important}
@media(max-width:1200px){.metric-grid{grid-template-columns:repeat(3,1fr)}.ai-grid{grid-template-columns:1fr 1fr}.evidence-card{grid-column:1/-1}.forensic-main{grid-template-columns:1fr}.status-panel{grid-row:1}.risk-strip{margin-right:0}}
@media(max-width:900px){.overview-context-grid,.overview-lower-grid{grid-template-columns:1fr}.custody-summary{grid-template-columns:repeat(2,1fr)}.custody-evidence{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:720px){.forensic-header{flex-direction:column}.metric-grid{grid-template-columns:repeat(2,1fr)}.ai-grid,.overview-grid{grid-template-columns:1fr}.forensic-footer{flex-direction:column;gap:7px}.case-meta{gap:7px}.risk-strip{grid-template-columns:repeat(2,1fr)}.custody-summary{grid-template-columns:1fr}.custody-event-heading{display:block}.custody-event-heading time{display:block;margin-top:6px}.custody-actor-row .custody-verified,.custody-actor-row .custody-warning{margin-left:0}}
`;
