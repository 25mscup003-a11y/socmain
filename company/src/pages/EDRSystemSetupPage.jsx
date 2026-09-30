import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io, socketOptions } from '../api/config';
import { useAuth } from '../context/AuthContext';

export default function EDRSystemSetupPage() {
  const navigate = useNavigate();
  const { company, user } = useAuth();
  const setupBase = user?.role === 'soc_manager' ? '/soc-manager/edrsystemstupe' : '/company-admin/edrsystemstupe';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const [systems, setSystems] = useState([]);
  const [dnsSetup, setDnsSetup] = useState({ configuration: null, rules: [], builtInRules: [] });
  const [cachePoisonSetup, setCachePoisonSetup] = useState({ configuration: null, builtInRules: [], systems: [] });
  const [memoryOverflowSetup, setMemoryOverflowSetup] = useState({ available: null, rules: [] });
  const [ransomwareSetup, setRansomwareSetup] = useState({ available: null, configuration: null, rules: [], targetCount: 0 });
  const [beaconingSetup, setBeaconingSetup] = useState({ available: null, configuration: null, rules: [], targetCount: 0 });
  const [timeAnomalySetup, setTimeAnomalySetup] = useState({ available: null, rules: [], exceptions: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const [systemsResult, dnsResult, cachePoisonResult, memoryRulesResult, ransomwareResult, beaconingResult, timeRulesResult, timeExceptionsResult] = await Promise.allSettled([
        api.get('/system'),
        api.get('/dns-sinkhole/configuration', { skipCache: true }),
        api.get('/dns-cache-poisoning/configuration', { skipCache: true }),
        api.get('/memory-overflow/rules', { skipCache: true }),
        api.get('/ransomware/configuration', { skipCache: true }),
        api.get('/network/beaconing/configuration', { skipCache: true }),
        api.get('/time-anomaly/policies', { skipCache: true }),
        api.get('/time-anomaly/exceptions', { skipCache: true }),
      ]);
      if (systemsResult.status === 'fulfilled') {
        const data = systemsResult.value.data;
        setSystems(Array.isArray(data) ? data : (data?.systems || []));
      } else {
        throw systemsResult.reason;
      }
      if (dnsResult.status === 'fulfilled') {
        setDnsSetup({
          configuration: dnsResult.value.data?.configuration || null,
          rules: dnsResult.value.data?.rules || [],
          builtInRules: dnsResult.value.data?.builtInRules || [],
        });
      }
      if (cachePoisonResult.status === 'fulfilled') {
        setCachePoisonSetup({
          configuration: cachePoisonResult.value.data?.configuration || null,
          builtInRules: cachePoisonResult.value.data?.builtInRules || [],
          systems: cachePoisonResult.value.data?.systems || [],
        });
      }
      setMemoryOverflowSetup(memoryRulesResult.status === 'fulfilled'
        ? { available: true, rules: memoryRulesResult.value.data?.rules || [] }
        : { available: false, rules: [] });
      setRansomwareSetup(ransomwareResult.status === 'fulfilled'
        ? {
            available: true,
            configuration: ransomwareResult.value.data?.configuration || null,
            rules: ransomwareResult.value.data?.rules || [],
            targetCount: Number(ransomwareResult.value.data?.targetCount || 0),
          }
        : { available: false, configuration: null, rules: [], targetCount: 0 });
      setBeaconingSetup(beaconingResult.status === 'fulfilled'
        ? {
            available: true,
            configuration: beaconingResult.value.data?.configuration || null,
            rules: beaconingResult.value.data?.rules || [],
            targetCount: Number(beaconingResult.value.data?.targetCount || 0),
          }
        : { available: false, configuration: null, rules: [], targetCount: 0 });
      setTimeAnomalySetup(timeRulesResult.status === 'fulfilled'
        ? {
            available: true,
            rules: timeRulesResult.value.data?.policies || [],
            exceptions: timeExceptionsResult.status === 'fulfilled' ? (timeExceptionsResult.value.data?.exceptions || []) : [],
          }
        : { available: false, rules: [], exceptions: [] });
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to load systems');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const refreshTimeSetup = async () => {
      const [rulesResult, exceptionsResult] = await Promise.allSettled([
        api.get('/time-anomaly/policies', { skipCache: true }),
        api.get('/time-anomaly/exceptions', { skipCache: true }),
      ]);
      setTimeAnomalySetup(current => ({
        available: rulesResult.status === 'fulfilled' ? true : current.available,
        rules: rulesResult.status === 'fulfilled' ? (rulesResult.value.data?.policies || []) : current.rules,
        exceptions: exceptionsResult.status === 'fulfilled' ? (exceptionsResult.value.data?.exceptions || []) : current.exceptions,
      }));
    };
    socket.on('connect', join);
    socket.on('time:policy-updated', refreshTimeSetup);
    socket.on('time:exception-updated', refreshTimeSetup);
    join();
    const disconnect = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('time:policy-updated', refreshTimeSetup);
      socket.off('time:exception-updated', refreshTimeSetup);
      disconnect();
    };
  }, [companyId]);

  const geoEnabledCount = systems.filter(system => system.geoEnrichmentEnabled !== false).length;
  const geoDisabledCount = systems.length - geoEnabledCount;
  const cachePoisonState = loading ? 'LOADING' : !cachePoisonSetup.configuration
    ? 'UNAVAILABLE' : cachePoisonSetup.configuration.enabled === false ? 'DISABLED' : 'ACTIVE';
  const cachePoisonActive = cachePoisonState === 'ACTIVE';
  const memoryEnabledRules = memoryOverflowSetup.rules.filter(rule => rule.enabled !== false).length;
  const memoryEnabledAgents = systems.filter(system => system.memoryMonitorEnabled !== false).length;
  const memoryOverflowState = loading ? 'LOADING' : memoryOverflowSetup.available === false
    ? 'UNAVAILABLE' : memoryEnabledRules ? 'ACTIVE' : 'DISABLED';
  const memoryOverflowActive = memoryOverflowState === 'ACTIVE';
  const ransomwareEnabledRules = ransomwareSetup.rules.filter(rule => rule.enabled !== false).length;
  const ransomwareState = loading ? 'LOADING' : ransomwareSetup.available === false
    ? 'UNAVAILABLE' : ransomwareSetup.configuration?.enabled === false ? 'DISABLED' : 'ACTIVE';
  const ransomwareActive = ransomwareState === 'ACTIVE';
  const beaconingEnabledRules = beaconingSetup.rules.filter(rule => rule.enabled !== false).length;
  const beaconingState = loading ? 'LOADING' : beaconingSetup.available === false
    ? 'UNAVAILABLE' : beaconingSetup.configuration?.enabled === false ? 'DISABLED' : 'ACTIVE';
  const beaconingActive = beaconingState === 'ACTIVE';
  const timeAnomalyEnabledRules = timeAnomalySetup.rules.filter(rule => rule.enabled !== false).length;
  const timeAnomalyTargetIds = new Set(timeAnomalySetup.rules.flatMap(rule => rule.systemIds || []).map(value => String(value?._id || value)));
  const timeAnomalyTargetCount = timeAnomalySetup.rules.some(rule => !(rule.systemIds || []).length) ? systems.length : timeAnomalyTargetIds.size;
  const activeTimeExceptions = timeAnomalySetup.exceptions.filter(exception => exception.enabled !== false && new Date(exception.startsAt) <= new Date() && new Date(exception.expiresAt) > new Date()).length;
  const timeAnomalyState = loading ? 'LOADING' : timeAnomalySetup.available === false
    ? 'UNAVAILABLE' : !timeAnomalySetup.rules.length ? 'NOT CONFIGURED' : timeAnomalyEnabledRules ? 'ACTIVE' : 'DISABLED';
  const timeAnomalyActive = timeAnomalyState === 'ACTIVE';

  return (
    <div>
      <div style={{ marginBottom: 18 }}>
        <h2 style={{ fontSize: 20, color: '#e0f2fe', margin: '0 0 6px' }}>🛡 EDR System Setup</h2>
        <div style={{ fontSize: 12, color: '#60a5fa' }}>Configure endpoint-level EDR controls and deploy policies to SOC agents.</div>
      </div>

      {error && (
        <div style={{ marginBottom: 12, color: '#fecaca', background: '#7f1d1d55', border: '1px solid #ef444455', padding: 10, borderRadius: 8 }}>
          {error}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 16 }}>
      <div
        role="button"
        tabIndex={0}
        onClick={() => navigate(`${setupBase}/systems`)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') navigate(`${setupBase}/systems`);
        }}
        style={{
          border: '1px solid rgba(59,130,246,.55)',
          borderRadius: 14,
          background: 'linear-gradient(135deg, rgba(13,25,48,.96), rgba(17,20,50,.94))',
          overflow: 'hidden',
          boxShadow: '0 18px 34px rgba(15,23,42,.28)',
          maxWidth: 362,
          cursor: 'pointer',
        }}
      >
        <div style={{ padding: '24px 26px 26px', minHeight: 260 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 38, lineHeight: 1 }}>🌍</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: '#60a5fa', fontSize: 18, fontWeight: 900 }}>↗</span>
              <span style={{
                border: '1px solid rgba(248,113,113,.45)',
                background: 'rgba(127,29,29,.45)',
                color: '#fecaca',
                borderRadius: 9,
                padding: '7px 12px',
                fontSize: 12,
                fontWeight: 900,
              }}>HIGH</span>
            </div>
          </div>

          <div style={{ marginTop: 28, color: '#e0f2fe', fontSize: 36, lineHeight: 1, fontWeight: 900 }}>
            {loading ? '-' : geoEnabledCount}
          </div>
          <div style={{ marginTop: 12, color: '#60a5fa', fontSize: 15, fontWeight: 900 }}>
            Geolocation setup
          </div>
          <div style={{ marginTop: 14, color: '#93c5fd', fontSize: 14 }}>
            Enabled: {geoEnabledCount} · Disabled: {geoDisabledCount} · Systems: {systems.length}
          </div>

          <svg width="124" height="42" viewBox="0 0 124 42" style={{ display: 'block', marginTop: 14 }}>
            <polyline
              points="1,31 8,14 17,14 24,31 33,31 43,21 50,25 59,31 86,31 96,1 104,31 123,31"
              fill="none"
              stroke="#3b82f6"
              strokeWidth="2.4"
              strokeLinejoin="round"
              strokeLinecap="round"
            />
          </svg>

          <div style={{ marginTop: 4, color: '#7dd3fc', fontSize: 13 }}>
            System-level geolocation monitoring
          </div>
        </div>
      </div>
      <div
        role="button"
        tabIndex={0}
        onClick={() => navigate(`${setupBase}/dns-sinkhole`)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') navigate(`${setupBase}/dns-sinkhole`);
        }}
        style={{
          border: '1px solid rgba(34,211,238,.55)',
          borderRadius: 14,
          background: 'linear-gradient(135deg, rgba(6,24,38,.98), rgba(14,30,54,.95))',
          overflow: 'hidden',
          boxShadow: '0 18px 34px rgba(8,145,178,.12)',
          maxWidth: 362,
          cursor: 'pointer',
        }}
      >
        <div style={{ padding: '24px 26px 26px', minHeight: 260 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 38, lineHeight: 1 }}>🌐</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: '#22d3ee', fontSize: 18, fontWeight: 900 }}>↗</span>
              <span style={{ border: '1px solid rgba(52,211,153,.45)', background: 'rgba(6,78,59,.42)', color: '#6ee7b7', borderRadius: 9, padding: '7px 12px', fontSize: 12, fontWeight: 900 }}>
                {dnsSetup.configuration?.enabled === false ? 'DISABLED' : 'ACTIVE'}
              </span>
            </div>
          </div>
          <div style={{ marginTop: 28, color: '#e0f2fe', fontSize: 36, lineHeight: 1, fontWeight: 900 }}>
            {loading ? '-' : dnsSetup.rules.filter(rule => rule.type === 'blocklist').length}
          </div>
          <div style={{ marginTop: 12, color: '#22d3ee', fontSize: 15, fontWeight: 900 }}>DNS Sinkhole</div>
          <div style={{ marginTop: 14, color: '#93c5fd', fontSize: 14 }}>
            Company rules: {dnsSetup.rules.length} · Built-in: {dnsSetup.builtInRules.length}
          </div>
          <svg width="124" height="42" viewBox="0 0 124 42" style={{ display: 'block', marginTop: 14 }} aria-hidden="true">
            <polyline points="1,31 12,31 20,18 31,18 39,31 53,31 64,8 74,31 88,31 98,20 108,20 123,4" fill="none" stroke="#22d3ee" strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
          </svg>
          <div style={{ marginTop: 4, color: '#67e8f9', fontSize: 13 }}>Choose rules and apply to agents</div>
        </div>
      </div>
      <div
        role="button"
        tabIndex={0}
        onClick={() => navigate(`${setupBase}/dns-cache-poisoning`)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') navigate(`${setupBase}/dns-cache-poisoning`);
        }}
        style={{
          border: '1px solid rgba(248,113,113,.52)',
          borderRadius: 14,
          background: 'linear-gradient(135deg, rgba(28,15,30,.98), rgba(14,30,54,.95))',
          overflow: 'hidden',
          boxShadow: '0 18px 34px rgba(127,29,29,.12)',
          maxWidth: 362,
          cursor: 'pointer',
        }}
      >
        <div style={{ padding: '24px 26px 26px', minHeight: 260 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 38, lineHeight: 1 }}>☠️</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: '#f87171', fontSize: 18, fontWeight: 900 }}>↗</span>
              <span style={{ border: `1px solid ${cachePoisonActive ? 'rgba(52,211,153,.45)' : 'rgba(248,113,113,.45)'}`, background: cachePoisonActive ? 'rgba(6,78,59,.42)' : 'rgba(127,29,29,.45)', color: cachePoisonActive ? '#6ee7b7' : '#fecaca', borderRadius: 9, padding: '7px 12px', fontSize: 12, fontWeight: 900 }}>
                {cachePoisonState}
              </span>
            </div>
          </div>
          <div style={{ marginTop: 28, color: '#e0f2fe', fontSize: 36, lineHeight: 1, fontWeight: 900 }}>
            {loading ? '-' : (cachePoisonSetup.configuration?.builtInRuleIds || []).length}
          </div>
          <div style={{ marginTop: 12, color: '#f87171', fontSize: 15, fontWeight: 900 }}>DNS Cache Poisoning</div>
          <div style={{ marginTop: 14, color: '#93c5fd', fontSize: 14 }}>
            Built-in rules: {cachePoisonSetup.builtInRules.length} · Agents: {cachePoisonSetup.systems.length}
          </div>
          <svg width="124" height="42" viewBox="0 0 124 42" style={{ display: 'block', marginTop: 14 }} aria-hidden="true">
            <polyline points="1,31 12,31 20,12 31,28 42,28 54,5 66,31 79,31 91,16 103,27 123,8" fill="none" stroke="#f87171" strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
          </svg>
          <div style={{ marginTop: 4, color: '#fca5a5', fontSize: 13 }}>Edit rules and apply to agents</div>
        </div>
      </div>
      <div
        role="button"
        tabIndex={0}
        onClick={() => navigate(`${setupBase}/time-based-anomaly-detection`)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') navigate(`${setupBase}/time-based-anomaly-detection`);
        }}
        style={{
          border: '1px solid rgba(52,211,153,.55)',
          borderRadius: 14,
          background: 'linear-gradient(135deg, rgba(7,31,32,.98), rgba(14,30,54,.95))',
          overflow: 'hidden',
          boxShadow: '0 18px 34px rgba(16,185,129,.12)',
          maxWidth: 362,
          cursor: 'pointer',
        }}
      >
        <div style={{ padding: '24px 26px 26px', minHeight: 260 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 38, lineHeight: 1 }}>⏱️</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: '#34d399', fontSize: 18, fontWeight: 900 }}>↗</span>
              <span style={{ border: `1px solid ${timeAnomalyActive ? 'rgba(52,211,153,.45)' : 'rgba(248,113,113,.45)'}`, background: timeAnomalyActive ? 'rgba(6,78,59,.42)' : 'rgba(127,29,29,.45)', color: timeAnomalyActive ? '#6ee7b7' : '#fecaca', borderRadius: 9, padding: '7px 12px', fontSize: 12, fontWeight: 900 }}>
                {timeAnomalyState}
              </span>
            </div>
          </div>
          <div style={{ marginTop: 28, color: '#e0f2fe', fontSize: 36, lineHeight: 1, fontWeight: 900 }}>
            {loading ? '-' : timeAnomalyEnabledRules}
          </div>
          <div style={{ marginTop: 12, color: '#34d399', fontSize: 15, fontWeight: 900 }}>⚙️ Configure</div>
          <div style={{ marginTop: 8, color: '#e0f2fe', fontSize: 14, fontWeight: 800 }}>Time-Based Anomaly Detection</div>
          <div style={{ marginTop: 14, color: '#93c5fd', fontSize: 14 }}>
            Active rules: {timeAnomalyEnabledRules} · Agents: {timeAnomalyTargetCount} · Exceptions: {activeTimeExceptions}
          </div>
          <svg width="124" height="42" viewBox="0 0 124 42" style={{ display: 'block', marginTop: 14 }} aria-hidden="true">
            <polyline points="1,31 12,31 20,19 31,29 42,9 54,30 66,16 78,30 89,5 101,25 112,17 123,7" fill="none" stroke="#34d399" strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
          </svg>
          <div style={{ marginTop: 4, color: '#6ee7b7', fontSize: 13 }}>Configure schedules, agent rules and approved exceptions</div>
        </div>
      </div>
      <div
        role="button"
        tabIndex={0}
        onClick={() => navigate(`${setupBase}/beaconing-detection`)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') navigate(`${setupBase}/beaconing-detection`);
        }}
        style={{
          border: '1px solid rgba(34,211,238,.55)',
          borderRadius: 14,
          background: 'linear-gradient(135deg, rgba(6,24,38,.98), rgba(20,18,46,.95))',
          overflow: 'hidden',
          boxShadow: '0 18px 34px rgba(8,145,178,.12)',
          maxWidth: 362,
          cursor: 'pointer',
        }}
      >
        <div style={{ padding: '24px 26px 26px', minHeight: 260 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 38, lineHeight: 1 }}>📡</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: '#22d3ee', fontSize: 18, fontWeight: 900 }}>↗</span>
              <span style={{ border: `1px solid ${beaconingActive ? 'rgba(52,211,153,.45)' : 'rgba(248,113,113,.45)'}`, background: beaconingActive ? 'rgba(6,78,59,.42)' : 'rgba(127,29,29,.45)', color: beaconingActive ? '#6ee7b7' : '#fecaca', borderRadius: 9, padding: '7px 12px', fontSize: 12, fontWeight: 900 }}>
                {beaconingState}
              </span>
            </div>
          </div>
          <div style={{ marginTop: 28, color: '#e0f2fe', fontSize: 36, lineHeight: 1, fontWeight: 900 }}>
            {loading ? '-' : beaconingEnabledRules}
          </div>
          <div style={{ marginTop: 12, color: '#22d3ee', fontSize: 15, fontWeight: 900 }}>Configure</div>
          <div style={{ marginTop: 8, color: '#e0f2fe', fontSize: 14, fontWeight: 800 }}>Beaconing Detection</div>
          <div style={{ marginTop: 14, color: '#93c5fd', fontSize: 14 }}>
            Active rules: {beaconingEnabledRules} · Agents: {beaconingSetup.targetCount}
          </div>
          <svg width="124" height="42" viewBox="0 0 124 42" style={{ display: 'block', marginTop: 14 }} aria-hidden="true">
            <polyline points="1,31 11,31 20,18 29,30 40,10 51,29 62,16 73,31 84,7 96,27 107,19 123,4" fill="none" stroke="#22d3ee" strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
          </svg>
          <div style={{ marginTop: 4, color: '#67e8f9', fontSize: 13 }}>Edit rules and C2 containment policy</div>
        </div>
      </div>
      <div
        role="button"
        tabIndex={0}
        onClick={() => navigate(`${setupBase}/memory-overflow-detection`)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') navigate(`${setupBase}/memory-overflow-detection`);
        }}
        style={{
          border: '1px solid rgba(167,139,250,.55)',
          borderRadius: 14,
          background: 'linear-gradient(135deg, rgba(24,16,45,.98), rgba(14,30,54,.95))',
          overflow: 'hidden',
          boxShadow: '0 18px 34px rgba(109,40,217,.12)',
          maxWidth: 362,
          cursor: 'pointer',
        }}
      >
        <div style={{ padding: '24px 26px 26px', minHeight: 260 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 38, lineHeight: 1 }}>💾</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: '#a78bfa', fontSize: 18, fontWeight: 900 }}>↗</span>
              <span style={{ border: `1px solid ${memoryOverflowActive ? 'rgba(52,211,153,.45)' : 'rgba(248,113,113,.45)'}`, background: memoryOverflowActive ? 'rgba(6,78,59,.42)' : 'rgba(127,29,29,.45)', color: memoryOverflowActive ? '#6ee7b7' : '#fecaca', borderRadius: 9, padding: '7px 12px', fontSize: 12, fontWeight: 900 }}>
                {memoryOverflowState}
              </span>
            </div>
          </div>
          <div style={{ marginTop: 28, color: '#e0f2fe', fontSize: 36, lineHeight: 1, fontWeight: 900 }}>
            {loading ? '-' : memoryEnabledRules}
          </div>
          <div style={{ marginTop: 12, color: '#a78bfa', fontSize: 15, fontWeight: 900 }}>Memory Overflow Detection</div>
          <div style={{ marginTop: 14, color: '#93c5fd', fontSize: 14 }}>
            Active rules: {memoryEnabledRules} · Agents: {memoryEnabledAgents}
          </div>
          <svg width="124" height="42" viewBox="0 0 124 42" style={{ display: 'block', marginTop: 14 }} aria-hidden="true">
            <polyline points="1,31 12,31 20,24 29,24 39,8 48,33 59,18 68,18 80,4 91,30 103,21 123,21" fill="none" stroke="#a78bfa" strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
          </svg>
          <div style={{ marginTop: 4, color: '#c4b5fd', fontSize: 13 }}>Open live dashboard and configure rules</div>
        </div>
      </div>
      <div
        role="button"
        tabIndex={0}
        onClick={() => navigate(`${setupBase}/encryption-ransomware-detection`)}
        onKeyDown={(event) => {
          if (event.key === 'Enter' || event.key === ' ') navigate(`${setupBase}/encryption-ransomware-detection`);
        }}
        style={{
          border: '1px solid rgba(34,211,238,.55)',
          borderRadius: 14,
          background: 'linear-gradient(135deg, rgba(9,27,38,.98), rgba(20,18,46,.95))',
          overflow: 'hidden',
          boxShadow: '0 18px 34px rgba(8,145,178,.12)',
          maxWidth: 362,
          cursor: 'pointer',
        }}
      >
        <div style={{ padding: '24px 26px 26px', minHeight: 260 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ fontSize: 38, lineHeight: 1 }}>⚙️</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ color: '#22d3ee', fontSize: 18, fontWeight: 900 }}>↗</span>
              <span style={{ border: `1px solid ${ransomwareActive ? 'rgba(52,211,153,.45)' : 'rgba(248,113,113,.45)'}`, background: ransomwareActive ? 'rgba(6,78,59,.42)' : 'rgba(127,29,29,.45)', color: ransomwareActive ? '#6ee7b7' : '#fecaca', borderRadius: 9, padding: '7px 12px', fontSize: 12, fontWeight: 900 }}>
                {ransomwareState}
              </span>
            </div>
          </div>
          <div style={{ marginTop: 28, color: '#e0f2fe', fontSize: 36, lineHeight: 1, fontWeight: 900 }}>
            {loading ? '-' : ransomwareEnabledRules}
          </div>
          <div style={{ marginTop: 12, color: '#22d3ee', fontSize: 15, fontWeight: 900 }}>Configure</div>
          <div style={{ marginTop: 8, color: '#e0f2fe', fontSize: 14, fontWeight: 800 }}>Encryption &amp; Ransomware Detection</div>
          <div style={{ marginTop: 14, color: '#93c5fd', fontSize: 14 }}>
            Active rules: {ransomwareEnabledRules} · Agents: {ransomwareSetup.targetCount}
          </div>
          <svg width="124" height="42" viewBox="0 0 124 42" style={{ display: 'block', marginTop: 14 }} aria-hidden="true">
            <polyline points="1,31 12,31 21,18 31,28 43,7 55,31 68,23 79,23 91,10 103,29 123,14" fill="none" stroke="#22d3ee" strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
          </svg>
          <div style={{ marginTop: 4, color: '#67e8f9', fontSize: 13 }}>Edit rules and deploy agent policy</div>
        </div>
      </div>
      </div>
    </div>
  );
}
