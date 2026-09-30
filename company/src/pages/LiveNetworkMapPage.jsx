import React, { useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import NetworkConnectionMap from '../components/NetworkConnectionMap';
import IdsIpsWafMap from '../components/IdsIpsWafMap';
import useLiveNetworkMap from '../hooks/useLiveNetworkMap';

export default function LiveNetworkMapPage() {
  const { user, company } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const searchParams = useMemo(() => new URLSearchParams(window.location.search), []);
  const selectedIp = searchParams.get('ip') || null;
  const attackMonitorView = searchParams.get('source') === 'ids' && searchParams.get('view') === 'ips-blocked';
  const liveNetwork = useLiveNetworkMap(companyId, !attackMonitorView);

  return (
    <div style={{ width: '100vw', height: '100vh', margin: 0, padding: 0, overflow: 'hidden', background: '#020617' }}>
      {attackMonitorView ? (
        <IdsIpsWafMap
          height="100%"
          refreshInterval={30000}
          selectedIp={selectedIp}
          label="AJNAT IDS / IPS / WAF LIVE MONITOR MAP (AGENT LINKED)"
        />
      ) : (
        <NetworkConnectionMap
          height="100%"
          connections={liveNetwork.connections}
          agents={liveNetwork.agents}
          total={liveNetwork.total}
          directionCounts={liveNetwork.directionCounts}
          selectedIp={selectedIp}
        />
      )}
    </div>
  );
}
