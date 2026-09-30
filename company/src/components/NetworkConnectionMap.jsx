import GoogleAttackMap from './GoogleAttackMap';

export default function NetworkConnectionMap({
  connections = [],
  agents = [],
  total = 0,
  directionCounts = {},
  height = 320,
  selectedIp = null,
  showMonitorCount = true,
}) {
  const inbound = Number(directionCounts.inbound || 0);
  const outbound = Number(directionCounts.outbound || 0);
  const locatedAgents = agents.filter(agent => Number.isFinite(Number(agent.dstLat)) && Number.isFinite(Number(agent.dstLon))).length;

  return (
    <GoogleAttackMap
      dataMode="network"
      height={height}
      selectedIp={selectedIp}
      customAttacks={connections}
      customAgents={agents}
      customTotal={total}
      showMonitorCount={showMonitorCount}
      customLabel={`LIVE NETWORK · ${inbound} INBOUND · ${outbound} OUTBOUND · ${locatedAgents} AJNAT LOCATIONS`}
      customEventLabel="NETWORK CONNECTION"
    />
  );
}
