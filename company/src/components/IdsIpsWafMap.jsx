import GoogleAttackMap from './GoogleAttackMap';

export default function IdsIpsWafMap({
  attacks,
  agents,
  total,
  height = 320,
  refreshInterval = 30000,
  selectedIp = null,
  showMonitorCount = true,
  label = 'AJNAT IDS / IPS / WAF LIVE MONITOR MAP (AGENT LINKED)',
}) {
  return (
    <GoogleAttackMap
      dataMode="ids"
      height={height}
      refreshInterval={refreshInterval}
      selectedIp={selectedIp}
      customAttacks={attacks}
      customAgents={agents}
      customTotal={total}
      showMonitorCount={showMonitorCount}
      customLabel={label}
      customEventLabel="ATTACK EVENT"
    />
  );
}
