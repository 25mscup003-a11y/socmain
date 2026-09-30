/**
 * GoogleAttackMap.jsx
 * Real-time IDS/IPS Attack Map using Real Google Maps & Google Earth Tiles.
 * Supports Google Maps Roadmap, Google Earth Satellite View, Dark Theme,
 * animated threat trajectory arcs, pulse markers, and interactive threat popups.
 */
import { useEffect, useRef, useState, useCallback } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../api/config';

const SEV_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#22c55e',
};

const EVENT_META = {
  ids_alert: { label: 'IDS MONITORED', icon: '📡', color: '#38bdf8' },
  ips_block: { label: 'IPS BLOCKED', icon: '🛡️', color: '#22c55e' },
  waf_attack: { label: 'WAF PROTECTED', icon: '🔥', color: '#f97316' },
};

const escapeHtml = value => String(value ?? '')
  .replaceAll('&', '&amp;')
  .replaceAll('<', '&lt;')
  .replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;')
  .replaceAll("'", '&#039;');

const loadLeaflet = () => Promise.resolve(L);

const hasMapCoordinate = value => value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value));

export default function GoogleAttackMap({ dataMode = 'ids', height = 320, refreshInterval = 30000, selectedIp = null, customAttacks = null, customAgents = null, customTotal = null, showMonitorCount = true, customLabel = 'NETWORK MONITORING', customEventLabel = 'NETWORK CONNECTION' }) {
  const { user, company } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const mapDivRef      = useRef(null);
  const mapInstanceRef = useRef(null);
  const layerGroupRef  = useRef(null);
  const tileLayerRef   = useRef(null);
  const markerMapRef   = useRef({});
  const lastFitSignatureRef = useRef('');

  const [attacks, setAttacks]     = useState([]);
  const [liveCount, setLiveCount] = useState(0);
  const [mapMode, setMapMode]     = useState('google_dark'); // google_dark | google_earth | google_streets
  const [status, setStatus]       = useState('loading'); // loading | ready | error
  const [monitoringSummary, setMonitoringSummary] = useState(null);
  const [originSummary, setOriginSummary] = useState(null);
  const [agents, setAgents] = useState([]);

  // Fetch live attack data from backend
  const fetchAttacks = useCallback(async () => {
    if (customAttacks !== null || dataMode !== 'ids') return;
    try {
      const { data } = await api.get('/ids/geo-attacks', {
        params: { hours: 24, ...(selectedIp ? { ip: selectedIp } : {}) },
        skipCache: true,
      });
      if (data?.attacks) {
        setAttacks(data.attacks);
        setLiveCount(data.total || data.attacks.length || 0);
        setMonitoringSummary(data.monitoringSummary || null);
        setOriginSummary(data.originSummary || null);
        setAgents(Array.isArray(data.agents) ? data.agents : []);
      }
    } catch {
      // Keep existing data on fetch error
    }
  }, [customAttacks, dataMode, selectedIp]);

  useEffect(() => {
    if (customAttacks !== null) {
      setAttacks(customAttacks);
      setLiveCount(customAttacks.length);
    }
  }, [customAttacks]);

  // Compute curved arc path points between two LatLngs for geodesic curved lines
  const getCurvePath = (start, end, curvature = 0.25) => {
    const points = [];
    const lat1 = start[0], lon1 = start[1];
    const lat2 = end[0],   lon2 = end[1];

    const midLat = (lat1 + lat2) / 2 + (lon2 - lon1) * curvature;
    const midLon = (lon1 + lon2) / 2 - (lat2 - lat1) * curvature;

    for (let t = 0; t <= 1; t += 0.04) {
      const lat = (1 - t) * (1 - t) * lat1 + 2 * (1 - t) * t * midLat + t * t * lat2;
      const lon = (1 - t) * (1 - t) * lon1 + 2 * (1 - t) * t * midLon + t * t * lon2;
      points.push([lat, lon]);
    }
    return points;
  };

  // Draw attack markers and curved trajectory lines on Leaflet map
  const renderAttacksOnMap = useCallback((L, map, attackList) => {
    if (!layerGroupRef.current) return;
    layerGroupRef.current.clearLayers();
    markerMapRef.current = {};

    const dataToRender = [...attackList];

    const hasCoordinate = hasMapCoordinate;
    const attackDestinations = dataToRender
      .filter(item => hasCoordinate(item.dstLat) && hasCoordinate(item.dstLon))
      .map(item => ({
        systemId: item.dstSystemId || '', name: item.dstName || 'Protected endpoint',
        dstLat: item.dstLat, dstLon: item.dstLon, dstIp: item.dstIp,
        dstLocationSource: item.dstLocationSource,
      }));
    const displayedAgents = Array.isArray(customAgents) ? customAgents : agents;
    const agentDestinations = displayedAgents
      .filter(agent => hasCoordinate(agent.dstLat) && hasCoordinate(agent.dstLon));
    const destinationRows = agentDestinations.length ? agentDestinations : attackDestinations;
    const sourceCounts = dataToRender.reduce((counts, attack) => {
      if (attack.srcIp) counts.set(attack.srcIp, (counts.get(attack.srcIp) || 0) + 1);
      return counts;
    }, new Map());
    const coordinateSources = new Map();
    dataToRender.forEach(attack => {
      if (!attack.srcIp || !hasCoordinate(attack.srcLat) || !hasCoordinate(attack.srcLon)) return;
      const key = `${Number(attack.srcLat).toFixed(4)},${Number(attack.srcLon).toFixed(4)}`;
      const sources = coordinateSources.get(key) || [];
      if (!sources.includes(attack.srcIp)) sources.push(attack.srcIp);
      coordinateSources.set(key, sources);
    });
    const displaySourcePoint = attack => {
      const lat = Number(attack.srcLat);
      const lon = Number(attack.srcLon);
      const key = `${lat.toFixed(4)},${lon.toFixed(4)}`;
      const sources = coordinateSources.get(key) || [];
      if (sources.length < 2) return [lat, lon];
      const index = Math.max(0, sources.indexOf(attack.srcIp));
      const angle = (Math.PI * 2 * index) / sources.length;
      const radius = 0.08;
      return [lat + Math.cos(angle) * radius, lon + Math.sin(angle) * radius];
    };
    const plottedPoints = destinationRows.map(destination => [Number(destination.dstLat), Number(destination.dstLon)]);

    if (dataToRender.length === 0 && destinationRows.length === 0) return;

    const companyIdsIpsTotal = Math.max(0, Number(monitoringSummary?.idsIpsEvents ?? liveCount ?? 0));
    const assignedIdsIpsTotal = destinationRows.reduce((sum, destination) => sum + Math.max(0, Number(destination.inputEvents || 0)), 0);
    const unassignedIdsIpsTotal = Math.max(0, companyIdsIpsTotal - assignedIdsIpsTotal);
    const seenDestinations = new Set();
    destinationRows.forEach((destination, destinationIndex) => {
      const dstLat = Number(destination.dstLat);
      const dstLon = Number(destination.dstLon);
      const destinationKey = destination.systemId || `${dstLat}:${dstLon}`;
      if (seenDestinations.has(destinationKey)) return;
      seenDestinations.add(destinationKey);
      const agentName = destination.name || destination.dstName || 'Unnamed endpoint';
      const agentLabel = destination.label || `AJNAT Agent — ${agentName}`;
      const isApproximateLocation = destination.dstLocationPrecision === 'approximate';
      const sensorLabel = Array.isArray(destination.sensors) && destination.sensors.length
        ? destination.sensors.join(' + ') : 'IDS monitoring';
      // If only one endpoint has a usable location, it is the sole plotted
      // destination for company-level/legacy sensor events too. Show the full
      // IDS/IPS total on that agent instead of making unlocated events appear
      // to be missing or inventing remote coordinates for them.
      const linkedEventCount = dataMode === 'ids'
        ? Math.max(0, Number(destination.inputEvents || 0)) + (destinationIndex === 0 ? unassignedIdsIpsTotal : 0)
        : Number(destination.inputEvents || 0);
      const dstMarkerIcon = L.divIcon({
        className: 'dst-radar-marker',
        html: `
          <div class="hacker-crosshair-container ajnat-agent-highlight">
            <div class="ajnat-agent-halo"></div>
            <div class="hacker-crosshair-ring ring-1"></div>
            <div class="hacker-crosshair-ring ring-2"></div>
            <div class="hacker-crosshair-lines"></div>
            <div class="hacker-crosshair-center"></div>
            ${dataMode === 'ids' && linkedEventCount > 0 ? `<div class="ajnat-agent-event-count">📡 ${linkedEventCount.toLocaleString('en-IN')} IDS/IPS</div>` : ''}
          </div>
        `,
        iconSize: [56, 56],
        iconAnchor: [28, 28],
      });
      const dstMarker = L.marker([dstLat, dstLon], { icon: dstMarkerIcon }).bindPopup(`
      <div style="font-family:monospace;font-size:12px;line-height:1.5">
        <b style="color:#00f0ff">🛡️ ${escapeHtml(agentLabel)}</b><br/>
        <strong style="color:#22c55e">AJNAT AGENT LOCATION — LIVE SECURITY ENDPOINT</strong><br/>
        ${isApproximateLocation ? '<strong style="color:#f59e0b">APPROXIMATE LIVE LOCATION</strong><br/>' : '<strong style="color:#22c55e">PRECISE LIVE LOCATION</strong><br/>'}
        <span style="color:#cbd5e1">Host: ${escapeHtml(destination.hostname || agentName)}</span><br/>
        <span style="color:#cbd5e1">IP: ${escapeHtml(destination.ip || destination.dstIp || '—')}</span><br/>
        <span style="color:#cbd5e1">Sensors: ${escapeHtml(sensorLabel)}</span><br/>
        <span style="color:#cbd5e1">${dataMode === 'ids' ? '24h linked IDS/IPS events' : 'Live inbound/outbound'}: ${linkedEventCount.toLocaleString('en-IN')}${dataMode === 'ids' ? '' : ` / ${Number(destination.outputEvents || 0).toLocaleString('en-IN')}`}</span><br/>
        <span style="color:#cbd5e1">${Number(dstLat).toFixed(5)}, ${Number(dstLon).toFixed(5)}</span><br/>
        <span style="color:#94a3b8">Source: ${escapeHtml(destination.dstLocationSource || 'AJNAT native location telemetry')}</span><br/>
        <span style="color:${['active', 'online'].includes(String(destination.status || '').toLowerCase()) ? '#22c55e' : '#f59e0b'}">Status: ${escapeHtml(destination.status || 'protected')}</span>
      </div>
    `).bindTooltip(`🛡️ AJNAT ${isApproximateLocation ? 'APPROX. ' : ''}LIVE LOCATION · ${escapeHtml(agentName)}${dataMode === 'ids' && linkedEventCount > 0 ? ` · 📡 ${linkedEventCount.toLocaleString('en-IN')}` : ''}`, {
      permanent: true,
      direction: 'top',
      offset: [0, -22],
      className: 'hacker-tooltip-permanent ajnat-agent-tooltip'
    });
      layerGroupRef.current.addLayer(dstMarker);
    });

    // Plot each threat attack
    dataToRender.forEach(atk => {
      if (!hasCoordinate(atk.srcLat) || !hasCoordinate(atk.srcLon)) return;
      const eventMeta = EVENT_META[atk.eventType] || { label: 'SECURITY EVENT', icon: '⚠️', color: SEV_COLOR[atk.severity] || '#60a5fa' };
      const col = eventMeta.color;
      // IP geolocation is city-level. Spread distinct sources that resolve to
      // the exact same city coordinate so one marker cannot hide another.
      const start = displaySourcePoint(atk);
      const hasDestination = hasCoordinate(atk.dstLat) && hasCoordinate(atk.dstLon);
      const end = hasDestination ? [Number(atk.dstLat), Number(atk.dstLon)] : null;

      // Curved Arc Line with custom flowing dashes
      if (end) {
      const curvePoints = getCurvePath(start, end, 0.2);
      const polyline = L.polyline(curvePoints, {
        color: col,
        weight: atk.severity === 'critical' ? 2.5 : 1.5,
        opacity: atk.blocked ? 0.35 : 0.85,
        dashArray: atk.blocked ? '3, 6' : '6, 12',
        className: atk.blocked ? 'hacker-blocked-line' : atk.direction === 'outbound' ? 'hacker-flowing-line hacker-flowing-line-reverse' : 'hacker-flowing-line',
      });
      layerGroupRef.current.addLayer(polyline);
      }

      plottedPoints.push([Number(atk.srcLat), Number(atk.srcLon)]);
      if (markerMapRef.current[atk.srcIp]) return;

      // Threat Source Circle Marker (pulsing red/orange threat)
      const srcMarkerIcon = L.divIcon({
        className: 'src-threat-marker',
        html: `
          <div class="hacker-threat-node" style="--threat-color: ${col}">
            <div class="node-ring"></div>
            <div class="node-core"></div>
          </div>
        `,
        iconSize: [20, 20],
        iconAnchor: [10, 10],
      });

      const sourcePlace = [atk.srcCity, atk.srcCountry].filter(Boolean).join(', ') || 'Public IP location';
      const sourceEventCount = sourceCounts.get(atk.srcIp) || 1;
      const srcMarker = L.marker(start, { icon: srcMarkerIcon }).bindPopup(`
        <div style="font-family:monospace;font-size:12px;line-height:1.6;min-width:210px">
          <div style="font-weight:bold;color:${col};text-transform:uppercase;margin-bottom:6px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:3px">
            ${EVENT_META[atk.eventType] ? `${eventMeta.icon} ${eventMeta.label}` : `🌐 ${escapeHtml(String(atk.direction || 'live').toUpperCase())} ${customEventLabel}`} ${atk.blocked ? '<span style="color:#22c55e">[BLOCKED]</span>' : ''}
          </div>
          <div><b>${atk.eventType === 'network_connection' ? 'Remote IP' : 'Source IP'}:</b> ${escapeHtml(atk.srcIp)}</div>
          <div><b>${atk.eventType === 'network_connection' ? 'Remote location' : 'Attack origin'}:</b> ${escapeHtml(sourcePlace)}</div>
          <div><b>${atk.eventType === 'network_connection' ? 'Active flows' : 'Events'}:</b> ${sourceEventCount.toLocaleString('en-IN')}</div>
          <div><b>ISP:</b> ${escapeHtml(atk.srcISP || '—')}</div>
          ${atk.direction ? `<div><b>Direction:</b> ${escapeHtml(String(atk.direction).toUpperCase())}</div>` : ''}
          ${atk.state ? `<div><b>State:</b> ${escapeHtml(atk.state)}${atk.agentOnline === false ? ' · agent heartbeat stale' : ''}</div>` : ''}
          ${atk.protocol ? `<div><b>Protocol:</b> ${escapeHtml(String(atk.protocol).toUpperCase())}${atk.destinationPort ? ` · port ${escapeHtml(atk.destinationPort)}` : ''}</div>` : ''}
          ${atk.processName ? `<div><b>Process:</b> ${escapeHtml(atk.processName)}</div>` : ''}
          ${Number.isFinite(Number(atk.durationSeconds)) ? `<div><b>Connected:</b> ${Math.max(0, Math.floor(Number(atk.durationSeconds)))}s</div>` : ''}
          <div><b>Severity:</b> ${escapeHtml(String(atk.severity || 'low').toUpperCase())}</div>
          <div><b>${customAttacks ? 'Activity' : 'Attack'}:</b> ${escapeHtml(atk.description || 'IDS Alert')}</div>
          <div style="color:#64748b;font-size:10px;margin-top:6px;border-top:1px solid rgba(255,255,255,0.05);padding-top:4px">
            ${atk.timestamp ? new Date(atk.timestamp).toLocaleString() : ''}
          </div>
        </div>
      `).bindTooltip(atk.eventType === 'network_connection'
        ? `${escapeHtml(String(atk.direction || 'live').toUpperCase())} · ${escapeHtml(atk.srcIp)}`
        : `${eventMeta.icon} ${eventMeta.label} · ${sourceEventCount.toLocaleString('en-IN')} EVENT${sourceEventCount === 1 ? '' : 'S'} · ${escapeHtml(sourcePlace)} · ${escapeHtml(atk.srcIp)}`, {
        permanent: true,
        direction: 'top',
        offset: [0, -8],
        className: 'hacker-tooltip-permanent',
      });
      layerGroupRef.current.addLayer(srcMarker);
      markerMapRef.current[atk.srcIp] = srcMarker;
    });

    if (!selectedIp && plottedPoints.length) {
      const fitSignature = plottedPoints
        .map(point => `${point[0].toFixed(3)},${point[1].toFixed(3)}`)
        .sort()
        .join('|');
      if (fitSignature !== lastFitSignatureRef.current) {
        lastFitSignatureRef.current = fitSignature;
        if (plottedPoints.length === 1) map.setView(plottedPoints[0], 5, { animate: true });
        else map.fitBounds(L.latLngBounds(plottedPoints), { padding: [60, 60], maxZoom: 5, animate: true });
      }
    }
  }, [selectedIp, customAttacks, customAgents, customEventLabel, agents, dataMode, monitoringSummary, liveCount]);

  // Change Google Maps Tile Layer dynamically
  const switchTileLayer = useCallback((L, map, mode) => {
    if (tileLayerRef.current) {
      map.removeLayer(tileLayerRef.current);
    }

    let url = 'https://{s}.google.com/vt/lyrs=m&x={x}&y={y}&z={z}'; // Google Maps Roadmap
    let subdomains = ['mt0', 'mt1', 'mt2', 'mt3'];
    let maxZoom = 20;

    if (mode === 'google_earth') {
      // Google Earth Satellite + Hybrid Labels
      url = 'https://{s}.google.com/vt/lyrs=y&x={x}&y={y}&z={z}';
    } else if (mode === 'google_dark') {
      // Dark Mode CartoDB Map Tiles
      url = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
      subdomains = ['a', 'b', 'c', 'd'];
    }

    const newLayer = L.tileLayer(url, {
      maxZoom,
      subdomains,
      attribution: mode.startsWith('google') ? '&copy; Google Maps' : '&copy; OpenStreetMap/CartoDB',
    });

    newLayer.addTo(map);
    tileLayerRef.current = newLayer;
  }, []);

  useEffect(() => {
    if (customAttacks === null && dataMode === 'ids') {
      fetchAttacks();
    }

    let isMounted = true;
    let resizeObserver = null;

    loadLeaflet()
      .then(L => {
        if (!isMounted || !mapDivRef.current) return;
        if (mapInstanceRef.current) return;

        const map = L.map(mapDivRef.current, {
          center: [25, 30],
          zoom: 2,
          minZoom: 2,
          maxZoom: 18,
          zoomControl: false,
          attributionControl: false,
        });

        // Add Zoom Control at bottom right
        L.control.zoom({ position: 'bottomright' }).addTo(map);

        // Add Layer Group for markers & polylines
        const layerGroup = L.layerGroup().addTo(map);
        layerGroupRef.current = layerGroup;
        mapInstanceRef.current = map;

        switchTileLayer(L, map, mapMode);
        setStatus('ready');

        // Setup ResizeObserver to handle dynamic width/height changes
        if (typeof ResizeObserver !== 'undefined' && mapDivRef.current) {
          resizeObserver = new ResizeObserver(() => {
            if (isMounted && map) {
              map.invalidateSize();
            }
          });
          resizeObserver.observe(mapDivRef.current);
        }

        setTimeout(() => { map.invalidateSize(); }, 50);
        setTimeout(() => { map.invalidateSize(); }, 250);
        setTimeout(() => { map.invalidateSize(); }, 600);
        setTimeout(() => { map.invalidateSize(); }, 1200);
      })
      .catch(() => setStatus('error'));

    return () => {
      isMounted = false;
      if (resizeObserver) {
        resizeObserver.disconnect();
      }
    };
  }, [fetchAttacks, switchTileLayer, mapMode, customAttacks, dataMode]);

  // Re-render markers when attack list changes
  useEffect(() => {
    if (status !== 'ready' || !mapInstanceRef.current) return;
    renderAttacksOnMap(L, mapInstanceRef.current, attacks);
  }, [attacks, status, renderAttacksOnMap]);

  // Handle selectedIp propagation and auto pan & zoom
  useEffect(() => {
    if (!selectedIp || !mapInstanceRef.current) return;
    const map = mapInstanceRef.current;
    
    let lat = null;
    let lon = null;

    // 1. Search in live database attacks
    const match = attacks.find(a => a.srcIp === selectedIp);
    if (match && Number.isFinite(Number(match.srcLat)) && Number.isFinite(Number(match.srcLon))) {
      lat = match.srcLat;
      lon = match.srcLon;
    }
    
    if (lat && lon) {
      map.setView([lat, lon], 6, { animate: true });
      
      // Auto open popup with delay to let map finish panning
      setTimeout(() => {
        const marker = markerMapRef.current[selectedIp];
        if (marker) {
          marker.openPopup();
        }
      }, 250);
    }
  }, [selectedIp, attacks]);

  // Change tile layer when mode changes
  const handleModeChange = (mode) => {
    setMapMode(mode);
    if (mapInstanceRef.current) {
      switchTileLayer(L, mapInstanceRef.current, mode);
    }
  };

  // Periodic refresh
  useEffect(() => {
    if (customAttacks !== null || dataMode !== 'ids') return;
    const tid = setInterval(fetchAttacks, refreshInterval);
    return () => clearInterval(tid);
  }, [fetchAttacks, refreshInterval, customAttacks, dataMode]);

  // IDS/IPS/WAF views refresh immediately when a tenant event arrives. The
  // interval above remains as reconnect/failure recovery.
  useEffect(() => {
    if (customAttacks !== null || dataMode !== 'ids') return undefined;
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    let timer = null;
    const refresh = () => {
      clearTimeout(timer);
      timer = setTimeout(fetchAttacks, 500);
    };
    socket.on('connect', join);
    socket.on('alert:new', refresh);
    socket.on('alert:updated', refresh);
    socket.on('ips:block', refresh);
    socket.on('waf:block', refresh);
    join();
    const disconnect = connectSocket(socket);
    return () => {
      clearTimeout(timer);
      socket.off('connect', join);
      socket.off('alert:new', refresh);
      socket.off('alert:updated', refresh);
      socket.off('ips:block', refresh);
      socket.off('waf:block', refresh);
      disconnect();
    };
  }, [companyId, customAttacks, fetchAttacks, dataMode]);

  const renderedCount = attacks.length;
  const realCount = customAttacks !== null && Number.isFinite(Number(customTotal)) ? Number(customTotal) : liveCount;
  const plottedDataCount = attacks.filter(item => hasMapCoordinate(item.srcLat) && hasMapCoordinate(item.srcLon)).length
    + (Array.isArray(customAgents) ? customAgents : agents)
      .filter(item => hasMapCoordinate(item.dstLat) && hasMapCoordinate(item.dstLon)).length;
  const monitorCountLabel = realCount.toLocaleString('en-IN');
  const flowSummary = monitoringSummary || {};
  const plottedOriginCount = Number(originSummary?.plottedRemoteEvents ?? renderedCount);
  const windowHours = Number(flowSummary.windowHours || 24);
  const idsMonitoredCount = Number(flowSummary.idsDetectedEvents ?? attacks.filter(item => item.eventType === 'ids_alert').length);
  const ipsBlockedCount = Number(flowSummary.ipsBlockedEvents ?? attacks.filter(item => item.eventType === 'ips_block').length);
  const wafProtectedCount = Number(flowSummary.wafEvents ?? attacks.filter(item => item.eventType === 'waf_attack').length);
  const displayedAgents = Array.isArray(customAgents) ? customAgents : agents;
  const activeAgentCount = Math.max(
    Number(flowSummary.activeAgentCount || 0),
    displayedAgents.filter(agent => ['active', 'online'].includes(String(agent?.status || '').toLowerCase())).length,
  );
  const locatedAgentCount = displayedAgents.filter(agent => hasMapCoordinate(agent.dstLat) && hasMapCoordinate(agent.dstLon)).length;

  return (
    <div style={{ position: 'relative', width: '100%', height: height === '100%' ? '100%' : height, display: 'flex', flexDirection: 'column', flex: 1, borderRadius: 12, overflow: 'hidden', background: '#0a1628', border: '1px solid rgba(59,130,246,0.35)', boxShadow: '0 0 15px rgba(0, 240, 255, 0.1)' }}>
      {/* Sci-Fi HUD Corner lines & Grid overlay */}
      <div style={{ position: 'absolute', inset: 0, pointerEvents: 'none', zIndex: 1001 }}>
        {/* CRT scanlines effect */}
        <div style={{
          position: 'absolute', inset: 0,
          background: 'linear-gradient(rgba(18,16,16,0) 50%, rgba(0,0,0,0.15) 50%), linear-gradient(90deg, rgba(255,0,0,0.03), rgba(0,255,0,0.01), rgba(0,0,255,0.03))',
          backgroundSize: '100% 4px, 6px 100%', opacity: 0.25
        }} />
        {/* Cyber Corners */}
        <div style={{ position: 'absolute', top: 12, left: 12, width: 14, height: 14, borderLeft: '2px solid #00f0ff', borderTop: '2px solid #00f0ff', opacity: 0.6 }} />
        <div style={{ position: 'absolute', top: 12, right: 12, width: 14, height: 14, borderRight: '2px solid #00f0ff', borderTop: '2px solid #00f0ff', opacity: 0.6 }} />
        <div style={{ position: 'absolute', bottom: 12, left: 12, width: 14, height: 14, borderLeft: '2px solid #00f0ff', borderBottom: '2px solid #00f0ff', opacity: 0.6 }} />
        <div style={{ position: 'absolute', bottom: 12, right: 12, width: 14, height: 14, borderRight: '2px solid #00f0ff', borderBottom: '2px solid #00f0ff', opacity: 0.6 }} />
      </div>

      {/* Live Badge */}
      <div style={{
        position: 'absolute', top: 16, left: 16, zIndex: 1000,
        background: 'rgba(10,22,40,0.9)', color: '#00f0ff',
        borderRadius: 4, padding: '4px 10px', fontSize: 10, fontWeight: 700,
        border: '1px solid rgba(0,240,255,0.4)', backdropFilter: 'blur(8px)',
        display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'monospace',
        boxShadow: '0 0 10px rgba(0,240,255,0.15)', textTransform: 'uppercase',
        letterSpacing: '1px'
      }}>
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: activeAgentCount ? '#22c55e' : '#f59e0b', display: 'inline-block', boxShadow: activeAgentCount ? '0 0 8px #22c55e' : '0 0 8px #f59e0b', animation: 'hackerPulse 1.2s infinite' }} />
        {dataMode === 'network'
          ? `[SYSTEM MONITOR]: ${showMonitorCount ? `${monitorCountLabel} ` : ''}${customLabel}`
          : `${customLabel} · ${activeAgentCount.toLocaleString('en-IN')} ACTIVE AGENT${activeAgentCount === 1 ? '' : 'S'} · ${windowHours}H`}
      </div>

      {dataMode === 'ids' && <div style={{
        position: 'absolute', top: 48, left: 16, zIndex: 1000,
        background: 'rgba(10,22,40,0.92)', borderRadius: 4, padding: '6px 10px',
        display: 'flex', flexWrap: 'wrap', gap: '5px 12px', maxWidth: 'calc(100% - 32px)', border: '1px solid rgba(0,240,255,0.25)',
        backdropFilter: 'blur(8px)', fontFamily: 'monospace', fontSize: 9, fontWeight: 800,
      }}>
        <span style={{ color: EVENT_META.ids_alert.color }}>{EVENT_META.ids_alert.icon} IDS MONITORED: {idsMonitoredCount.toLocaleString('en-IN')}</span>
        <span style={{ color: EVENT_META.ips_block.color }}>{EVENT_META.ips_block.icon} IPS BLOCKED: {ipsBlockedCount.toLocaleString('en-IN')}</span>
        <span style={{ color: EVENT_META.waf_attack.color }}>{EVENT_META.waf_attack.icon} WAF: {wafProtectedCount.toLocaleString('en-IN')}</span>
        <span style={{ color: '#22c55e' }}>📍 AJNAT LOCATIONS: {locatedAgentCount.toLocaleString('en-IN')}</span>
        <span style={{ color: '#94a3b8' }}>ORIGINS: {plottedOriginCount.toLocaleString('en-IN')}</span>
      </div>}

      {/* Map Mode Switcher (Google Maps / Google Earth / Dark) */}
      {renderedCount > 0 && <div style={{
        position: 'absolute', top: 16, right: 16, zIndex: 1000,
        background: 'rgba(10,22,40,0.9)', borderRadius: 4, padding: '3px',
        display: 'flex', gap: 4, border: '1px solid rgba(0,240,255,0.3)',
        backdropFilter: 'blur(8px)', fontFamily: 'monospace',
      }}>
        <button
          onClick={() => handleModeChange('google_dark')}
          style={{
            background: mapMode === 'google_dark' ? '#00f0ff' : 'transparent',
            color: mapMode === 'google_dark' ? '#0a1628' : '#00f0ff',
            border: 'none', borderRadius: 2, padding: '4px 10px',
            fontSize: 9, fontWeight: 700, cursor: 'pointer', transition: 'all 0.15s',
            textTransform: 'uppercase', letterSpacing: '0.5px'
          }}>
          Dark Map
        </button>
        <button
          onClick={() => handleModeChange('google_earth')}
          style={{
            background: mapMode === 'google_earth' ? '#00f0ff' : 'transparent',
            color: mapMode === 'google_earth' ? '#0a1628' : '#00f0ff',
            border: 'none', borderRadius: 2, padding: '4px 10px',
            fontSize: 9, fontWeight: 700, cursor: 'pointer', transition: 'all 0.15s',
            textTransform: 'uppercase', letterSpacing: '0.5px'
          }}>
          Satellite
        </button>
        <button
          onClick={() => handleModeChange('google_streets')}
          style={{
            background: mapMode === 'google_streets' ? '#00f0ff' : 'transparent',
            color: mapMode === 'google_streets' ? '#0a1628' : '#00f0ff',
            border: 'none', borderRadius: 2, padding: '4px 10px',
            fontSize: 9, fontWeight: 700, cursor: 'pointer', transition: 'all 0.15s',
            textTransform: 'uppercase', letterSpacing: '0.5px'
          }}>
          Roadmap
        </button>
      </div>}

      {/* Event-type legend */}
      {renderedCount > 0 && <div style={{
        position: 'absolute', bottom: 16, left: 16, zIndex: 1000,
        background: 'rgba(10,22,40,0.9)', borderRadius: 4, padding: '6px 12px',
        display: 'flex', gap: 12, fontSize: 9, border: '1px solid rgba(0,240,255,0.2)',
        backdropFilter: 'blur(8px)', fontFamily: 'monospace',
      }}>
        {Object.entries(EVENT_META).map(([type, meta]) => (
          <span key={type} style={{ color: meta.color, display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: meta.color, display: 'inline-block', boxShadow: `0 0 6px ${meta.color}` }} />
            {meta.label}
          </span>
        ))}
      </div>}

      {/* Map Container */}
      <div ref={mapDivRef} style={{ width: '100%', height: '100%', flex: 1, borderRadius: 12 }} />
      {status === 'ready' && plottedDataCount === 0 && (
        <div style={{ position: 'absolute', inset: 0, zIndex: 999, display: 'grid', placeItems: 'center', pointerEvents: 'none' }}>
          <div style={{ padding: '12px 18px', borderRadius: 8, color: '#94a3b8', background: 'rgba(6,14,26,.88)', border: '1px solid #1e3a5f', fontSize: 12, fontFamily: 'monospace' }}>
            {realCount > 0
              ? dataMode === 'network'
                ? 'Live connections received · waiting for public-IP or AJNAT GPS coordinates to draw routes'
                : 'No remote public attack origin detected · local and sensor-only diagnostics are not placed on the world map'
              : dataMode === 'network'
                ? `No ${customEventLabel.toLowerCase()} data in the selected window`
                : 'No IDS, IPS, or WAF attacks in the last 24 hours'}
          </div>
        </div>
      )}

      <style>{`
        /* Hacker Style Markers & Animations */
        @keyframes hackerPulse {
          0% { transform: scale(0.85); opacity: 0.5; box-shadow: 0 0 0 0 rgba(255, 0, 85, 0.4); }
          70% { transform: scale(1); opacity: 1; box-shadow: 0 0 0 8px rgba(255, 0, 85, 0); }
          100% { transform: scale(0.85); opacity: 0.5; box-shadow: 0 0 0 0 rgba(255, 0, 85, 0); }
        }

        /* Curvature Flow Line packet animation */
        .hacker-flowing-line {
          stroke-dasharray: 8, 16;
          animation: flowPackets 1s linear infinite;
        }
        .hacker-flowing-line-reverse {
          animation-direction: reverse;
        }
        @keyframes flowPackets {
          to {
            stroke-dashoffset: -24;
          }
        }
        .hacker-blocked-line {
          stroke-dasharray: 2, 6;
          animation: slowFlow 3s linear infinite;
        }
        @keyframes slowFlow {
          to {
            stroke-dashoffset: 8;
          }
        }

        /* Protected Crosshair */
        .hacker-crosshair-container {
          position: relative;
          width: 40px;
          height: 40px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .ajnat-agent-highlight {
          width: 56px;
          height: 56px;
          filter: drop-shadow(0 0 9px rgba(239, 68, 68, .98));
        }
        .ajnat-agent-halo {
          position: absolute;
          width: 44px;
          height: 44px;
          border-radius: 50%;
          border: 2px solid #ef4444;
          background: rgba(239, 68, 68, .14);
          box-shadow: 0 0 20px rgba(239, 68, 68, .9), inset 0 0 12px rgba(239, 68, 68, .5);
          animation: ajnatAgentPulse 1.7s ease-out infinite;
        }
        .ajnat-agent-event-count {
          position: absolute;
          top: 48px;
          left: 50%;
          transform: translateX(-50%);
          min-width: max-content;
          padding: 3px 7px;
          border: 1px solid rgba(56,189,248,.8);
          border-radius: 4px;
          background: rgba(2,6,23,.94);
          color: #38bdf8;
          box-shadow: 0 0 10px rgba(56,189,248,.45);
          font: 800 10px/1.2 monospace;
          letter-spacing: .4px;
          white-space: nowrap;
        }
        .ajnat-agent-highlight .hacker-crosshair-ring {
          border-color: #ef4444;
          box-shadow: 0 0 8px rgba(239, 68, 68, .75);
        }
        .ajnat-agent-highlight .hacker-crosshair-lines::before,
        .ajnat-agent-highlight .hacker-crosshair-lines::after,
        .ajnat-agent-highlight .hacker-crosshair-center {
          background: #ef4444;
          box-shadow: 0 0 12px #ef4444;
        }
        @keyframes ajnatAgentPulse {
          0% { transform: scale(.65); opacity: 1; }
          75%, 100% { transform: scale(1.45); opacity: 0; }
        }
        .ajnat-agent-tooltip {
          color: #fee2e2 !important;
          background: rgba(69, 10, 10, .96) !important;
          border: 1px solid #ef4444 !important;
          box-shadow: 0 0 18px rgba(239, 68, 68, .7) !important;
          font-size: 10px !important;
        }
        .hacker-crosshair-ring {
          position: absolute;
          border-radius: 50%;
          border: 1px dashed #00f0ff;
          opacity: 0.8;
          box-shadow: 0 0 6px rgba(0, 240, 255, 0.3);
        }
        .ring-1 {
          width: 32px;
          height: 32px;
          animation: spinCw 10s linear infinite;
        }
        .ring-2 {
          width: 20px;
          height: 20px;
          border-style: dotted;
          animation: spinCcw 6s linear infinite;
        }
        .hacker-crosshair-lines {
          position: absolute;
          width: 100%;
          height: 100%;
        }
        .hacker-crosshair-lines::before, .hacker-crosshair-lines::after {
          content: '';
          position: absolute;
          background: #00f0ff;
          opacity: 0.6;
        }
        .hacker-crosshair-lines::before {
          top: 50%; left: 0; width: 100%; height: 1px;
        }
        .hacker-crosshair-lines::after {
          top: 0; left: 50%; width: 1px; height: 100%;
        }
        .hacker-crosshair-center {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #ff0055;
          box-shadow: 0 0 10px #ff0055;
          z-index: 5;
        }

        @keyframes spinCw {
          to { transform: rotate(360deg); }
        }
        @keyframes spinCcw {
          to { transform: rotate(-360deg); }
        }

        /* Attacker Node Style */
        .hacker-threat-node {
          position: relative;
          width: 20px;
          height: 20px;
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .node-ring {
          position: absolute;
          width: 20px;
          height: 20px;
          border-radius: 50%;
          border: 1.5px solid var(--threat-color);
          animation: pingRing 1.5s cubic-bezier(0, 0, 0.2, 1) infinite;
        }
        .node-core {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: var(--threat-color);
          box-shadow: 0 0 8px var(--threat-color);
        }
        @keyframes pingRing {
          75%, 100% {
            transform: scale(2.5);
            opacity: 0;
          }
        }

        /* Hacker Popup Styles */
        .leaflet-popup-content-wrapper {
          background: rgba(10, 22, 40, 0.95) !important;
          color: #f8fafc !important;
          border-radius: 4px !important;
          border: 1px solid #00f0ff !important;
          box-shadow: 0 0 15px rgba(0, 240, 255, 0.25) !important;
          backdrop-filter: blur(8px);
        }
        .leaflet-popup-tip {
          background: rgba(10, 22, 40, 0.95) !important;
          border-left: 1px solid #00f0ff !important;
          border-bottom: 1px solid #00f0ff !important;
        }

        /* Hacker Permanent Tooltip */
        .hacker-tooltip-permanent {
          background: rgba(10, 22, 40, 0.92) !important;
          color: #00f0ff !important;
          border: 1px solid rgba(0, 240, 255, 0.6) !important;
          box-shadow: 0 0 10px rgba(0, 240, 255, 0.3) !important;
          font-family: monospace !important;
          font-size: 9px !important;
          font-weight: 700 !important;
          padding: 2px 6px !important;
          border-radius: 4px !important;
          text-shadow: 0 0 4px rgba(0, 240, 255, 0.5) !important;
        }
        .hacker-tooltip-permanent::before {
          border-top-color: rgba(10, 22, 40, 0.92) !important;
        }
      `}</style>
    </div>
  );
}
