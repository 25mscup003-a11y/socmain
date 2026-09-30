/**
 * GoogleAttackMap.jsx
 * Real-time IDS/IPS Attack Map using Real Google Maps & Google Earth Tiles.
 * Supports Google Maps Roadmap, Google Earth Satellite View, Dark Theme,
 * animated threat trajectory arcs, pulse markers, and interactive threat popups.
 */
import { useEffect, useRef, useState, useCallback } from 'react';
import api from '../api/axios';

const SEV_COLOR = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#22c55e',
};

// Dynamically load Leaflet for tile rendering
let leafletPromise = null;
function loadLeaflet() {
  if (window.L) return Promise.resolve(window.L);
  if (leafletPromise) return leafletPromise;
  leafletPromise = new Promise((resolve, reject) => {
    if (!document.getElementById('leaflet-css-cdn')) {
      const link = document.createElement('link');
      link.id = 'leaflet-css-cdn';
      link.rel = 'stylesheet';
      link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
      document.head.appendChild(link);
    }
    const script = document.createElement('script');
    script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
    script.onload = () => resolve(window.L);
    script.onerror = () => reject(new Error('LEAFLET_LOAD_FAILED'));
    document.head.appendChild(script);
  });
  return leafletPromise;
}

export default function GoogleAttackMap({ height = 320, refreshInterval = 30000, selectedIp = null, customAttacks = null, customTotal = null, showMonitorCount = true, customLabel = 'NETWORK MONITORING', customEventLabel = 'NETWORK CONNECTION' }) {
  const mapDivRef      = useRef(null);
  const mapInstanceRef = useRef(null);
  const layerGroupRef  = useRef(null);
  const tileLayerRef   = useRef(null);
  const markerMapRef   = useRef({});

  const [attacks, setAttacks]     = useState([]);
  const [liveCount, setLiveCount] = useState(0);
  const [mapMode, setMapMode]     = useState('google_dark'); // google_dark | google_earth | google_streets
  const [status, setStatus]       = useState('loading'); // loading | ready | error

  // Fetch live attack data from backend
  const fetchAttacks = useCallback(async () => {
    if (customAttacks) return;
    try {
      const { data } = await api.get('/ids/geo-attacks');
      if (data?.attacks) {
        setAttacks(data.attacks);
        setLiveCount(data.total || data.attacks.length || 0);
      }
    } catch {
      // Keep existing data on fetch error
    }
  }, [customAttacks]);

  useEffect(() => {
    if (customAttacks) {
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

    const hasCoordinate = value => value !== null && value !== undefined && value !== '' && Number.isFinite(Number(value));
    const firstDestination = dataToRender.find(item => hasCoordinate(item.dstLat) && hasCoordinate(item.dstLon));
    const dstLat = firstDestination ? Number(firstDestination.dstLat) : null;
    const dstLon = firstDestination ? Number(firstDestination.dstLon) : null;

    if (dataToRender.length === 0) return;

    // Protected Destination Marker (real configured AJNAT agent location only)
    const dstMarkerIcon = L.divIcon({
      className: 'dst-radar-marker',
      html: `
        <div class="hacker-crosshair-container">
          <div class="hacker-crosshair-ring ring-1"></div>
          <div class="hacker-crosshair-ring ring-2"></div>
          <div class="hacker-crosshair-lines"></div>
          <div class="hacker-crosshair-center"></div>
        </div>
      `,
      iconSize: [40, 40],
      iconAnchor: [20, 20],
    });

    if (firstDestination) {
    const dstMarker = L.marker([dstLat, dstLon], { icon: dstMarkerIcon }).bindPopup(`
      <div style="font-family:monospace;font-size:12px;line-height:1.5">
        <b style="color:#00f0ff">🛡️ ${firstDestination.dstName || 'AJNAT AGENT'}</b><br/>
        <span style="color:#cbd5e1">IP: ${firstDestination.dstIp || '—'}</span><br/>
        <span style="color:#cbd5e1">${Number(dstLat).toFixed(5)}, ${Number(dstLon).toFixed(5)}</span><br/>
        <span style="color:#94a3b8">Source: ${firstDestination.dstLocationSource || 'Agent telemetry'}</span><br/>
        <span style="color:#22c55e">Status: Active & Protected</span>
      </div>
    `).bindTooltip("🛡️ AGENT (ACTIVE)", {
      permanent: true,
      direction: 'top',
      offset: [0, -15],
      className: 'hacker-tooltip-permanent'
    });
    layerGroupRef.current.addLayer(dstMarker);
    }

    // Plot each threat attack
    dataToRender.forEach(atk => {
      if (!hasCoordinate(atk.srcLat) || !hasCoordinate(atk.srcLon)) return;
      const col = SEV_COLOR[atk.severity] || '#60a5fa';
      const start = [atk.srcLat, atk.srcLon];
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
        className: atk.blocked ? 'hacker-blocked-line' : 'hacker-flowing-line',
      });
      layerGroupRef.current.addLayer(polyline);
      }

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

      const srcMarker = L.marker(start, { icon: srcMarkerIcon }).bindPopup(`
        <div style="font-family:monospace;font-size:12px;line-height:1.6;min-width:210px">
          <div style="font-weight:bold;color:${col};text-transform:uppercase;margin-bottom:6px;border-bottom:1px solid rgba(255,255,255,0.1);padding-bottom:3px">
            ${atk.eventType === 'waf_attack' ? '🔥 WAF ATTACK' : atk.eventType === 'ips_block' ? '🛡️ IPS BLOCK' : atk.eventType === 'ids_alert' ? '⚠️ IDS ATTACK' : `🌐 ${customEventLabel}`} ${atk.blocked ? '<span style="color:#22c55e">[BLOCKED]</span>' : ''}
          </div>
          <div><b>IP:</b> ${atk.srcIp}</div>
          <div><b>Location:</b> ${[atk.srcCity, atk.srcCountry].filter(Boolean).join(', ') || 'Unknown'}</div>
          <div><b>ISP:</b> ${atk.srcISP || '—'}</div>
          <div><b>${customAttacks ? 'Activity' : 'Attack'}:</b> ${atk.description || 'IDS Alert'}</div>
          <div style="color:#64748b;font-size:10px;margin-top:6px;border-top:1px solid rgba(255,255,255,0.05);padding-top:4px">
            ${atk.timestamp ? new Date(atk.timestamp).toLocaleString() : ''}
          </div>
        </div>
      `);
      layerGroupRef.current.addLayer(srcMarker);
      markerMapRef.current[atk.srcIp] = srcMarker;
    });
  }, [selectedIp, customAttacks, customEventLabel]);

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
    if (!customAttacks) {
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
  }, [fetchAttacks, switchTileLayer, mapMode, customAttacks]);

  // Re-render markers when attack list changes
  useEffect(() => {
    if (status !== 'ready' || !mapInstanceRef.current || !window.L) return;
    renderAttacksOnMap(window.L, mapInstanceRef.current, attacks);
  }, [attacks, status, renderAttacksOnMap]);

  // Handle selectedIp propagation and auto pan & zoom
  useEffect(() => {
    if (!selectedIp || !mapInstanceRef.current || !window.L) return;
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
    if (mapInstanceRef.current && window.L) {
      switchTileLayer(window.L, mapInstanceRef.current, mode);
    }
  };

  // Periodic refresh
  useEffect(() => {
    if (customAttacks) return;
    const tid = setInterval(fetchAttacks, refreshInterval);
    return () => clearInterval(tid);
  }, [fetchAttacks, refreshInterval, customAttacks]);

  const renderedCount = attacks.length;
  const realCount = customAttacks && Number.isFinite(Number(customTotal)) ? Number(customTotal) : liveCount;
  const monitorCountLabel = realCount.toLocaleString('en-IN');

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
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: realCount ? '#ff0055' : '#64748b', display: 'inline-block', boxShadow: realCount ? '0 0 8px #ff0055' : 'none', animation: realCount ? 'hackerPulse 1.2s infinite' : 'none' }} />
        [SYSTEM MONITOR]: {showMonitorCount ? `${monitorCountLabel} ` : ''}{customAttacks ? customLabel : 'IDS / IPS / WAF ATTACKS'}
      </div>

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

      {/* Severity Legend */}
      {renderedCount > 0 && <div style={{
        position: 'absolute', bottom: 16, left: 16, zIndex: 1000,
        background: 'rgba(10,22,40,0.9)', borderRadius: 4, padding: '6px 12px',
        display: 'flex', gap: 12, fontSize: 9, border: '1px solid rgba(0,240,255,0.2)',
        backdropFilter: 'blur(8px)', fontFamily: 'monospace',
      }}>
        {Object.entries(SEV_COLOR).map(([sev, col]) => (
          <span key={sev} style={{ color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: col, display: 'inline-block', boxShadow: `0 0 6px ${col}` }} />
            {sev.toUpperCase()}
          </span>
        ))}
      </div>}

      {/* Map Container */}
      <div ref={mapDivRef} style={{ width: '100%', height: '100%', flex: 1, borderRadius: 12 }} />
      {status === 'ready' && renderedCount === 0 && (
        <div style={{ position: 'absolute', inset: 0, zIndex: 999, display: 'grid', placeItems: 'center', pointerEvents: 'none' }}>
          <div style={{ padding: '12px 18px', borderRadius: 8, color: '#94a3b8', background: 'rgba(6,14,26,.88)', border: '1px solid #1e3a5f', fontSize: 12, fontFamily: 'monospace' }}>
            {realCount > 0
              ? 'Events found, but public IP geolocation is unavailable'
              : customAttacks
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
