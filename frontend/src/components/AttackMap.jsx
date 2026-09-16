import React, { useEffect, useRef, useState } from 'react';
import L from 'leaflet';
import { Globe2, Shield, Crosshair, Search, Radio, Layers, ZoomIn, ZoomOut, RefreshCw } from 'lucide-react';

export default function AttackMap({ countries = [], recentAttacks = [], onSelectIP }) {
  const mapContainerRef = useRef(null);
  const mapInstanceRef = useRef(null);
  const layerGroupRef = useRef(null);
  const [selectedCountry, setSelectedCountry] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Default honeypot sensor coordinates (e.g. Frankfurt Central SOC node)
  const sensorCoords = [50.1109, 8.6821];

  useEffect(() => {
    if (!mapContainerRef.current) return;

    if (!mapInstanceRef.current) {
      // Initialize Leaflet Map
      const map = L.map(mapContainerRef.current, {
        center: [25, 10],
        zoom: 2,
        minZoom: 2,
        maxZoom: 10,
        zoomControl: false,
        attributionControl: false,
      });

      // CartoDB Dark Matter tiles (Professional enterprise dark theme)
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19,
      }).addTo(map);

      // Add zoom control top right
      L.control.zoom({ position: 'topright' }).addTo(map);

      const layerGroup = L.layerGroup().addTo(map);
      layerGroupRef.current = layerGroup;
      mapInstanceRef.current = map;
    }

    const map = mapInstanceRef.current;
    const layerGroup = layerGroupRef.current;
    layerGroup.clearLayers();

    // 1. Plot Honeypot Sensor Node
    const sensorIcon = L.divIcon({
      className: 'honeypot-sensor-pin',
      html: `
        <div style="position:relative; width:22px; height:22px;">
          <div style="position:absolute; inset:0; border-radius:9999px; background:#06b6d4; opacity:0.3; animation:ping 2s cubic-bezier(0,0,0.2,1) infinite;"></div>
          <div style="position:absolute; inset:3px; border-radius:9999px; background:#06b6d4; border:2px solid #ecfeff; box-shadow:0 0 10px #06b6d4;"></div>
        </div>
      `,
      iconSize: [22, 22],
      iconAnchor: [11, 11],
    });

    const sensorMarker = L.marker(sensorCoords, { icon: sensorIcon }).addTo(layerGroup);
    sensorMarker.bindPopup(`
      <div style="font-family:monospace; font-size:11px; line-height:1.4;">
        <div style="color:#38bdf8; font-weight:bold; border-bottom:1px solid #334155; padding-bottom:4px; margin-bottom:4px;">
          COWRIE HONEYPOT SENSOR #1
        </div>
        <div style="color:#94a3b8;">Location: Frankfurt, Germany (EU-West)</div>
        <div style="color:#94a3b8;">Status: <span style="color:#4ade80; font-weight:bold;">ACTIVE LISTENING</span></div>
        <div style="color:#94a3b8;">Ports: 22 (SSH), 23 (Telnet), 2222</div>
      </div>
    `);

    // 2. Plot Attacker Origin Hotspots & Trajectory Arcs
    const maxCount = Math.max(...countries.map((c) => c.count), 1);

    countries.forEach((c) => {
      if (!c.latitude || !c.longitude) return;

      const originCoords = [c.latitude, c.longitude];
      const radius = Math.min(28, Math.max(8, (c.count / maxCount) * 26));

      // Draw attack circle
      const circle = L.circleMarker(originCoords, {
        radius: radius,
        fillColor: '#f43f5e',
        fillOpacity: 0.5,
        color: '#fda4af',
        weight: 1.5,
      }).addTo(layerGroup);

      circle.bindPopup(`
        <div style="font-family:monospace; font-size:11px; line-height:1.4;">
          <div style="color:#f43f5e; font-weight:bold; border-bottom:1px solid #334155; padding-bottom:4px; margin-bottom:4px;">
            THREAT ORIGIN: ${c.country_name} (${c.country_code})
          </div>
          <div style="color:#cbd5e1;">Attack Volume: <strong>${c.count.toLocaleString()}</strong> events</div>
          <div style="color:#cbd5e1;">Coordinates: ${c.latitude.toFixed(2)}, ${c.longitude.toFixed(2)}</div>
          <div style="color:#94a3b8; font-size:10px; margin-top:4px;">Adversary cluster detected</div>
        </div>
      `);

      circle.on('click', () => {
        setSelectedCountry(c);
      });

      // Draw trajectory line to sensor
      L.polyline([originCoords, sensorCoords], {
        color: '#f43f5e',
        weight: 1.2,
        opacity: 0.25,
        dashArray: '4, 6',
      }).addTo(layerGroup);
    });

    // Handle map resize cleanly
    setTimeout(() => {
      if (map) map.invalidateSize();
    }, 150);

  }, [countries]);

  const totalAttacks = countries.reduce((sum, c) => sum + c.count, 0) || 1;

  const filteredCountries = countries.filter((c) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.country_name.toLowerCase().includes(q) ||
      c.country_code.toLowerCase().includes(q)
    );
  });

  const handleCenterOnCountry = (c) => {
    setSelectedCountry(c);
    if (mapInstanceRef.current && c.latitude && c.longitude) {
      mapInstanceRef.current.setView([c.latitude, c.longitude], 4, { animate: true });
    }
  };

  return (
    <div className="rounded-lg bg-[#0b1120] border border-slate-800 shadow-xl overflow-hidden">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-slate-800 bg-[#080d1a]">
        <div className="flex items-center gap-2.5">
          <Globe2 className="h-4 w-4 text-cyan-400" />
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
            GEOLOCATION ATTACK ORIGIN RADAR & SENSOR MAPPING
          </h2>
          <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[10px] font-mono text-cyan-400 border border-cyan-500/20">
            Live Dark Matter Tiles &bull; {countries.length} Origin Zones
          </span>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-slate-400">
            <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#06b6d4]" />
            <span>Honeypot Sensor</span>
          </div>
          <div className="flex items-center gap-1.5 text-slate-400">
            <span className="h-2 w-2 rounded-full bg-rose-500 shadow-[0_0_8px_#f43f5e]" />
            <span>Adversary Hotspot</span>
          </div>
        </div>
      </div>

      {/* Map + Sidebar Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 min-h-[460px]">
        {/* Leaflet Map Area */}
        <div className="lg:col-span-3 relative h-[460px] w-full bg-[#060913]">
          <div ref={mapContainerRef} className="h-full w-full z-10" />

          {/* Map Overlay Floating HUD */}
          <div className="absolute bottom-3 left-3 z-20 rounded-md bg-[#0b1120]/90 border border-slate-800 p-2.5 backdrop-blur-sm text-[11px] font-mono text-slate-400 space-y-1">
            <div className="flex justify-between gap-4">
              <span>Sensor Location:</span>
              <span className="text-slate-200 font-bold">Frankfurt (EU-Central)</span>
            </div>
            <div className="flex justify-between gap-4">
              <span>Total Origin Vectors:</span>
              <span className="text-cyan-400 font-bold">{countries.length} Countries</span>
            </div>
            <div className="flex justify-between gap-4">
              <span>Cumulative Intercepts:</span>
              <span className="text-rose-400 font-bold">{totalAttacks.toLocaleString()}</span>
            </div>
          </div>
        </div>

        {/* Origin Leaderboard Sidebar */}
        <div className="border-t lg:border-t-0 lg:border-l border-slate-800 bg-[#090e1b] flex flex-col h-[460px]">
          <div className="p-3 border-b border-slate-800">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                placeholder="Filter origin country..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full rounded bg-slate-950 border border-slate-800 pl-8 pr-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {filteredCountries.map((c, idx) => {
              const pct = ((c.count / totalAttacks) * 100).toFixed(1);
              const isSelected = selectedCountry?.country_code === c.country_code;

              return (
                <div
                  key={idx}
                  onClick={() => handleCenterOnCountry(c)}
                  className={`p-2.5 rounded border transition-all cursor-pointer font-mono text-xs ${
                    isSelected
                      ? 'bg-cyan-500/10 border-cyan-500/40 text-cyan-200'
                      : 'bg-slate-950/60 border-slate-850 hover:bg-slate-900/80 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold flex items-center gap-1.5 truncate">
                      <span className="text-slate-500 text-[10px]">#{idx + 1}</span>
                      <span className="text-slate-100">{c.country_name}</span>
                      <span className="text-slate-500 text-[10px]">({c.country_code})</span>
                    </span>
                    <span className="text-slate-200 font-bold ml-2 shrink-0">
                      {c.count.toLocaleString()}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1 bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-rose-500 to-amber-500 rounded-full"
                        style={{ width: `${Math.max(Number(pct), 4)}%` }}
                      />
                    </div>
                    <span className="text-[10px] text-slate-400 shrink-0">{pct}%</span>
                  </div>
                </div>
              );
            })}

            {filteredCountries.length === 0 && (
              <div className="py-12 text-center text-xs font-mono text-slate-500">
                No telemetry recorded for this filter.
              </div>
            )}
          </div>

          <div className="p-2.5 border-t border-slate-800 bg-[#080d1a] text-[10px] font-mono text-slate-500 flex justify-between">
            <span>Projection: WGS84</span>
            <span className="text-cyan-400">CartoDB Dark Matter</span>
          </div>
        </div>
      </div>
    </div>
  );
}
