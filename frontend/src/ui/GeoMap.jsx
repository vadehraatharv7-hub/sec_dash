import { useEffect, useMemo, useRef, useState } from 'react';
import { Minus, Plus } from 'lucide-react';
import { feature } from 'topojson-client';
import world from 'world-atlas/countries-110m.json';
import { compact } from '../lib/format';
import { riskColor } from '../lib/theme';

// Natural Earth projection (Savric 2011), output in a 1000 x ~520 viewport.
const W = 1000;
const H = 520;
const rad = Math.PI / 180;
function project(lon, lat) {
  const l = lon * rad;
  const p = lat * rad;
  const p2 = p * p;
  const p4 = p2 * p2;
  const x = l * (0.8707 - 0.131979 * p2 + p4 * (-0.013791 + p4 * p4 * (0.003971 * p2 - 0.001529 * p4)));
  const y = p * (1.007226 + p2 * (0.015085 + p4 * (-0.044475 + 0.028874 * p2 - 0.005916 * p4)));
  return [x, y];
}
const [X0] = project(-180, 0);
const [, Y0] = project(0, 85);
const [, Y1] = project(0, -58);
const SX = W / (-2 * X0);
const SY = H / (Y1 - Y0);
const S = Math.min(SX, SY * 1.0);
const px = (lon, lat) => { const [x, y] = project(lon, lat); return [W / 2 + x * S, (y - Y0) * S + 6]; };

let landPath = null;
function getLand() {
  if (landPath) return landPath;
  const fc = feature(world, world.objects.countries);
  const ring = (r) => r.map((c, i) => { const [x, y] = px(c[0], c[1]); return `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`; }).join('') + 'Z';
  const polys = (g) => (g.type === 'Polygon' ? [g.coordinates] : g.type === 'MultiPolygon' ? g.coordinates : []);
  landPath = fc.features.filter((f) => String(f.id) !== '010').map((f) => polys(f.geometry).map((p) => p.map(ring).join('')).join('')).join('');
  return landPath;
}

/** Offline world map with one bubble per attacker location. */
export default function GeoMap({ points, height = 340, onSelect }) {
  const land = useMemo(getLand, []);
  const wrap = useRef(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const [tip, setTip] = useState(null);
  const drag = useRef(null);
  const max = Math.max(1, ...points.map((p) => p.events));

  const zoom = (f, cx = W / 2, cy = H / 2) => setView((v) => {
    const k = Math.min(8, Math.max(1, v.k * f));
    const nx = cx - ((cx - v.x) / v.k) * k;
    const ny = cy - ((cy - v.y) / v.k) * k;
    return clampView({ k, x: nx, y: ny });
  });
  const clampView = (v) => ({ k: v.k, x: Math.min(0, Math.max(W - W * v.k, v.x)), y: Math.min(0, Math.max(H - H * v.k, v.y)) });

  useEffect(() => {
    const el = wrap.current;
    if (!el) return undefined;
    const onWheel = (e) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoom(e.deltaY < 0 ? 1.25 : 0.8, ((e.clientX - r.left) / r.width) * W, ((e.clientY - r.top) / r.height) * H);
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    return () => el.removeEventListener('wheel', onWheel);
  }, []);

  const onDown = (e) => { drag.current = { x: e.clientX, y: e.clientY, v: view }; };
  const onMove = (e) => {
    if (!drag.current || !wrap.current) return;
    const r = wrap.current.getBoundingClientRect();
    const dx = ((e.clientX - drag.current.x) / r.width) * W;
    const dy = ((e.clientY - drag.current.y) / r.height) * H;
    setView(clampView({ k: drag.current.v.k, x: drag.current.v.x + dx, y: drag.current.v.y + dy }));
  };
  const onUp = () => { drag.current = null; };

  const k = view.k;
  return (
    <div ref={wrap} className="relative w-full overflow-hidden rounded-lg bg-[#070d18] select-none touch-none" style={{ height }}
      onMouseDown={onDown} onMouseMove={onMove} onMouseUp={onUp} onMouseLeave={() => { onUp(); setTip(null); }}>
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" className="absolute inset-0 w-full h-full" role="img" aria-label="Map of attacker locations">
        <g transform={`translate(${view.x} ${view.y}) scale(${k})`}>
          <path d={land} fill="#1a2a43" stroke="#2f4468" strokeWidth={0.5 / k} strokeLinejoin="round" />
          {points.map((p) => {
            const [x, y] = px(p.lon, p.lat);
            const c = riskColor(p.max_risk);
            const r = (3 + Math.sqrt(p.events / max) * 13) / Math.sqrt(k);
            return (
              <g key={`${p.lat}${p.lon}`} onMouseEnter={(e) => setTip({ p, x: e.clientX, y: e.clientY })} onMouseMove={(e) => setTip({ p, x: e.clientX, y: e.clientY })}
                onMouseLeave={() => setTip(null)} onClick={() => onSelect?.(p)} style={{ cursor: onSelect ? 'pointer' : 'default' }}>
                <circle cx={x} cy={y} r={r * 2} fill={c} opacity="0.1" />
                <circle cx={x} cy={y} r={r} fill={c} fillOpacity="0.5" stroke={c} strokeWidth={1 / k} />
              </g>
            );
          })}
        </g>
      </svg>
      <div className="absolute right-2 top-2 flex flex-col gap-1">
        <button type="button" onClick={() => zoom(1.4)} aria-label="Zoom in" className="grid h-7 w-7 place-items-center rounded-md border border-line2 bg-panel2/90 text-soft hover:text-ink"><Plus size={14} /></button>
        <button type="button" onClick={() => zoom(1 / 1.4)} aria-label="Zoom out" className="grid h-7 w-7 place-items-center rounded-md border border-line2 bg-panel2/90 text-soft hover:text-ink"><Minus size={14} /></button>
      </div>
      <div className="absolute left-2 bottom-2 flex items-center gap-3 rounded-md bg-panel2/80 px-2 py-1 text-[10px] text-mute">
        {[['Low', 10], ['Medium', 40], ['High', 65], ['Critical', 90]].map(([l, v]) => (
          <span key={l} className="flex items-center gap-1"><i className="inline-block h-2 w-2 rounded-full" style={{ background: riskColor(v) }} />{l}</span>
        ))}
      </div>
      {tip && (
        <div className="pointer-events-none fixed z-50 rounded-lg border border-line2 bg-panel2/95 px-2.5 py-1.5 text-xs shadow-xl"
          style={{ left: tip.x + 12, top: tip.y + 12 }}>
          <b>{tip.p.city || tip.p.country || 'Unknown'}{tip.p.city && tip.p.country ? `, ${tip.p.country}` : ''}</b>
          <div className="text-mute">{compact(tip.p.events)} events - {tip.p.attackers} attacker{tip.p.attackers === 1 ? '' : 's'}</div>
          {tip.p.top_ip && <div className="font-mono text-[11px] text-accent mt-0.5">{tip.p.top_ip}</div>}
        </div>
      )}
    </div>
  );
}
