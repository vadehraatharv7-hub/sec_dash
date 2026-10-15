import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { bucketLabel, compact, nf } from '../lib/format';
import { cx } from './primitives';

function useWidth() {
  const ref = useRef(null);
  const [w, setW] = useState(0);
  useEffect(() => {
    if (!ref.current) return undefined;
    const ro = new ResizeObserver(([e]) => setW(Math.max(0, Math.floor(e.contentRect.width))));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  const n = v / p;
  const r = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
  return r * p;
}

/** Stacked column chart over time with a hover tooltip. */
export function StackedBars({ data, series, bucketSeconds, height = 220 }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState(null);
  const m = { l: 40, r: 8, t: 8, b: 22 };
  const iw = width - m.l - m.r;
  const ih = height - m.t - m.b;
  const totals = useMemo(() => data.map((d) => series.reduce((s, k) => s + (d[k.key] || 0), 0)), [data, series]);
  const max = niceMax(Math.max(1, ...totals));
  const n = Math.max(1, data.length);
  const bw = iw / n;
  const gap = Math.min(3, bw * 0.2);
  const y = (v) => m.t + ih - (v / max) * ih;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * max);
  const every = Math.ceil(n / Math.max(2, Math.floor(iw / 78)));

  return (
    <div ref={ref} className="relative w-full overflow-hidden select-none" style={{ height }}>
      {width > 0 && <svg width={width} height={height} role="img" aria-label="Activity over time"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect();
          const i = Math.floor((e.clientX - r.left - m.l) / bw);
          setHover(i >= 0 && i < n ? i : null);
        }}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={m.l} x2={width - m.r} y1={y(t)} y2={y(t)} stroke="var(--color-line)" strokeDasharray={t === 0 ? '' : '2 4'} />
            <text x={m.l - 6} y={y(t) + 3.5} textAnchor="end" fontSize="10" fill="var(--color-faint)">{compact(t)}</text>
          </g>
        ))}
        {data.map((d, i) => {
          let acc = 0;
          return (
            <g key={d.t} opacity={hover === null || hover === i ? 1 : 0.55}>
              {series.map((s) => {
                const v = d[s.key] || 0;
                if (!v) return null;
                const h = (v / max) * ih;
                const yy = m.t + ih - ((acc + v) / max) * ih;
                acc += v;
                return <rect key={s.key} x={m.l + i * bw + gap / 2} y={yy} width={Math.max(1, bw - gap)} height={Math.max(0.5, h - 0.5)} fill={s.color} rx={bw > 8 ? 1.5 : 0} />;
              })}
            </g>
          );
        })}
        {data.map((d, i) => (i % every === 0 ? (
          <text key={d.t} x={m.l + i * bw + bw / 2} y={height - 6} textAnchor="middle" fontSize="10" fill="var(--color-faint)">
            {bucketLabel(d.t, bucketSeconds)}
          </text>
        ) : null))}
      </svg>}
      {hover !== null && data[hover] && (
        <div
          className="pointer-events-none absolute z-10 rounded-lg border border-line2 bg-panel2/95 backdrop-blur px-3 py-2 text-xs shadow-xl"
          style={{ left: Math.min(width - 190, Math.max(0, m.l + hover * bw - 70)), top: 4, width: 180 }}
        >
          <div className="text-mute mb-1">{bucketLabel(data[hover].t, bucketSeconds)}</div>
          <div className="flex justify-between font-semibold mb-1"><span>Total</span><span className="num">{nf.format(totals[hover])}</span></div>
          {series.map((s) => (data[hover][s.key] ? (
            <div key={s.key} className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-1.5 text-soft"><i className="inline-block w-2 h-2 rounded-sm" style={{ background: s.color }} />{s.label}</span>
              <span className="num">{nf.format(data[hover][s.key])}</span>
            </div>
          ) : null))}
        </div>
      )}
    </div>
  );
}

export function Legend({ series, className }) {
  return (
    <div className={cx('flex flex-wrap gap-x-4 gap-y-1', className)}>
      {series.map((s) => (
        <span key={s.key} className="flex items-center gap-1.5 text-xs text-mute">
          <i className="inline-block w-2 h-2 rounded-sm" style={{ background: s.color }} />{s.label}
        </span>
      ))}
    </div>
  );
}

export function Sparkline({ values, color = 'var(--color-accent)', height = 28, width = 90, fill = true }) {
  const id = `sp${useId().replace(/:/g, '')}`;
  if (!values?.length) return <div style={{ height, width }} />;
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const pts = values.map((v, i) => [i * step, height - 2 - (v / max) * (height - 4)]);
  const line = pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
  const area = `${line} L${width},${height} L0,${height} Z`;
  return (
    <svg width={width} height={height} aria-hidden>
      {fill && (
        <>
          <defs>
            <linearGradient id={id} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor={color} stopOpacity=".35" />
              <stop offset="1" stopColor={color} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={area} fill={`url(#${id})`} />
        </>
      )}
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

/** Horizontal ranked bars. */
export function BarList({ items, max, color = 'var(--color-accent)', empty = 'No data', format = nf.format, mono }) {
  if (!items?.length) return <div className="text-xs text-mute py-6 text-center">{empty}</div>;
  const top = max || Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="space-y-1.5">
      {items.map((it) => {
        const Tag = it.onClick ? 'button' : 'div';
        return (
          <li key={it.key ?? it.label}>
            <Tag
              type={it.onClick ? 'button' : undefined}
              onClick={it.onClick}
              className={cx('group relative w-full text-left rounded-md overflow-hidden', it.onClick && 'hover:bg-panel2/60')}
            >
              <span
                className="absolute inset-y-0 left-0 rounded-md opacity-20 transition-all"
                style={{ width: `${Math.max(2, (it.value / top) * 100)}%`, background: it.color || color }}
              />
              <span className="relative flex items-center justify-between gap-3 px-2 py-1.5 text-[13px]">
                <span className={cx('truncate', mono && 'font-mono text-[12px]')} title={typeof it.label === 'string' ? it.label : undefined}>{it.label}</span>
                <span className="flex items-center gap-2 shrink-0 num">
                  {it.sub && <span className="text-xs text-mute">{it.sub}</span>}
                  <span className="font-medium">{format(it.value)}</span>
                </span>
              </span>
            </Tag>
          </li>
        );
      })}
    </ul>
  );
}

export function Donut({ slices, size = 150, thickness = 18, center }) {
  const total = slices.reduce((s, x) => s + x.value, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let off = 0;
  return (
    <div className="flex items-center gap-4">
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90" role="img" aria-label="Distribution">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-line)" strokeWidth={thickness} />
          {total > 0 && slices.map((s) => {
            const len = (s.value / total) * c;
            const el = (
              <circle key={s.label} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color} strokeWidth={thickness}
                strokeDasharray={`${Math.max(0, len - 1.5)} ${c}`} strokeDashoffset={-off} />
            );
            off += len;
            return el;
          })}
        </svg>
        {center && <div className="absolute inset-0 flex flex-col items-center justify-center text-center">{center}</div>}
      </div>
      <ul className="space-y-1 min-w-0 flex-1">
        {slices.map((s) => (
          <li key={s.label} className="flex items-center justify-between gap-2 text-xs">
            <span className="flex items-center gap-1.5 min-w-0 text-soft"><i className="inline-block w-2 h-2 rounded-sm shrink-0" style={{ background: s.color }} /><span className="truncate">{s.label}</span></span>
            <span className="num text-mute">{nf.format(s.value)}{total > 0 && <span className="text-faint ml-1.5">{Math.round((s.value / total) * 100)}%</span>}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

/** Weekday x hour activity heatmap (UTC). */
export function Heatmap({ matrix }) {
  const max = Math.max(1, ...matrix.flat());
  const order = [1, 2, 3, 4, 5, 6, 0];
  return (
    <div>
      <div className="grid gap-[3px]" style={{ gridTemplateColumns: 'auto repeat(24, minmax(0, 1fr))' }}>
        <span />
        {Array.from({ length: 24 }, (_, h) => (
          <span key={h} className="text-[9px] text-faint text-center">{h % 3 === 0 ? String(h).padStart(2, '0') : ''}</span>
        ))}
        {order.map((d) => (
          <FragmentRow key={d} label={DAYS[d]} row={matrix[d]} max={max} />
        ))}
      </div>
      <p className="text-[11px] text-faint mt-2">UTC. Darker = quieter, brighter = busier.</p>
    </div>
  );
}

function FragmentRow({ label, row, max }) {
  return (
    <>
      <span className="text-[10px] text-mute pr-1.5 self-center">{label}</span>
      {row.map((v, h) => (
        <span
          key={h}
          title={`${label} ${String(h).padStart(2, '0')}:00 - ${nf.format(v)} events`}
          className="aspect-square rounded-[3px] min-h-[10px]"
          style={{ background: v ? `color-mix(in srgb, var(--color-accent) ${Math.round(14 + (v / max) * 80)}%, var(--color-panel2))` : 'var(--color-panel2)' }}
        />
      ))}
    </>
  );
}

export function Funnel({ steps }) {
  const top = Math.max(1, steps[0]?.value || 1);
  return (
    <ol className="space-y-2">
      {steps.map((s, i) => {
        const prev = i ? steps[i - 1].value : s.value;
        const conv = prev ? Math.round((s.value / prev) * 100) : 0;
        return (
          <li key={s.label}>
            <div className="flex items-baseline justify-between text-xs mb-1">
              <span className="text-soft">{s.label}</span>
              <span className="num"><b className="text-ink font-semibold">{nf.format(s.value)}</b>{i > 0 && <span className="text-faint ml-2">{conv}% of prev.</span>}</span>
            </div>
            <div className="h-2 rounded-full bg-panel2 overflow-hidden">
              <div className="h-full rounded-full transition-all" style={{ width: `${Math.max(s.value ? 2 : 0, (s.value / top) * 100)}%`, background: s.color }} />
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function MiniBars({ items, color = 'var(--color-accent)', height = 70 }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="flex items-end gap-2" style={{ height: height + 18 }}>
      {items.map((i) => (
        <div key={i.label} className="flex-1 flex flex-col items-center justify-end gap-1 min-w-0" title={`${i.label}: ${nf.format(i.value)}`}>
          <div className="w-full rounded-t-md" style={{ height: Math.max(2, (i.value / max) * height), background: color, opacity: 0.85 }} />
          <span className="text-[10px] text-mute truncate">{i.label}</span>
        </div>
      ))}
    </div>
  );
}
