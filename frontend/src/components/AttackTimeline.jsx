import React, { useState } from 'react';
import { Clock, Shield, Flame } from 'lucide-react';

export default function AttackTimeline({ timeline = [] }) {
  const [hoverIndex, setHoverIndex] = useState(null);

  if (!timeline || timeline.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center rounded-xl bg-slate-900/60 border border-slate-800 p-6">
        <p className="text-sm font-mono text-slate-500">Gathering timeline telemetry...</p>
      </div>
    );
  }

  // Find max value for scaling
  const maxVal = Math.max(...timeline.map((d) => d.total), 10);
  const chartHeight = 180;
  const chartWidth = 700;
  const paddingBottom = 25;
  const paddingTop = 15;
  const usableHeight = chartHeight - paddingBottom - paddingTop;

  // Generate SVG points
  const points = timeline.map((d, i) => {
    const x = (i / Math.max(timeline.length - 1, 1)) * (chartWidth - 40) + 20;
    const y = chartHeight - paddingBottom - (d.total / maxVal) * usableHeight;
    const sshY = chartHeight - paddingBottom - (d.ssh / maxVal) * usableHeight;
    const telnetY = chartHeight - paddingBottom - (d.telnet / maxVal) * usableHeight;
    return { x, y, sshY, telnetY, d };
  });

  const pathD = points.length > 0
    ? `M ${points[0].x} ${points[0].y} ` +
      points.slice(1).map((p) => `L ${p.x} ${p.y}`).join(' ')
    : '';

  const areaD = points.length > 0
    ? `${pathD} L ${points[points.length - 1].x} ${chartHeight - paddingBottom} L ${points[0].x} ${chartHeight - paddingBottom} Z`
    : '';

  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-xl backdrop-blur-sm">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 text-cyan-400" />
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
            ATTACK VELOCITY TIMELINE (24H)
          </h2>
        </div>

        <div className="flex items-center gap-4 text-[11px] font-mono">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            <span className="text-slate-300">Total Attacks</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            <span className="text-slate-400">SSH (22)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-amber-400" />
            <span className="text-slate-400">Telnet (23)</span>
          </div>
        </div>
      </div>

      <div className="relative w-full overflow-hidden">
        <svg
          viewBox={`0 0 ${chartWidth} ${chartHeight}`}
          className="w-full h-48 overflow-visible"
          preserveAspectRatio="none"
        >
          <defs>
            <linearGradient id="cyberArea" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.45" />
              <stop offset="85%" stopColor="#06b6d4" stopOpacity="0.02" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
            </linearGradient>
            <linearGradient id="cyberLine" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#06b6d4" />
              <stop offset="100%" stopColor="#38bdf8" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {[0, 0.25, 0.5, 0.75, 1].map((ratio, idx) => {
            const y = chartHeight - paddingBottom - ratio * usableHeight;
            return (
              <g key={idx}>
                <line
                  x1="20"
                  y1={y}
                  x2={chartWidth - 20}
                  y2={y}
                  stroke="#1e293b"
                  strokeDasharray="4 4"
                  strokeWidth="1"
                />
                <text
                  x="15"
                  y={y + 3}
                  fill="#64748b"
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor="end"
                >
                  {Math.round(ratio * maxVal)}
                </text>
              </g>
            );
          })}

          {/* Area fill */}
          {areaD && <path d={areaD} fill="url(#cyberArea)" />}

          {/* Main Total Line */}
          {pathD && (
            <path
              d={pathD}
              fill="none"
              stroke="url(#cyberLine)"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}

          {/* Points & Hover detectors */}
          {points.map((p, idx) => (
            <g key={idx} onMouseEnter={() => setHoverIndex(idx)} onMouseLeave={() => setHoverIndex(null)}>
              <circle
                cx={p.x}
                cy={p.y}
                r={hoverIndex === idx ? '6' : '3'}
                className="fill-cyan-400 stroke-slate-950 stroke-2 cursor-pointer transition-all"
              />
              {/* Vertical crosshair on hover */}
              {hoverIndex === idx && (
                <line
                  x1={p.x}
                  y1={paddingTop}
                  x2={p.x}
                  y2={chartHeight - paddingBottom}
                  stroke="#38bdf8"
                  strokeWidth="1"
                  strokeDasharray="2 2"
                />
              )}
            </g>
          ))}

          {/* X Axis Labels */}
          {points.filter((_, idx) => idx % Math.ceil(points.length / 6) === 0).map((p, idx) => {
            const timeLabel = p.d.time_bucket ? p.d.time_bucket.split(' ')[1] || p.d.time_bucket : '';
            return (
              <text
                key={idx}
                x={p.x}
                y={chartHeight - 6}
                fill="#64748b"
                fontSize="9"
                fontFamily="monospace"
                textAnchor="middle"
              >
                {timeLabel}
              </text>
            );
          })}
        </svg>

        {/* Hover Tooltip Popup */}
        {hoverIndex !== null && points[hoverIndex] && (
          <div
            className="absolute top-2 pointer-events-none rounded-lg bg-slate-950/95 border border-cyan-500/40 p-2 text-xs font-mono shadow-xl shadow-cyan-500/10 z-20"
            style={{
              left: `${Math.min(Math.max(10, (points[hoverIndex].x / chartWidth) * 100), 80)}%`,
            }}
          >
            <div className="text-[10px] text-slate-400 mb-1 border-b border-slate-800 pb-1">
              Time: {points[hoverIndex].d.time_bucket}
            </div>
            <div className="flex justify-between gap-3 text-cyan-300 font-bold">
              <span>Total Attacks:</span>
              <span>{points[hoverIndex].d.total}</span>
            </div>
            <div className="flex justify-between gap-3 text-emerald-400 text-[11px]">
              <span>SSH (22):</span>
              <span>{points[hoverIndex].d.ssh}</span>
            </div>
            <div className="flex justify-between gap-3 text-amber-400 text-[11px]">
              <span>Telnet (23):</span>
              <span>{points[hoverIndex].d.telnet}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
