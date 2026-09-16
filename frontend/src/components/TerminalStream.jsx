import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Pause, Play, Trash2, Download, Search, Check, Copy } from 'lucide-react';

export default function TerminalStream({ events = [] }) {
  const [autoScroll, setAutoScroll] = useState(true);
  const [grepQuery, setGrepQuery] = useState('');
  const [logLevel, setLogLevel] = useState('all');
  const [copiedIndex, setCopiedIndex] = useState(null);
  const scrollContainerRef = useRef(null);

  useEffect(() => {
    if (autoScroll && scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight;
    }
  }, [events, autoScroll]);

  const filteredEvents = events.filter((ev) => {
    if (logLevel !== 'all' && ev.severity !== logLevel) return false;
    if (grepQuery.trim()) {
      const q = grepQuery.toLowerCase();
      const raw = `${ev.timestamp} ${ev.eventid} ${ev.src_ip} ${ev.username} ${ev.password} ${ev.input} ${ev.description}`.toLowerCase();
      if (!raw.includes(q)) return false;
    }
    return true;
  });

  const handleExportLogs = () => {
    const lines = filteredEvents.map((ev) => {
      const ts = new Date(ev.timestamp).toISOString();
      return `${ts} [${ev.severity.toUpperCase()}] [${ev.eventid}] src=${ev.src_ip}:${ev.src_port} dst=${ev.dst_port} user="${ev.username || ''}" pass="${ev.password || ''}" cmd="${ev.input || ''}" desc="${ev.description}"`;
    });
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cowrie_audit_${Date.now()}.log`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyLine = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  return (
    <div className="rounded-lg bg-[#070b14] border border-slate-800 shadow-xl overflow-hidden flex flex-col h-[650px] font-mono">
      {/* Terminal Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5 bg-[#0b1120] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="flex space-x-1.5 mr-2">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80 inline-block" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80 inline-block" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80 inline-block" />
          </div>
          <Terminal className="h-4 w-4 text-cyan-400" />
          <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
            RAW AUDIT TERMINAL STREAM &bull; WEBSOCKET FEED
          </span>
          <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20 animate-pulse">
            TAILING :8080/ws
          </span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2 text-xs">
          {/* Grep */}
          <div className="relative">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="grep query..."
              value={grepQuery}
              onChange={(e) => setGrepQuery(e.target.value)}
              className="rounded bg-slate-950 border border-slate-800 pl-7 pr-2.5 py-1 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Level Filter */}
          <select
            value={logLevel}
            onChange={(e) => setLogLevel(e.target.value)}
            className="rounded bg-slate-950 border border-slate-800 px-2.5 py-1 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">ALL LEVELS</option>
            <option value="critical">CRITICAL ONLY</option>
            <option value="high">HIGH</option>
            <option value="warning">WARNING</option>
            <option value="info">INFO</option>
          </select>

          {/* Autoscroll Toggle */}
          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`flex items-center gap-1 px-2.5 py-1 rounded border transition-colors ${
              autoScroll
                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            }`}
          >
            {autoScroll ? <Pause className="h-3 w-3" /> : <Play className="h-3 w-3" />}
            <span>{autoScroll ? 'Scroll: Locked' : 'Scroll: Free'}</span>
          </button>

          {/* Export Log */}
          <button
            onClick={handleExportLogs}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300 hover:text-white"
            title="Download audit log file"
          >
            <Download className="h-3 w-3" />
            <span>Export</span>
          </button>
        </div>
      </div>

      {/* Terminal Output Window */}
      <div 
        ref={scrollContainerRef}
        className="flex-1 p-4 overflow-y-auto text-[11px] leading-relaxed space-y-1 bg-[#060913]"
      >
        <div className="text-slate-600 pb-2 border-b border-slate-900 mb-2">
          # SecDash Honeypot Live Audit Log Stream initialized. Ready for incoming Alloy / Cowrie events.
        </div>

        {filteredEvents.map((ev, idx) => {
          const ts = new Date(ev.timestamp).toLocaleTimeString([], { hour12: false }) + '.' + new Date(ev.timestamp).getMilliseconds().toString().padStart(3, '0');
          const isCopied = copiedIndex === idx;

          let sevColor = 'text-cyan-400';
          if (ev.severity === 'critical') sevColor = 'text-rose-400 font-bold';
          else if (ev.severity === 'high') sevColor = 'text-orange-400 font-bold';
          else if (ev.severity === 'warning') sevColor = 'text-amber-400';

          const rawLine = `${ts} [${ev.severity.toUpperCase()}] [${ev.eventid}] src=${ev.src_ip}:${ev.src_port} dst=${ev.dst_port} user="${ev.username || ''}" pass="${ev.password || ''}" cmd="${ev.input || ''}" geo=${ev.geo?.country_code || '??'}`;

          return (
            <div
              key={ev.id || idx}
              className="group flex items-start justify-between gap-3 hover:bg-slate-900/60 p-1 rounded transition-colors"
            >
              <div className="break-all font-mono">
                <span className="text-slate-500 mr-2">{ts}</span>
                <span className={`${sevColor} mr-2`}>[{ev.severity.toUpperCase()}]</span>
                <span className="text-slate-300 mr-2">[{ev.eventid}]</span>
                <span className="text-slate-400">src=</span>
                <span className="text-cyan-300 font-semibold">{ev.src_ip}:{ev.src_port}</span>{' '}
                <span className="text-slate-400">dst=</span>
                <span className="text-slate-200">{ev.dst_port || 22}</span>{' '}

                {ev.username && (
                  <>
                    <span className="text-slate-400">user=</span>
                    <span className="text-amber-300 font-bold">"{ev.username}"</span>{' '}
                  </>
                )}

                {ev.password && (
                  <>
                    <span className="text-slate-400">pass=</span>
                    <span className="text-rose-300 font-bold">"{ev.password}"</span>{' '}
                  </>
                )}

                {ev.input && (
                  <>
                    <span className="text-slate-400">cmd=</span>
                    <span className="text-emerald-300 font-bold">"{ev.input}"</span>{' '}
                  </>
                )}

                {ev.geo?.country_code && (
                  <span className="text-slate-500">
                    geo=<strong className="text-slate-400">{ev.geo.country_code}</strong>
                  </span>
                )}
              </div>

              <button
                onClick={() => handleCopyLine(rawLine, idx)}
                className="opacity-0 group-hover:opacity-100 transition-opacity p-1 text-slate-500 hover:text-cyan-300 shrink-0"
                title="Copy log line"
              >
                {isCopied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              </button>
            </div>
          );
        })}

        {filteredEvents.length === 0 && (
          <div className="py-20 text-center text-slate-600">
            No audit records matching query. Waiting for socket events...
          </div>
        )}
      </div>

      {/* Terminal Footer */}
      <div className="px-4 py-2 bg-[#090e1b] border-t border-slate-800 flex justify-between items-center text-[10px] text-slate-500">
        <div>
          Buffer: <strong className="text-slate-300">{filteredEvents.length}</strong> lines displayed
        </div>
        <div className="flex items-center gap-2">
          <span>Encoding: UTF-8</span>
          <span>&bull;</span>
          <span>Protocol: RFC-5424 Logstream</span>
        </div>
      </div>
    </div>
  );
}
