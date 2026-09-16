import React, { useState } from 'react';
import { 
  Radio, 
  Pause, 
  Play, 
  Trash2, 
  ShieldAlert, 
  Terminal, 
  Key, 
  FileDown, 
  ChevronDown, 
  ChevronRight, 
  ExternalLink,
  Search
} from 'lucide-react';

export default function LiveFeed({ events = [], onSelectIP }) {
  const [filterType, setFilterType] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [isPaused, setIsPaused] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedId, setExpandedId] = useState(null);

  const filteredEvents = events.filter((ev) => {
    if (filterType !== 'all') {
      if (filterType === 'login' && !ev.eventid.includes('login')) return false;
      if (filterType === 'command' && !ev.eventid.includes('command')) return false;
      if (filterType === 'malware' && !ev.eventid.includes('file_download')) return false;
      if (filterType === 'connect' && !ev.eventid.includes('connect')) return false;
    }
    if (filterSeverity !== 'all' && ev.severity !== filterSeverity) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchIP = ev.src_ip?.toLowerCase().includes(q);
      const matchUser = ev.username?.toLowerCase().includes(q);
      const matchCmd = ev.input?.toLowerCase().includes(q);
      const matchDesc = ev.description?.toLowerCase().includes(q);
      const matchCountry = ev.geo?.country_name?.toLowerCase().includes(q);
      if (!matchIP && !matchUser && !matchCmd && !matchDesc && !matchCountry) return false;
    }
    return true;
  });

  const getSeverityBadge = (sev) => {
    switch (sev) {
      case 'critical':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'high':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'warning':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      default:
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
    }
  };

  const getEventIcon = (eventid) => {
    if (eventid.includes('login')) return <Key className="h-3.5 w-3.5 text-amber-400" />;
    if (eventid.includes('command')) return <Terminal className="h-3.5 w-3.5 text-rose-400" />;
    if (eventid.includes('file_download')) return <FileDown className="h-3.5 w-3.5 text-purple-400" />;
    return <Radio className="h-3.5 w-3.5 text-cyan-400" />;
  };

  return (
    <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-xl backdrop-blur-sm">
      {/* Feed Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800 mb-4">
        <div className="flex items-center gap-2">
          <Radio className="h-4 w-4 text-cyan-400 animate-pulse" />
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
            REAL-TIME HONEYPOT ATTACK FEED
          </h2>
          <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[10px] font-mono text-cyan-300 border border-cyan-500/30">
            {events.length} Buffered
          </span>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Quick Search */}
          <div className="relative">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Filter by IP, command..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="rounded-md bg-slate-950 border border-slate-800 pl-8 pr-2.5 py-1 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none font-mono"
            />
          </div>

          {/* Event Type Filter */}
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="rounded-md bg-slate-950 border border-slate-800 px-2.5 py-1 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none font-mono"
          >
            <option value="all">All Events</option>
            <option value="login">Brute Force Logins</option>
            <option value="command">Shell Commands</option>
            <option value="malware">Malware Downloads</option>
            <option value="connect">Connections</option>
          </select>

          {/* Severity Filter */}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="rounded-md bg-slate-950 border border-slate-800 px-2.5 py-1 text-xs text-slate-300 focus:border-cyan-500 focus:outline-none font-mono"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>

          {/* Pause stream toggle */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono border transition-all ${
              isPaused
                ? 'bg-amber-500/10 border-amber-500/40 text-amber-300'
                : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            {isPaused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>
        </div>
      </div>

      {/* Events Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left font-mono text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase tracking-wider">
              <th className="pb-2 w-6"></th>
              <th className="pb-2">Time</th>
              <th className="pb-2">Severity</th>
              <th className="pb-2">Event</th>
              <th className="pb-2">Attacker IP</th>
              <th className="pb-2">Location</th>
              <th className="pb-2">Payload / Activity Details</th>
              <th className="pb-2 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-850/80">
            {filteredEvents.map((ev, i) => {
              const isExpanded = expandedId === ev.id || (expandedId === null && i === 0 && events.length === 1);
              const formattedTime = new Date(ev.timestamp).toLocaleTimeString([], {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              });

              return (
                <React.Fragment key={ev.id || i}>
                  <tr 
                    onClick={() => setExpandedId(isExpanded ? null : ev.id || i)}
                    className="hover:bg-slate-850/50 cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 pr-1 text-slate-600">
                      {isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                    </td>
                    <td className="py-2.5 text-slate-400 whitespace-nowrap">{formattedTime}</td>
                    <td className="py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold border ${getSeverityBadge(ev.severity)}`}>
                        {ev.severity}
                      </span>
                    </td>
                    <td className="py-2.5 whitespace-nowrap">
                      <div className="flex items-center gap-1.5 text-slate-200">
                        {getEventIcon(ev.eventid)}
                        <span className="font-semibold">{ev.eventid}</span>
                      </div>
                    </td>
                    <td className="py-2.5 whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIP(ev.src_ip);
                        }}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline flex items-center gap-1 font-bold"
                      >
                        <span>{ev.src_ip}</span>
                        <ExternalLink className="h-2.5 w-2.5 opacity-60" />
                      </button>
                    </td>
                    <td className="py-2.5 text-slate-300 whitespace-nowrap">
                      {ev.geo?.country_name ? `${ev.geo.country_name} (${ev.geo.country_code})` : 'Unknown'}
                    </td>
                    <td className="py-2.5 text-slate-300 max-w-md truncate">
                      {ev.description || ev.input || ev.username || 'Event logged'}
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIP(ev.src_ip);
                        }}
                        className="px-2 py-0.5 rounded bg-slate-800 text-[10px] text-cyan-300 hover:bg-slate-700 border border-slate-700 font-mono"
                      >
                        Profile
                      </button>
                    </td>
                  </tr>

                  {/* Expanded Forensics Details */}
                  {isExpanded && (
                    <tr className="bg-slate-950/70">
                      <td colSpan="8" className="p-3 border-y border-slate-800">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase">Connection Details</span>
                            <div className="mt-1 text-slate-300 space-y-0.5">
                              <div>Source Port: <span className="text-slate-100">{ev.src_port || 'N/A'}</span></div>
                              <div>Target Port: <span className="text-slate-100">{ev.dst_port || 22}</span></div>
                              <div>Protocol: <span className="text-slate-100 uppercase">{ev.protocol || 'SSH'}</span></div>
                              <div>Session ID: <span className="text-cyan-400">{ev.session}</span></div>
                            </div>
                          </div>

                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase">Threat Forensics</span>
                            <div className="mt-1 text-slate-300 space-y-0.5">
                              <div>ASN / ISP: <span className="text-slate-100">{ev.geo?.asn || 'N/A'} - {ev.geo?.org || 'N/A'}</span></div>
                              <div>City / Region: <span className="text-slate-100">{ev.geo?.city || 'N/A'}</span></div>
                              {ev.username && <div>Attempted User: <span className="text-amber-400 font-bold">{ev.username}</span></div>}
                              {ev.password && <div>Attempted Pass: <span className="text-amber-400 font-bold">{ev.password}</span></div>}
                              {ev.input && <div>Command Typed: <span className="text-rose-400 font-bold">{ev.input}</span></div>}
                            </div>
                          </div>

                          <div>
                            <span className="text-slate-500 block text-[10px] uppercase">Client Signature</span>
                            <div className="mt-1 text-slate-300 space-y-0.5">
                              <div>Banner: <span className="text-slate-200 break-all">{ev.ssh_version || 'N/A'}</span></div>
                              {ev.sha256 && <div>File SHA256: <span className="text-purple-400 break-all">{ev.sha256}</span></div>}
                              {ev.download_url && <div>Payload URL: <span className="text-purple-400 break-all">{ev.download_url}</span></div>}
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}

            {filteredEvents.length === 0 && (
              <tr>
                <td colSpan="8" className="py-12 text-center text-slate-500 font-mono">
                  No events match the current filter or waiting for attack telemetry.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
