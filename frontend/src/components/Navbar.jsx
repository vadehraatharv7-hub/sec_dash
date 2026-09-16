import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Terminal, 
  KeyRound, 
  TerminalSquare, 
  Bug, 
  Fingerprint, 
  Bell, 
  Cpu, 
  Search,
  Download,
  CheckCircle2
} from 'lucide-react';

export default function Navbar({ 
  activeTab, 
  setActiveTab, 
  wsConnected, 
  onSearchIP,
  searchTerm,
  setSearchTerm,
  installPrompt,
  onInstallPWA
}) {
  const tabs = [
    { id: 'overview', label: 'Overview & Radar', icon: Activity },
    { id: 'terminal', label: 'Live Terminal Stream', icon: Terminal },
    { id: 'credentials', label: 'Harvested Credentials', icon: KeyRound },
    { id: 'sessions', label: 'Adversary Sessions & AI', icon: TerminalSquare },
    { id: 'loot', label: 'Payload Loot', icon: Bug },
    { id: 'botnet', label: 'Botnet Fingerprints', icon: Fingerprint },
    { id: 'alerts', label: 'Webhook Alerts', icon: Bell },
    { id: 'alloy', label: 'Alloy Pipeline', icon: Cpu },
  ];

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    if (searchTerm.trim()) {
      onSearchIP(searchTerm.trim());
    }
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-[#080d1a]/95 backdrop-blur-md">
      <div className="flex h-14 items-center justify-between px-4 sm:px-6">
        {/* Brand & Honeypot Status */}
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <ShieldAlert className="h-4 w-4" />
          </div>

          <div className="flex items-center gap-2">
            <span className="text-sm font-bold tracking-wider text-slate-100 uppercase font-mono">
              SEC<span className="text-cyan-400">DASH</span>
            </span>
            <span className="text-slate-600 font-mono">/</span>
            <span className="text-xs font-mono text-slate-400">COWRIE THREAT INTEL</span>
          </div>
        </div>

        {/* Global IP Forensics Search */}
        <form onSubmit={handleSearchSubmit} className="hidden md:flex items-center relative max-w-sm w-full mx-4">
          <Search className="absolute left-3 h-3.5 w-3.5 text-slate-500" />
          <input
            type="text"
            placeholder="Search IP threat profile (e.g. 185.220...)"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full rounded bg-slate-950 border border-slate-800 pl-8 pr-3 py-1 text-xs text-slate-200 placeholder-slate-500 focus:border-cyan-500 focus:outline-none font-mono"
          />
        </form>

        {/* Right Action Controls */}
        <div className="flex items-center gap-3">
          {/* Socket status */}
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-950 border border-slate-850 text-[10px] font-mono">
            <span className={`h-1.5 w-1.5 rounded-full ${wsConnected ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'}`} />
            <span className="text-slate-400">{wsConnected ? 'SOCKET: CONNECTED' : 'SOCKET: OFFLINE'}</span>
          </div>

          {/* Production Mode Indicator */}
          <div className="hidden sm:flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono font-bold">
            <CheckCircle2 className="h-3 w-3" />
            <span>PRODUCTION</span>
          </div>

          {/* Install PWA Button (if browser prompt available) */}
          {installPrompt && (
            <button
              onClick={onInstallPWA}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold bg-cyan-600 hover:bg-cyan-500 text-slate-950 transition-all shadow-sm"
              title="Install SecDash as Desktop / Mobile PWA App"
            >
              <Download className="h-3 w-3" />
              <span>Install App</span>
            </button>
          )}
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav className="flex overflow-x-auto px-4 sm:px-6 border-t border-slate-850 bg-[#070b16]">
        <div className="flex space-x-1 py-1">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono whitespace-nowrap transition-colors border ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border-transparent'
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </nav>
    </header>
  );
}
