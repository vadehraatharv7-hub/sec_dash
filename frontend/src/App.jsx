import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import VelocityMetrics from './components/VelocityMetrics';
import AttackMap from './components/AttackMap';
import AttackTimeline from './components/AttackTimeline';
import TerminalStream from './components/TerminalStream';
import CredentialWall from './components/CredentialWall';
import SessionsView from './components/SessionsView';
import LootView from './components/LootView';
import BotnetView from './components/BotnetView';
import AlertsView from './components/AlertsView';
import AlloyGuideView from './components/AlloyGuideView';
import ThreatProfileModal from './components/ThreatProfileModal';

import { 
  fetchOverviewStats, 
  fetchTimeline, 
  fetchTopCountries, 
  fetchTopCredentials, 
  fetchTopCommands, 
  fetchEvents, 
  fetchSessions, 
  fetchMalwareFiles, 
  createAttackStream 
} from './utils/api';

import { 
  ShieldCheck, 
  Terminal, 
  Server, 
  CheckCircle2, 
  Activity,
  Cpu
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [wsConnected, setWsConnected] = useState(false);
  const [selectedIP, setSelectedIP] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [installPrompt, setInstallPrompt] = useState(null);

  // Telemetry state
  const [stats, setStats] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [countries, setCountries] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [commands, setCommands] = useState([]);
  const [events, setEvents] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [malwareFiles, setMalwareFiles] = useState([]);

  // PWA Install Prompt Listener
  useEffect(() => {
    const handleBeforeInstall = (e) => {
      e.preventDefault();
      setInstallPrompt(e);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstall);
    return () => window.removeEventListener('beforeinstallprompt', handleBeforeInstall);
  }, []);

  const handleInstallPWA = async () => {
    if (!installPrompt) return;
    installPrompt.prompt();
    const { outcome } = await installPrompt.userChoice;
    if (outcome === 'accepted') {
      setInstallPrompt(null);
    }
  };

  // Load telemetry data from Go backend
  const loadAllData = async () => {
    try {
      const [
        overviewData,
        timelineData,
        countryData,
        credData,
        cmdData,
        eventData,
        sessionData,
        malwareData,
      ] = await Promise.allSettled([
        fetchOverviewStats(),
        fetchTimeline(24),
        fetchTopCountries(15),
        fetchTopCredentials(25),
        fetchTopCommands(20),
        fetchEvents({ limit: 80 }),
        fetchSessions(40),
        fetchMalwareFiles(40),
      ]);

      if (overviewData.status === 'fulfilled') setStats(overviewData.value);
      if (timelineData.status === 'fulfilled') setTimeline(timelineData.value || []);
      if (countryData.status === 'fulfilled') setCountries(countryData.value || []);
      if (credData.status === 'fulfilled') setCredentials(credData.value || []);
      if (cmdData.status === 'fulfilled') setCommands(cmdData.value || []);
      if (eventData.status === 'fulfilled') setEvents(eventData.value || []);
      if (sessionData.status === 'fulfilled') setSessions(sessionData.value || []);
      if (malwareData.status === 'fulfilled') setMalwareFiles(malwareData.value || []);
    } catch (err) {
      console.error('Failed to load telemetry:', err);
    }
  };

  useEffect(() => {
    loadAllData();

    // WebSocket attack stream
    const stream = createAttackStream(
      (newEvent) => {
        setEvents((prev) => [newEvent, ...prev.slice(0, 149)]);

        // Live KPI increment
        setStats((prev) => {
          if (!prev) return prev;
          const next = { ...prev, total_events: (prev.total_events || 0) + 1 };
          if (newEvent.eventid === 'cowrie.login.failed') {
            next.failed_logins = (next.failed_logins || 0) + 1;
          } else if (newEvent.eventid === 'cowrie.login.success') {
            next.successful_logins = (next.successful_logins || 0) + 1;
          } else if (newEvent.eventid === 'cowrie.command.input') {
            next.commands_executed = (next.commands_executed || 0) + 1;
          } else if (newEvent.eventid === 'cowrie.session.file_download') {
            next.files_captured = (next.files_captured || 0) + 1;
          }
          return next;
        });
      },
      (connected) => {
        setWsConnected(connected);
      }
    );

    // Refresh metrics periodically
    const interval = setInterval(() => {
      fetchOverviewStats().then((s) => setStats(s)).catch(() => {});
      fetchTimeline(24).then((t) => setTimeline(t || [])).catch(() => {});
      fetchTopCountries(15).then((c) => setCountries(c || [])).catch(() => {});
      fetchTopCredentials(25).then((cr) => setCredentials(cr || [])).catch(() => {});
      fetchSessions(40).then((se) => setSessions(se || [])).catch(() => {});
      fetchMalwareFiles(40).then((mf) => setMalwareFiles(mf || [])).catch(() => {});
    }, 8000);

    return () => {
      stream.close();
      clearInterval(interval);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#080d1a] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Top Header Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        wsConnected={wsConnected}
        onSearchIP={setSelectedIP}
        searchTerm={searchTerm}
        setSearchTerm={setSearchTerm}
        installPrompt={installPrompt}
        onInstallPWA={handleInstallPWA}
      />

      {/* Main Content Viewport */}
      <main className="flex-1 px-4 sm:px-6 py-6 max-w-7xl mx-auto w-full space-y-6">
        {/* Status Line */}
        <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 rounded-lg bg-[#0b1120] border border-slate-800 text-xs font-mono">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 text-emerald-400 font-bold">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>COWRIE HONEYPOT SENSOR ACTIVE</span>
            </div>
            <span className="text-slate-700">|</span>
            <span className="text-slate-400">
              Pipeline: <strong className="text-slate-200">Alloy &rarr; Golang WAL Engine</strong>
            </span>
            <span className="text-slate-700">|</span>
            <span className="text-slate-400">
              Stream: <strong className="text-cyan-400">RFC-5424 Logstream :8080/ws</strong>
            </span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setActiveTab('alloy')}
              className="text-cyan-400 hover:text-cyan-300 font-bold underline"
            >
              Alloy Guide &rarr;
            </button>
          </div>
        </div>

        {/* Dynamic Views */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* 3. Attack Velocity & Threat Counters */}
            <VelocityMetrics stats={stats} />

            {/* 5. IP Geolocation Heatmap / Radar */}
            <AttackMap
              countries={countries}
              recentAttacks={events.slice(0, 15)}
              onSelectIP={setSelectedIP}
            />

            {/* Attack Velocity Timeline */}
            <AttackTimeline timeline={timeline} />

            {/* Intercepted Shell Sandbox Commands */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Live Terminal stream preview */}
              <div className="lg:col-span-2">
                <TerminalStream events={events.slice(0, 30)} />
              </div>

              {/* Right 1 Col: Top Sandbox Commands */}
              <div className="rounded-lg bg-[#0b1120] border border-slate-800 p-4 font-mono text-xs flex flex-col h-[650px]">
                <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-rose-400" />
                    <span className="font-bold text-slate-200 uppercase">INTERCEPTED COMMANDS</span>
                  </div>
                  <span className="text-[10px] text-slate-500">FREQUENCY</span>
                </div>

                <div className="flex-1 overflow-y-auto space-y-2 pr-1">
                  {commands.map((cmd, i) => (
                    <div
                      key={i}
                      className="p-2 rounded bg-slate-950/80 border border-slate-850 flex items-center justify-between gap-2 hover:border-slate-700 transition-colors"
                    >
                      <div className="flex items-center gap-1.5 truncate">
                        <span className="text-rose-400 font-bold select-none">#</span>
                        <span className="text-slate-200 font-bold truncate">{cmd.command}</span>
                      </div>
                      <span className="text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded text-[10px] font-bold border border-slate-800 shrink-0">
                        {cmd.count}x
                      </span>
                    </div>
                  ))}

                  {commands.length === 0 && (
                    <div className="py-16 text-center text-slate-500 italic">
                      Waiting for command execution telemetry...
                    </div>
                  )}
                </div>

                <div className="pt-3 border-t border-slate-800 text-[10px] text-slate-500">
                  Sandbox: Fake Debian GNU/Linux 11 (Bullseye)
                </div>
              </div>
            </div>
          </div>
        )}

        {/* 1. The Real-Time Terminal Stream (WebSockets) */}
        {activeTab === 'terminal' && (
          <TerminalStream events={events} />
        )}

        {/* 2. The Credential Harvesting Wall */}
        {activeTab === 'credentials' && (
          <CredentialWall credentials={credentials} />
        )}

        {/* 6. LLM-Powered Threat Profiling & 8. The Kill Chain Session Timeline */}
        {activeTab === 'sessions' && (
          <SessionsView sessions={sessions} onSelectIP={setSelectedIP} />
        )}

        {/* 4. Payload Extraction (The Loot Tab) */}
        {activeTab === 'loot' && (
          <LootView malwareFiles={malwareFiles} onSelectIP={setSelectedIP} />
        )}

        {/* 7. Botnet Fingerprinting (HASSH & Client Strings) */}
        {activeTab === 'botnet' && (
          <BotnetView />
        )}

        {/* 9. Custom Webhook Alerting Engine */}
        {activeTab === 'alerts' && (
          <AlertsView />
        )}

        {/* Grafana Alloy Pipeline Guide */}
        {activeTab === 'alloy' && (
          <AlloyGuideView />
        )}
      </main>

      {/* Adversary IP Forensics Modal */}
      {selectedIP && (
        <ThreatProfileModal
          ip={selectedIP}
          onClose={() => setSelectedIP(null)}
        />
      )}

      {/* Enterprise Footer */}
      <footer className="border-t border-slate-800/80 py-3.5 px-6 text-xs font-mono text-slate-500 bg-[#070b16]">
        <div className="flex flex-wrap items-center justify-between gap-2 max-w-7xl mx-auto">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyan-400" />
            <span className="text-slate-300 font-bold">SecDash Cowrie SOC</span>
            <span>&bull;</span>
            <span>Production Engine (Golang 1.27.1)</span>
          </div>

          <div className="flex items-center gap-3">
            <span>Storage: SQLite WAL</span>
            <span>&bull;</span>
            <span>Mode: <strong className="text-emerald-400">PRODUCTION</strong></span>
          </div>
        </div>
      </footer>
    </div>
  );
}
