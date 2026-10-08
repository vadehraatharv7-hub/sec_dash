import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import ProvisionHoneypot from './components/ProvisionHoneypot';
import AccessControl from './components/AccessControl';
import TopIPs from './components/TopIPs';
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
  fetchTopIPs, 
  fetchEvents, 
  fetchSessions, 
  fetchMalwareFiles,
  fetchSensors, 
  createAttackStream 
} from './utils/api';

import { 
  Terminal, 
  CheckCircle2
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
  const [topIPs, setTopIPs] = useState([]);
  const [commands, setCommands] = useState([]);
  const [events, setEvents] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [malwareFiles, setMalwareFiles] = useState([]);
  const [sensors, setSensors] = useState([]);
  const [selectedSensor, setSelectedSensor] = useState('all');

  // Fetch events when sensor changes
  useEffect(() => {
    fetchEvents({ limit: 80, sensor: selectedSensor === 'all' ? '' : selectedSensor })
      .then(res => setEvents(res || []))
      .catch(e => console.error("Failed to fetch events:", e));
  }, [selectedSensor]);

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
      fetchSensors().then(sen => setSensors(sen || [])).catch(() => {});
      const [
        overviewData,
        timelineData,
        countryData,
        credData,
        ipData,
        cmdData,
                sessionData,
        malwareData,
      ] = await Promise.allSettled([
        fetchOverviewStats(),
        fetchTimeline(24),
        fetchTopCountries(15),
        fetchTopCredentials(25),
        fetchTopIPs(7),
        fetchTopCommands(20),
        fetchSessions(40),
        fetchMalwareFiles(40),
        fetchSensors(),
      ]);

      if (overviewData.status === 'fulfilled') setStats(overviewData.value);
      if (timelineData.status === 'fulfilled') setTimeline(timelineData.value || []);
      if (countryData.status === 'fulfilled') setCountries(countryData.value || []);
      if (credData.status === 'fulfilled') setCredentials(credData.value || []);
      if (ipData && ipData.status === 'fulfilled') setTopIPs(ipData.value || []);
      if (cmdData && cmdData.status === 'fulfilled') setCommands(cmdData.value || []);
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
    }, 30000);

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
              <span>{sensors.length > 0 ? `${sensors.length} ACTIVE SENSOR${sensors.length > 1 ? 'S' : ''}` : 'MULTI-SENSOR HONEYPOT ACTIVE'}</span>
            </div>
            {sensors.length > 0 && sensors.map(s => (
                <span key={s.sensor_id} className="ml-2 px-1.5 py-0.5 bg-slate-800 rounded text-cyan-400 border border-slate-700 text-[10px]">
                   {s.sensor_id} ({s.event_count})
                </span>
            ))}
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

            {/* Live Terminal & Top IPs */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Live Terminal stream preview */}
              <div className="lg:col-span-2">
                <TerminalStream events={events.slice(0, 30)} sensors={sensors} selectedSensor={selectedSensor} onSelectSensor={setSelectedSensor} />
              </div>

              {/* Right 1 Col: Recurrent Threat Actors */}
              <div className="lg:col-span-1">
                <TopIPs ips={topIPs} onSelectIP={setSelectedIP} />
              </div>
            </div>
          </div>
        )}

        {/* 1. The Real-Time Terminal Stream (WebSockets) */}
        {activeTab === 'terminal' && (
          <TerminalStream events={events} sensors={sensors} selectedSensor={selectedSensor} onSelectSensor={setSelectedSensor} />
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

        {/* Access Control (Ban/Whitelist) */}
        {activeTab === 'access' && (
          <AccessControl />
        )}

        {/* Grafana Alloy Pipeline Guide */}
        {/* Remote Honeypot Provisioning */}
        {activeTab === 'provision' && (
          <ProvisionHoneypot />
        )}

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
            <span className="text-slate-300 font-bold">SecDash Multi-Sensor SOC</span>
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
