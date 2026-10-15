import { useEffect, useMemo, useState } from 'react';
import {
  Bell, Bug, Crosshair, Globe, Grid3x3, KeyRound, LayoutDashboard, Lock, Menu, Network, Radio,
  Search, Server, ShieldBan, Terminal, TerminalSquare, Wifi, WifiOff,
} from 'lucide-react';
import { FilterProvider, go, useApi, useFilters, useLive, useRoute } from './lib/hooks';
import { getToken, setToken } from './lib/api';
import { UiCtx } from './lib/ui';
import { RANGES } from './lib/theme';
import { Segmented, Select, cx } from './ui/primitives';
import AttackerDrawer from './views/AttackerDrawer';
import Overview from './views/Overview';
import LiveFeed from './views/LiveFeed';
import ThreatMap from './views/ThreatMap';
import Attackers from './views/Attackers';
import Sessions from './views/Sessions';
import SessionDetail from './views/SessionDetail';
import Campaigns from './views/Campaigns';
import Credentials from './views/Credentials';
import Commands from './views/Commands';
import Malware from './views/Malware';
import Mitre from './views/Mitre';
import Alerts from './views/Alerts';
import Blocklist from './views/Blocklist';
import Sensors from './views/Sensors';


const NAV = [
  { group: 'Monitor', items: [
    { id: '', label: 'Command Center', icon: LayoutDashboard },
    { id: 'live', label: 'Live Feed', icon: Radio },
    { id: 'map', label: 'Threat Map', icon: Globe },
  ] },
  { group: 'Investigate', items: [
    { id: 'attackers', label: 'Attackers', icon: Crosshair },
    { id: 'sessions', label: 'Sessions', icon: TerminalSquare },
    { id: 'campaigns', label: 'Campaigns', icon: Network },
    { id: 'credentials', label: 'Credentials', icon: KeyRound },
    { id: 'commands', label: 'Commands', icon: Terminal },
    { id: 'malware', label: 'Malware & IOCs', icon: Bug },
  ] },
  { group: 'Detect & Respond', items: [
    { id: 'mitre', label: 'ATT&CK Coverage', icon: Grid3x3 },
    { id: 'alerts', label: 'Alerts', icon: Bell },
    { id: 'blocklist', label: 'Blocklist', icon: ShieldBan },
  ] },
  { group: 'Infrastructure', items: [
    { id: 'sensors', label: 'Sensors', icon: Server },
  ] },
];

const PAGES = {
  '': Overview, live: LiveFeed, map: ThreatMap, attackers: Attackers, sessions: Sessions, campaigns: Campaigns,
  credentials: Credentials, commands: Commands, malware: Malware, mitre: Mitre, alerts: Alerts, blocklist: Blocklist,
  sensors: Sensors,
};

function Sidebar({ page, onNavigate }) {
  return (
    <nav className="flex flex-col h-full" aria-label="Main">
      <div className="flex items-center gap-2.5 px-4 h-14 shrink-0 border-b border-line">
        <img src="/icon.svg" alt="" className="h-7 w-7 rounded-md" />
        <div className="leading-tight">
          <div className="font-semibold tracking-tight">SecDash</div>
          <div className="text-[10px] uppercase tracking-[0.14em] text-faint">Honeypot analytics</div>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto px-2.5 py-3 space-y-4">
        {NAV.map((g) => (
          <div key={g.group}>
            <div className="px-2 pb-1 text-[10px] uppercase tracking-[0.14em] text-faint">{g.group}</div>
            {g.items.map((it) => {
              const active = page === it.id;
              const Icon = it.icon;
              return (
                <a
                  key={it.id}
                  href={`#/${it.id}`}
                  onClick={onNavigate}
                  aria-current={active ? 'page' : undefined}
                  className={cx(
                    'flex items-center gap-2.5 rounded-lg px-2.5 h-8 text-[13px] transition-colors',
                    active ? 'bg-raised text-ink font-medium' : 'text-mute hover:text-ink hover:bg-panel2',
                  )}
                >
                  <Icon size={16} className={active ? 'text-accent' : ''} />
                  {it.label}
                </a>
              );
            })}
          </div>
        ))}
      </div>
    </nav>
  );
}

function LiveBadge({ status }) {
  const on = status === 'live';
  return (
    <span
      className={cx('hidden sm:inline-flex items-center gap-1.5 h-8 px-2.5 rounded-lg border text-xs',
        on ? 'border-ok/30 text-ok bg-ok/10' : 'border-line text-mute')}
      title={on ? 'Receiving events in real time' : 'Reconnecting to the live stream'}
    >
      {on ? <Wifi size={13} /> : <WifiOff size={13} />}
      <span className={cx('h-1.5 w-1.5 rounded-full', on ? 'bg-ok live-dot' : 'bg-faint')} />
      {on ? 'Live' : status === 'connecting' ? 'Connecting' : 'Offline'}
    </span>
  );
}

function GlobalSearch({ openIP }) {
  const [q, setQ] = useState('');
  const submit = (e) => {
    e.preventDefault();
    const v = q.trim();
    if (!v) return;
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(v)) openIP(v);
    else if (/^[0-9a-f]{12}$/.test(v)) go(`/sessions/${v}`);
    else go('/live', { q: v });
    setQ('');
  };
  return (
    <form onSubmit={submit} className="relative flex-1 max-w-sm" role="search">
      <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search IP, session, command, hash..."
        aria-label="Global search"
        className="h-8 w-full rounded-lg border border-line bg-panel pl-8 pr-2 text-[13px] placeholder:text-faint hover:border-line2 focus:border-accent/60 focus:outline-none"
      />
    </form>
  );
}

function AuthBanner() {
  const { data } = useApi('/auth', null, { filters: false });
  const [token, setTok] = useState(getToken());
  const [asking, setAsking] = useState(false);
  const [val, setVal] = useState('');
  if (!data?.required) return null;
  const ok = data.ok;
  const save = async (e) => {
    e.preventDefault();
    setToken(val.trim());
    setTok(val.trim());
    setAsking(false);
    window.location.reload();
  };
  if (ok && token) return null;
  return (
    <div className="flex items-center gap-3 border-b border-med/30 bg-med/10 px-4 py-1.5 text-xs text-med">
      <Lock size={13} />
      <span className="flex-1">Read-only mode. Enter the access token to ban IPs and manage alerts.</span>
      {asking ? (
        <form onSubmit={save} className="flex gap-2">
          <input autoFocus type="password" value={val} onChange={(e) => setVal(e.target.value)} placeholder="Access token"
            className="h-6 rounded border border-line2 bg-panel px-2 text-ink" />
          <button className="rounded bg-med px-2 text-[#1a1400] font-medium">Unlock</button>
        </form>
      ) : (
        <button onClick={() => setAsking(true)} className="underline underline-offset-2">Enter token</button>
      )}
    </div>
  );
}

function Shell() {
  const { parts } = useRoute();
  const page = parts[0] || '';
  const { range, setRange, sensor, setSensor } = useFilters();
  const { data: meta } = useApi('/meta', null, { filters: false, interval: 60000 });
  const [open, setOpen] = useState(false);
  const [ip, setIP] = useState(null);
  const status = useLive(() => {});

  const ui = useMemo(() => ({ openIP: setIP, closeIP: () => setIP(null) }), []);
  useEffect(() => { setOpen(false); }, [page]);

  const sensors = [{ id: 'all', label: 'All sensors' }, ...(meta?.sensors || []).map((s) => ({ id: s.id, label: s.id }))];
  const Page = page === 'sessions' && parts[1] ? SessionDetail : PAGES[page] || Overview;

  return (
    <UiCtx.Provider value={ui}>
      <div className="flex h-full">
        <aside className="hidden lg:block w-[220px] shrink-0 border-r border-line bg-panel/40">
          <Sidebar page={page} onNavigate={() => {}} />
        </aside>
        {open && (
          <div className="fixed inset-0 z-40 lg:hidden">
            <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
            <aside className="absolute left-0 top-0 h-full w-[240px] bg-bg border-r border-line2">
              <Sidebar page={page} onNavigate={() => setOpen(false)} />
            </aside>
          </div>
        )}
        <div className="flex-1 min-w-0 flex flex-col">
          <AuthBanner />
          <header className="flex items-center gap-2.5 h-14 shrink-0 border-b border-line px-4 bg-bg/80 backdrop-blur sticky top-0 z-30">
            <button className="lg:hidden text-mute hover:text-ink -ml-1 p-1" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={20} /></button>
            <GlobalSearch openIP={setIP} />
            <div className="flex-1" />
            <Select aria-label="Sensor" value={sensor} onChange={setSensor} options={sensors} className="max-w-[150px]" />
            <div className="hidden md:block"><Segmented value={range} onChange={setRange} options={RANGES} /></div>
            <div className="md:hidden">
              <Select aria-label="Time range" value={range} onChange={setRange} options={RANGES} />
            </div>
            <LiveBadge status={status} />
          </header>
          <main className="flex-1 overflow-y-auto">
            <div className="mx-auto max-w-[1500px] px-4 sm:px-6 py-5">
              <Page route={parts} />
            </div>
          </main>
        </div>
      </div>
      <AttackerDrawer ip={ip} onClose={() => setIP(null)} />
    </UiCtx.Provider>
  );
}

export default function App() {
  return (
    <FilterProvider>
      <Shell />
    </FilterProvider>
  );
}


