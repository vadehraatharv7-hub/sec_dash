import { useState } from 'react';
import { ChevronDown, Server } from 'lucide-react';
import { useApi, useFilters } from '../lib/hooks';
import { ago, compact, flag } from '../lib/format';
import { KINDS, STATUS } from '../lib/theme';
import { Sparkline } from '../ui/charts';
import { Badge, Card, CopyButton, Empty, ErrorBox, Mono, PageHeader, Skeleton, cx } from '../ui/primitives';

function SensorCard({ s, onPick, active }) {
  const st = STATUS[s.status];
  const kinds = Object.entries(s.kinds).sort((a, b) => b[1] - a[1]).slice(0, 4);
  return (
    <Card className={cx('p-4', active && 'border-accent/50')}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2"><Server size={15} className="text-mute" /><h3 className="text-[14px] font-semibold">{s.id}</h3></div>
          <div className="text-xs text-mute mt-0.5">{s.source === 'snare' ? 'Snare web honeypot (HTTP)' : 'Cowrie SSH/Telnet honeypot'}</div>
        </div>
        <Badge color={st.color}><span className={cx('h-1.5 w-1.5 rounded-full', s.status === 'live' && 'live-dot')} style={{ background: st.color }} />{st.label}</Badge>
      </div>
      <div className="grid grid-cols-3 gap-3 mt-4">
        <div><div className="text-[11px] uppercase tracking-wider text-mute">Events</div><div className="text-lg font-semibold num">{compact(s.events)}</div></div>
        <div><div className="text-[11px] uppercase tracking-wider text-mute">Last 24h</div><div className="text-lg font-semibold num">{compact(s.events_24h)}</div></div>
        <div><div className="text-[11px] uppercase tracking-wider text-mute">Attackers</div><div className="text-lg font-semibold num">{compact(s.attackers)}</div></div>
      </div>
      <div className="mt-3"><Sparkline values={s.spark} width={320} height={44} /></div>
      <div className="text-[11px] text-faint">Hourly volume, last 24 hours</div>
      <div className="mt-3 flex flex-wrap gap-1.5">{kinds.map(([k, n]) => <Badge key={k} color={KINDS[k]?.color}>{KINDS[k]?.label || k} {compact(n)}</Badge>)}</div>
      {s.top_countries.length > 0 && <div className="mt-2.5 text-xs text-mute">Top origins: {s.top_countries.map((c) => `${flag(c.code)} ${c.code}`).join('  ')}</div>}
      <div className="mt-3 flex items-center justify-between text-xs text-mute">
        <span>Last event {ago(s.last_seen)}</span>
        <button className="text-accent hover:underline" onClick={() => onPick(s.id)}>{active ? 'Showing in dashboard' : 'Filter dashboard'}</button>
      </div>
    </Card>
  );
}

function AddSensor() {
  const [open, setOpen] = useState(false);
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  const snippet = `curl -X POST "${origin}/api/ingest/stream?sensor=my-sensor" \\
  -H "Content-Type: application/json" \\
  -d '{"eventid":"cowrie.login.failed","src_ip":"203.0.113.9","username":"root","password":"123456","timestamp":"'"$(date -u +%FT%TZ)"'"}'`;
  return (
    <Card>
      <button className="w-full flex items-center justify-between px-4 py-3 text-left" onClick={() => setOpen(!open)} aria-expanded={open}>
        <div><h3 className="text-[13px] font-semibold">Add a sensor</h3><p className="text-xs text-mute mt-0.5">Sensors are deployed with the Ansible roles in honeypot-infra; any log shipper can feed the ingest endpoint.</p></div>
        <ChevronDown size={16} className={cx('text-mute transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-4 text-[13px] text-soft border-t border-line pt-3">
          <div>
            <div className="font-medium text-ink mb-1">1. Deploy with Ansible</div>
            <p className="text-xs text-mute mb-1.5">Add the host to <Mono>inventory.ini</Mono> under [honeypot] (Cowrie) or [snare] (web), then:</p>
            <pre className="rounded-lg bg-[#060a12] border border-line p-2.5 text-[12px] font-mono overflow-x-auto">ansible-playbook -i inventory.ini site.yml --limit &lt;host&gt;</pre>
          </div>
          <div>
            <div className="font-medium text-ink mb-1">2. Or send events from anything</div>
            <p className="text-xs text-mute mb-1.5">POST a JSON object, array or NDJSON. Use <Mono>?sensor=</Mono> to name the source; it shows up here automatically.</p>
            <div className="relative"><pre className="rounded-lg bg-[#060a12] border border-line p-2.5 text-[12px] font-mono overflow-x-auto whitespace-pre-wrap break-all">{snippet}</pre><span className="absolute top-2 right-2"><CopyButton text={snippet} /></span></div>
          </div>
        </div>
      )}
    </Card>
  );
}

export default function Sensors() {
  const { data, error, reload } = useApi('/sensors', null, { filters: false, interval: 20000 });
  const { sensor, setSensor } = useFilters();
  return (
    <div className="space-y-4">
      <PageHeader title="Sensors" sub="Health and output of every honeypot feeding this dashboard." />
      <ErrorBox error={error} onRetry={reload} />
      {!data ? <Skeleton className="h-64" /> : data.length === 0 ? <Card><Empty title="No sensors have reported yet" hint="Deploy a honeypot or POST an event to /api/ingest/stream." /></Card> : (
        <div className="grid gap-4 lg:grid-cols-2 2xl:grid-cols-3">
          {data.map((s) => <SensorCard key={s.id} s={s} active={sensor === s.id} onPick={(id) => setSensor(sensor === id ? 'all' : id)} />)}
        </div>
      )}
      <AddSensor />
      <p className="text-xs text-faint">Status: <b className="text-ok font-medium">Live</b> event within 30 min - <b className="text-med font-medium">Idle</b> within 24 h - <b className="text-crit font-medium">Silent</b> longer than that.</p>
    </div>
  );
}
