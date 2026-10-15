import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Pause, Play, Trash2 } from 'lucide-react';
import { api } from '../lib/api';
import { go, useFilters, useLive, useRoute, useDebounced } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { clock, flag } from '../lib/format';
import { CATEGORIES, KINDS } from '../lib/theme';
import { Badge, Button, Card, Empty, Mono, PageHeader, SearchInput, Segmented, cx } from '../ui/primitives';

const FILTERS = [
  { id: '', label: 'Everything' },
  { id: 'login_success,command,download,upload,tcp_forward', label: 'Serious only' },
  { id: 'login_failed,login_success', label: 'Logins' },
  { id: 'command,command_failed', label: 'Commands' },
  { id: 'download,upload', label: 'Payloads' },
  { id: 'http_request', label: 'Web' },
];

function describe(e) {
  switch (e.kind) {
    case 'login_failed': return <span>login failed <Mono className="text-soft">{e.username}</Mono> / <Mono className="text-soft">{e.password || '(empty)'}</Mono></span>;
    case 'login_success': return <span className="text-med">logged in as <Mono>{e.username}</Mono> / <Mono>{e.password || '(empty)'}</Mono></span>;
    case 'command': case 'command_failed': return <Mono className="text-ink break-all">$ {e.input}</Mono>;
    case 'download': case 'upload': return <span className="text-crit">payload <Mono className="break-all">{e.url || e.sha256}</Mono></span>;
    case 'http_request': return <span><Mono className="text-ink break-all">{e.method} {e.path}</Mono>{e.label && <span className="text-mute ml-2">{e.label}</span>}</span>;
    case 'connect': return <span>connected to port {e.dst_port}</span>;
    case 'client_version': return <span>client banner <Mono className="text-soft">{e.client}</Mono></span>;
    case 'close': return <span>session closed{e.duration ? ` after ${e.duration.toFixed(1)}s` : ''}</span>;
    default: return <span>{e.eventid}</span>;
  }
}

export default function LiveFeed() {
  const { query } = useRoute();
  const { sensor } = useFilters();
  const { openIP } = useUi();
  const [kind, setKind] = useState('');
  const [q, setQ] = useState(query.q || '');
  const dq = useDebounced(q, 350);
  const [rows, setRows] = useState([]);
  const [paused, setPaused] = useState(false);
  const [perMin, setPerMin] = useState(0);
  const [loading, setLoading] = useState(true);
  const pausedRef = useRef(false);
  const stamps = useRef([]);
  pausedRef.current = paused;

  useEffect(() => { setQ(query.q || ''); }, [query.q]);

  useEffect(() => {
    const ctl = new AbortController();
    setLoading(true);
    api('/events', { params: { limit: 150, kind, q: dq, sensor }, signal: ctl.signal })
      .then((r) => setRows(r.events.map((e, i) => ({ ...e, _k: `${e.ts}${i}` }))))
      .catch(() => {})
      .finally(() => setLoading(false));
    return () => ctl.abort();
  }, [kind, dq, sensor]);

  const match = useMemo(() => {
    const kinds = new Set(kind.split(',').filter(Boolean));
    const needle = dq.toLowerCase();
    return (e) => {
      if (sensor !== 'all' && e.sensor !== sensor) return false;
      if (kinds.size && !kinds.has(e.kind)) return false;
      if (needle) {
        const hay = [e.src_ip, e.username, e.password, e.input, e.url, e.sha256, e.session, e.path, e.client, e.sensor, e.geo?.country_name].join(' ').toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      return true;
    };
  }, [kind, dq, sensor]);

  const onEvent = useCallback((e) => {
    const now = Date.now();
    stamps.current = [...stamps.current.filter((t) => now - t < 60000), now];
    setPerMin(stamps.current.length);
    if (pausedRef.current || !match(e)) return;
    setRows((r) => [{ ...e, _k: `${e.ts}${Math.random()}`, _new: true }, ...r].slice(0, 300));
  }, [match]);
  const status = useLive(onEvent);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Live Feed"
        sub="Every event as it hits a sensor. Click an address to open its profile."
        right={
          <>
            <span className="text-xs text-mute num">{perMin} events/min</span>
            <Button size="sm" onClick={() => setPaused((p) => !p)}>{paused ? <><Play size={13} /> Resume</> : <><Pause size={13} /> Pause</>}</Button>
            <Button size="sm" variant="ghost" onClick={() => setRows([])}><Trash2 size={13} /> Clear</Button>
          </>
        }
      />
      <div className="flex flex-wrap items-center gap-3">
        <Segmented value={kind} onChange={setKind} options={FILTERS} />
        <SearchInput value={q} onChange={(v) => { setQ(v); }} placeholder="Filter by IP, user, command, URL..." className="w-72" />
        <span className={cx('ml-auto text-xs', status === 'live' ? 'text-ok' : 'text-mute')}>{status === 'live' ? (paused ? 'Paused' : 'Streaming') : 'Stream reconnecting...'}</span>
      </div>
      <Card className="overflow-hidden">
        {rows.length === 0 ? (
          <Empty title={loading ? 'Loading...' : 'No matching events'} hint="New events appear here the moment a sensor reports them." />
        ) : (
          <ul className="divide-y divide-line/60 max-h-[calc(100vh-250px)] overflow-y-auto font-sans">
            {rows.map((e) => {
              const k = KINDS[e.kind] || KINDS.other;
              return (
                <li key={e._k} className={cx('flex flex-wrap sm:flex-nowrap items-start gap-x-3 gap-y-1 px-4 py-2 text-[13px] hover:bg-panel2/60', e._new && 'row-in')}>
                  <span className="num text-xs text-faint w-[68px] shrink-0 pt-0.5">{clock(e.ts)}</span>
                  <span className="w-[92px] shrink-0"><Badge color={k.color}>{k.label}</Badge></span>
                  <span className="w-[150px] shrink-0 truncate">
                    <span aria-hidden className="mr-1.5">{flag(e.geo?.country_code)}</span>
                    {e.src_ip ? <button className="font-mono text-[12px] text-accent hover:underline" onClick={() => openIP(e.src_ip)}>{e.src_ip}</button> : <span className="text-faint">unknown</span>}
                  </span>
                  <span className="order-last sm:order-none basis-full sm:basis-0 flex-1 min-w-0 text-soft">{describe(e)}</span>
                  {e.category && e.category !== 'other' && <span className="hidden lg:block"><Badge color={CATEGORIES[e.category]?.color}>{CATEGORIES[e.category]?.label}</Badge></span>}
                  <span className="hidden xl:block text-xs text-faint w-[96px] text-right truncate">{e.sensor}</span>
                  {e.session && e.source === 'cowrie' && (
                    <button className="hidden 2xl:block text-xs text-faint hover:text-accent font-mono" onClick={() => go(`/sessions/${e.session}`)}>{e.session.slice(0, 8)}</button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>
    </div>
  );
}
