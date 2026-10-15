import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, Check, Play, RotateCcw, SkipForward } from 'lucide-react';
import { go, useApi } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { clock, duration } from '../lib/format';
import { CATEGORIES, OUTCOMES } from '../lib/theme';
import { Badge, Button, Card, CardHeader, CopyButton, Country, ErrorBox, IPLink, Mono, RiskPill, Skeleton, cx } from '../ui/primitives';
import { TechChips } from './AttackerDrawer';

function KillChain({ phases }) {
  return (
    <ol className="grid grid-cols-2 sm:grid-cols-4 xl:grid-cols-7 gap-2">
      {phases.map((p) => (
        <li key={p.number} title={p.evidence || p.summary}
          className={cx('rounded-lg border p-2.5 min-h-[76px]', p.achieved ? 'border-high/40 bg-high/[0.07]' : 'border-line bg-panel opacity-70')}>
          <div className="flex items-center gap-1.5 text-[11px]">
            <span className={cx('grid place-items-center h-4 w-4 rounded-full text-[10px] font-semibold', p.achieved ? 'bg-high text-[#1c0d00]' : 'bg-line2 text-mute')}>
              {p.achieved ? <Check size={10} strokeWidth={3} /> : p.number}
            </span>
            <span className={cx('font-medium truncate', p.achieved ? 'text-ink' : 'text-mute')}>{p.name}</span>
          </div>
          <p className="text-[11px] text-mute mt-1.5 leading-snug line-clamp-3">{p.achieved && p.evidence ? p.evidence : p.summary}</p>
        </li>
      ))}
    </ol>
  );
}

function Line({ it }) {
  const off = `+${it.offset.toFixed(1)}s`;
  const base = 'flex gap-3 px-4 py-[3px] font-mono text-[12.5px] leading-6';
  let body;
  switch (it.kind) {
    case 'command':
    case 'command_failed':
      body = (
        <span className="break-all">
          <span className="text-accent">$ </span><span className={it.kind === 'command_failed' ? 'text-mute' : 'text-ink'}>{it.text}</span>
          {it.category && it.category !== 'other' && <span className="ml-2 align-middle font-sans"><Badge color={CATEGORIES[it.category]?.color}>{CATEGORIES[it.category]?.label}</Badge></span>}
        </span>
      );
      break;
    case 'login_failed': body = <span className="text-violet">{it.text}</span>; break;
    case 'login_success': body = <span className="text-med font-semibold">{it.text}</span>; break;
    case 'download': case 'upload': body = <span className="text-crit break-all">{it.text}<span className="block text-[11px] text-crit/70">{it.detail}</span></span>; break;
    case 'http_request': body = <span className="text-low break-all">{it.text}{it.detail && <span className="ml-2 text-mute font-sans text-xs">{it.detail}</span>}</span>; break;
    default: body = <span className="text-mute">{it.text}</span>;
  }
  return (
    <div className={base}>
      <span className="w-14 shrink-0 text-faint text-right num">{off}</span>
      {body}
    </div>
  );
}

function Replay({ items }) {
  const [shown, setShown] = useState(items.length);
  const [playing, setPlaying] = useState(false);
  const box = useRef(null);
  const timer = useRef(null);

  useEffect(() => { setShown(items.length); setPlaying(false); }, [items]);
  useEffect(() => {
    if (!playing) return undefined;
    if (shown >= items.length) { setPlaying(false); return undefined; }
    const prev = shown === 0 ? 0 : items[shown - 1].offset;
    // compress real time: cap each gap to 1.4s so long idle periods don't stall the replay
    const gap = Math.min(1400, Math.max(120, (items[shown].offset - prev) * 1000 / 3));
    timer.current = setTimeout(() => setShown((n) => n + 1), gap);
    return () => clearTimeout(timer.current);
  }, [playing, shown, items]);
  useEffect(() => { if (box.current) box.current.scrollTop = box.current.scrollHeight; }, [shown]);

  const start = () => { setShown(0); setPlaying(true); };
  return (
    <Card className="overflow-hidden">
      <CardHeader title="Session replay" sub={`${items.length} events`} right={
        <>
          <Button size="sm" onClick={start}>{shown === items.length && !playing ? <><Play size={13} /> Replay</> : <><RotateCcw size={13} /> Restart</>}</Button>
          <Button size="sm" variant="ghost" onClick={() => { setPlaying(false); setShown(items.length); }} disabled={shown >= items.length}><SkipForward size={13} /> Skip</Button>
        </>
      } />
      <div ref={box} className="bg-[#060a12] border-t border-line max-h-[460px] overflow-y-auto py-2">
        {items.slice(0, shown).map((it, i) => <Line key={i} it={it} />)}
        {playing && <div className="px-4 py-1 font-mono text-accent live-dot">▍</div>}
      </div>
    </Card>
  );
}

export default function SessionDetail({ route }) {
  const id = route[1];
  const { openIP } = useUi();
  const { data, error, reload } = useApi(`/sessions/${id}`, null, { filters: false });
  const s = data?.session;
  const items = useMemo(() => data?.timeline || [], [data]);

  return (
    <div className="space-y-4">
      <button onClick={() => (window.history.length > 1 ? window.history.back() : go('/sessions'))} className="inline-flex items-center gap-1.5 text-xs text-mute hover:text-ink">
        <ArrowLeft size={14} /> Back
      </button>
      <ErrorBox error={error} onRetry={reload} />
      {!data && !error && <div className="space-y-3"><Skeleton className="h-20" /><Skeleton className="h-24" /><Skeleton className="h-72" /></div>}
      {s && (
        <>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <h1 className="text-xl font-semibold tracking-tight">Session <Mono className="text-lg text-soft">{s.id.length > 14 ? `${s.id.slice(0, 14)}…` : s.id}</Mono></h1>
            <Badge color={OUTCOMES[s.outcome]?.color}>{OUTCOMES[s.outcome]?.label}</Badge>
            <CopyButton text={s.id} />
          </div>
          <Card className="px-4 py-3 grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4 text-[13px]">
            <div><div className="text-[11px] uppercase tracking-wider text-mute">Source</div><div className="mt-1 flex items-center gap-2"><IPLink ip={s.src_ip} onClick={openIP} /></div><div className="text-xs text-mute mt-0.5"><Country geo={s.geo} /></div></div>
            <div><div className="text-[11px] uppercase tracking-wider text-mute">Started</div><div className="mt-1 num">{clock(s.start, true)}</div></div>
            <div><div className="text-[11px] uppercase tracking-wider text-mute">Duration</div><div className="mt-1 num">{duration(s.duration)}</div></div>
            <div><div className="text-[11px] uppercase tracking-wider text-mute">Sensor</div><div className="mt-1">{s.sensor}<div className="text-xs text-mute">{s.protocol?.toUpperCase()} :{s.dst_port}</div></div></div>
            <div><div className="text-[11px] uppercase tracking-wider text-mute">Client</div><div className="mt-1 font-mono text-xs break-all">{s.client || '-'}</div></div>
            <div><div className="text-[11px] uppercase tracking-wider text-mute">Severity</div><div className="mt-1.5"><RiskPill score={s.severity} /></div></div>
          </Card>

          <Card>
            <CardHeader title="Kill chain" sub="How far this session progressed" />
            <div className="px-4 pb-4"><KillChain phases={data.kill_chain} /></div>
          </Card>

          <div className="grid gap-4 xl:grid-cols-3">
            <div className="xl:col-span-2 space-y-4">
              <Replay items={items} />
              {data.commands.length > 0 && (
                <Card>
                  <CardHeader title="Commands as a script" right={<CopyButton text={data.transcript} label="Copy" />} />
                  <pre className="mx-4 mb-4 overflow-x-auto rounded-lg bg-[#060a12] border border-line p-3 text-[12px] font-mono text-soft whitespace-pre-wrap break-all">{data.transcript}</pre>
                </Card>
              )}
            </div>
            <div className="space-y-4">
              <Card>
                <CardHeader title="Analysis" sub={data.analysis.model} />
                <div className="px-4 pb-4 text-[13px] space-y-3">
                  <div><div className="text-[11px] uppercase tracking-wider text-mute">Likely intent</div><p className="mt-0.5">{data.analysis.intent}</p></div>
                  <div className="flex gap-6">
                    <div><div className="text-[11px] uppercase tracking-wider text-mute">Category</div><p className="mt-0.5">{data.analysis.category}</p></div>
                    <div><div className="text-[11px] uppercase tracking-wider text-mute">Actor</div><p className="mt-0.5">{data.analysis.skill_level}</p></div>
                  </div>
                  <p className="text-soft leading-relaxed">{data.analysis.summary}</p>
                  <div>
                    <div className="text-[11px] uppercase tracking-wider text-mute mb-1">Recommended</div>
                    <ul className="list-disc pl-4 space-y-0.5 text-soft">{data.analysis.recommended_actions.map((a) => <li key={a}>{a}</li>)}</ul>
                  </div>
                </div>
              </Card>
              <Card>
                <CardHeader title="ATT&CK techniques" />
                <div className="px-4 pb-4"><TechChips techs={s.techniques} max={20} /></div>
              </Card>
              {s.families?.length > 0 && (
                <Card>
                  <CardHeader title="Matches known activity" />
                  <div className="px-4 pb-4 flex flex-wrap gap-1.5">{s.families.map((f) => <Badge key={f} color="#ff5d73">{f}</Badge>)}</div>
                </Card>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
