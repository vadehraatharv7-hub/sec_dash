import { useEffect, useState } from 'react';
import { go, useApi, useDebounced, useRoute } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { clock, duration, nf } from '../lib/format';
import { OUTCOMES, OUTCOME_ORDER } from '../lib/theme';
import {
  Badge, Card, Country, Empty, ErrorBox, IPLink, PageHeader, Pager, SearchInput, Segmented, Select, Skeleton, Table, Td, Th, Tr,
} from '../ui/primitives';

const LIMIT = 40;

function Details({ s }) {
  const parts = [];
  if (s.username) parts.push(<span key="u">as <b className="font-mono text-ink">{s.username}</b></span>);
  if (s.failed) parts.push(<span key="f">{nf.format(s.failed)} failed login{s.failed > 1 ? 's' : ''}</span>);
  if (s.commands) parts.push(<span key="c">{s.commands} command{s.commands > 1 ? 's' : ''}</span>);
  if (s.downloads) parts.push(<span key="d" className="text-crit">{s.downloads} payload{s.downloads > 1 ? 's' : ''}</span>);
  if (s.requests) parts.push(<span key="r">{s.requests} request{s.requests > 1 ? 's' : ''}</span>);
  if (!parts.length) return <span className="text-faint">connect only</span>;
  return <span className="text-soft">{parts.reduce((a, p, i) => (i ? [...a, <span key={`s${i}`} className="text-faint"> · </span>, p] : [p]), [])}</span>;
}

export default function Sessions() {
  const { query } = useRoute();
  const { openIP } = useUi();
  const [outcome, setOutcome] = useState(query.outcome || '');
  const [q, setQ] = useState(query.q || '');
  const [sort, setSort] = useState('recent');
  const [offset, setOffset] = useState(0);
  const dq = useDebounced(q);
  useEffect(() => { if (query.outcome !== undefined) setOutcome(query.outcome); }, [query.outcome]);
  useEffect(() => { setOffset(0); }, [outcome, dq, sort, query.technique, query.ip]);

  const { data, error, loading, reload } = useApi('/sessions', { outcome, q: dq, sort, offset, limit: LIMIT, technique: query.technique, ip: query.ip });
  const opts = [{ id: '', label: 'All' }, ...OUTCOME_ORDER.map((o) => ({ id: o, label: OUTCOMES[o].label, count: data?.outcomes?.[o] ?? 0 }))];
  const customOutcome = outcome && !OUTCOME_ORDER.includes(outcome);

  return (
    <div className="space-y-4">
      <PageHeader title="Sessions" sub="Each connection to a honeypot, reconstructed end to end. Open one to replay what the attacker typed." />
      <div className="flex flex-wrap items-center gap-2.5">
        <Segmented value={customOutcome ? '' : outcome} onChange={setOutcome} options={opts} size="sm" />
        <SearchInput value={q} onChange={setQ} placeholder="IP, user, command, URL, hash..." className="w-64" />
        <Select aria-label="Sort" value={sort} onChange={setSort} options={[{ id: 'recent', label: 'Sort: newest' }, { id: 'severity', label: 'Sort: severity' }, { id: 'duration', label: 'Sort: duration' }, { id: 'commands', label: 'Sort: commands' }]} />
        {(query.technique || query.ip || customOutcome) && (
          <Badge color="#3dd6c6">
            filter: {[query.technique, query.ip, customOutcome && outcome].filter(Boolean).join(' ')}
            <button className="ml-1" onClick={() => go('/sessions')} aria-label="Clear filters">×</button>
          </Badge>
        )}
        <span className="ml-auto text-xs text-mute num">{data ? `${nf.format(data.total)} sessions` : ''}{loading && ' ...'}</span>
      </div>
      <ErrorBox error={error} onRetry={reload} />
      <Card className="overflow-hidden">
        {!data ? <div className="p-4 space-y-2">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-9" />)}</div> : data.sessions.length === 0 ? (
          <Empty title="No sessions match" hint="Try a different outcome or a wider time range." />
        ) : (
          <>
            <Table head={<><Th>Started</Th><Th>Source</Th><Th>Outcome</Th><Th>What happened</Th><Th>Sensor</Th><Th align="right">Duration</Th><Th align="right">Severity</Th></>}>
              {data.sessions.map((s) => (
                <Tr key={s.id} onClick={() => go(`/sessions/${s.id}`)}>
                  <Td className="whitespace-nowrap text-mute num">{clock(s.start, true)}</Td>
                  <Td><div className="flex items-center gap-2"><IPLink ip={s.src_ip} onClick={openIP} /><span className="text-xs text-faint"><Country geo={s.geo} short /></span></div></Td>
                  <Td><Badge color={OUTCOMES[s.outcome]?.color}>{OUTCOMES[s.outcome]?.label}</Badge></Td>
                  <Td><Details s={s} /></Td>
                  <Td className="text-mute text-xs">{s.sensor}</Td>
                  <Td align="right" className="text-mute">{duration(s.duration)}</Td>
                  <Td align="right"><span className="font-semibold" style={{ color: s.severity >= 80 ? '#ff5d73' : s.severity >= 60 ? '#ff9a4d' : s.severity >= 35 ? '#f5c451' : '#7d8ba3' }}>{s.severity}</span></Td>
                </Tr>
              ))}
            </Table>
            <Pager total={data.total} offset={offset} limit={LIMIT} onChange={setOffset} />
          </>
        )}
      </Card>
    </div>
  );
}
