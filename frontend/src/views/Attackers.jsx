import { useEffect, useState } from 'react';
import { useApi, useDebounced, useRoute } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { ago, nf } from '../lib/format';
import { CLASSES } from '../lib/theme';
import {
  Badge, Card, Country, Empty, ErrorBox, IPLink, PageHeader, Pager, RiskPill, SearchInput, Select, Skeleton, Table, Td, Th, Tr,
} from '../ui/primitives';

const LIMIT = 50;
const SORTS = [{ id: 'risk', label: 'Sort: risk' }, { id: 'events', label: 'Sort: events' }, { id: 'sessions', label: 'Sort: sessions' }, { id: 'recent', label: 'Sort: most recent' }];

export default function Attackers() {
  const { query } = useRoute();
  const { openIP } = useUi();
  const [q, setQ] = useState(query.q || '');
  const [cls, setCls] = useState(query.class || '');
  const [minRisk, setMinRisk] = useState(query.min_risk || '0');
  const [sort, setSort] = useState('risk');
  const [offset, setOffset] = useState(0);
  const dq = useDebounced(q);

  useEffect(() => {
    if (query.min_risk !== undefined) setMinRisk(query.min_risk);
    if (query.class !== undefined) setCls(query.class);
    if (query.ip) openIP(query.ip);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.min_risk, query.class, query.ip]);
  useEffect(() => { setOffset(0); }, [dq, cls, minRisk, sort]);

  const { data, error, loading, reload } = useApi('/attackers', { q: dq, class: cls, min_risk: minRisk, sort, offset, limit: LIMIT });

  return (
    <div className="space-y-4">
      <PageHeader title="Attackers" sub="Every source IP seen in the window, scored by what it actually did on the honeypot." />
      <div className="flex flex-wrap items-center gap-2.5">
        <SearchInput value={q} onChange={setQ} placeholder="IP, country, city, network..." className="w-64" />
        <Select aria-label="Behaviour" value={cls} onChange={setCls} options={[{ id: '', label: 'All behaviours' }, ...Object.entries(CLASSES).map(([id, c]) => ({ id, label: c.label }))]} />
        <Select aria-label="Minimum risk" value={minRisk} onChange={setMinRisk} options={[{ id: '0', label: 'Any risk' }, { id: '35', label: 'Medium+ (35)' }, { id: '60', label: 'High+ (60)' }, { id: '80', label: 'Critical (80)' }]} />
        <Select aria-label="Sort" value={sort} onChange={setSort} options={SORTS} />
        <span className="ml-auto text-xs text-mute num">{data ? `${nf.format(data.total)} attackers` : ''}{loading && ' ...'}</span>
      </div>
      <ErrorBox error={error} onRetry={reload} />
      <Card className="overflow-hidden">
        {!data ? <div className="p-4 space-y-2">{Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-9" />)}</div> : data.attackers.length === 0 ? (
          <Empty title="No attackers match" hint="Try a wider time range or clear the filters." />
        ) : (
          <>
            <Table head={<><Th>Source</Th><Th>Origin</Th><Th>Behaviour</Th><Th align="right">Sessions</Th><Th align="right">Events</Th><Th align="right">Logins ok/failed</Th><Th align="right">Cmds</Th><Th>Last seen</Th><Th>Risk</Th></>}>
              {data.attackers.map((a) => (
                <Tr key={a.ip} onClick={() => openIP(a.ip)}>
                  <Td><div className="flex items-center gap-2"><IPLink ip={a.ip} onClick={openIP} />{a.banned && <Badge color="#ff5d73" solid>Blocked</Badge>}{a.campaign && <Badge color="#a78bfa">campaign</Badge>}</div></Td>
                  <Td><div className="leading-tight"><Country geo={a.geo} /><div className="text-[11px] text-faint truncate max-w-[200px]">{a.geo?.org || a.geo?.city}</div></div></Td>
                  <Td><div className="flex flex-col gap-0.5 items-start"><Badge color={CLASSES[a.class]?.color}>{CLASSES[a.class]?.label}</Badge>{a.credential_style && <span className="text-[11px] text-faint">{a.credential_style}</span>}</div></Td>
                  <Td align="right">{a.sessions}</Td>
                  <Td align="right">{nf.format(a.events)}</Td>
                  <Td align="right"><span className="text-ok">{a.successful_logins}</span> <span className="text-faint">/</span> {nf.format(a.failed_logins)}</Td>
                  <Td align="right">{a.commands || '-'}</Td>
                  <Td className="text-mute whitespace-nowrap">{ago(a.last_seen)}</Td>
                  <Td><RiskPill score={a.risk} label={a.risk_label} /></Td>
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
