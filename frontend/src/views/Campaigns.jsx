import { useEffect, useState } from 'react';
import { Network } from 'lucide-react';
import { useApi, useRoute } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { ago, clock, flag } from '../lib/format';
import { Badge, Card, CardHeader, CopyButton, Empty, ErrorBox, IPLink, Mono, PageHeader, RiskPill, Skeleton, cx } from '../ui/primitives';
import { TechChips } from './AttackerDrawer';

function Block({ title, children }) {
  return <div><div className="text-[11px] uppercase tracking-wider text-mute mb-1.5">{title}</div>{children}</div>;
}

export default function Campaigns() {
  const { query } = useRoute();
  const { openIP } = useUi();
  const { data, error, reload } = useApi('/campaigns', null, { interval: 30000 });
  const [sel, setSel] = useState(query.id || null);
  useEffect(() => { if (query.id) setSel(query.id); }, [query.id]);
  const cur = data?.find((c) => c.id === sel) || data?.[0];

  return (
    <div className="space-y-4">
      <PageHeader title="Campaigns" sub="Groups of attacker IPs that share payload hashes, download URLs or identical command playbooks - evidence they are one operation." />
      <ErrorBox error={error} onRetry={reload} />
      {!data ? <Skeleton className="h-64" /> : data.length === 0 ? (
        <Card><Empty icon={Network} title="No coordinated campaigns detected" hint="A campaign appears when two or more IPs reuse the same payload, URL or command sequence." /></Card>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[380px_1fr]">
          <div className="space-y-2.5">
            {data.map((c) => (
              <button key={c.id} onClick={() => setSel(c.id)}
                className={cx('w-full text-left rounded-xl border p-3.5 transition-colors', cur?.id === c.id ? 'border-accent/50 bg-panel2' : 'border-line bg-panel hover:bg-panel2/60')}>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0"><div className="text-[13px] font-semibold truncate">{c.name}</div><div className="text-[11px] text-faint font-mono">#{c.id}</div></div>
                  <RiskPill score={c.risk} />
                </div>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-mute">
                  <span><b className="text-ink num">{c.attackers}</b> IPs</span>
                  <span><b className="text-ink num">{c.sessions}</b> sessions</span>
                  <span>{c.countries.slice(0, 6).map(flag).join(' ')}</span>
                </div>
                <div className="mt-1.5 text-[11px] text-faint">Last active {ago(c.last_seen)}</div>
              </button>
            ))}
          </div>
          {cur && (
            <Card className="self-start">
              <CardHeader title={cur.name} sub={`Campaign #${cur.id} - ${clock(cur.first_seen, true)} to ${clock(cur.last_seen, true)}`}
                right={<CopyButton text={cur.ips.join('\n')} label="Copy IPs" />} />
              <div className="px-4 pb-5 space-y-5">
                <div className="flex flex-wrap gap-1.5">
                  {cur.linked_by.map((l) => <Badge key={l} color="#a78bfa">linked by {l}</Badge>)}
                  {cur.families.map((f) => <Badge key={f} color="#ff5d73">{f}</Badge>)}
                  {cur.sensors.map((s) => <Badge key={s}>{s}</Badge>)}
                </div>
                <Block title={`Infrastructure (${cur.ips.length} IPs)`}>
                  <div className="flex flex-wrap gap-x-4 gap-y-1.5 max-h-40 overflow-y-auto">
                    {cur.ips.map((ip) => <IPLink key={ip} ip={ip} onClick={openIP} />)}
                  </div>
                </Block>
                {cur.hashes.length > 0 && (
                  <Block title="Payload hashes">
                    <ul className="space-y-1">{cur.hashes.map((h) => (
                      <li key={h} className="flex items-center gap-2"><Mono className="text-soft break-all">{h}</Mono><CopyButton text={h} />
                        <a className="text-xs text-accent hover:underline shrink-0" href={`https://www.virustotal.com/gui/file/${h}`} target="_blank" rel="noreferrer noopener">VirusTotal</a></li>
                    ))}</ul>
                  </Block>
                )}
                {cur.urls.length > 0 && (
                  <Block title="Distribution URLs"><ul className="space-y-1">{cur.urls.map((u) => <li key={u} className="flex gap-2"><Mono className="text-crit break-all">{u}</Mono><CopyButton text={u} /></li>)}</ul></Block>
                )}
                {cur.playbooks.length > 0 && (
                  <Block title="Command playbooks">
                    <div className="space-y-2">{cur.playbooks.map((p) => (
                      <div key={p.hash} className="rounded-lg border border-line bg-[#060a12] p-3">
                        <div className="text-[11px] text-faint mb-1.5">{p.sessions} sessions from {p.ips} IPs</div>
                        {p.commands.map((c, i) => <div key={i} className="font-mono text-[12px] text-soft break-all"><span className="text-accent">$ </span>{c}</div>)}
                      </div>
                    ))}</div>
                  </Block>
                )}
                <Block title="ATT&CK techniques"><TechChips techs={cur.techniques} max={24} /></Block>
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
