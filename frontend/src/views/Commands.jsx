import { go, useApi } from '../lib/hooks';
import { ago, nf } from '../lib/format';
import { CATEGORIES } from '../lib/theme';
import { BarList } from '../ui/charts';
import { Badge, Card, CardHeader, CopyButton, Empty, ErrorBox, Mono, PageHeader, Skeleton, Stat, Table, Td, Th, Tr } from '../ui/primitives';

export default function Commands() {
  const { data, error, reload } = useApi('/commands', { limit: 40 }, { interval: 30000 });
  if (!data) return <div className="space-y-4"><PageHeader title="Commands" /><ErrorBox error={error} onRetry={reload} /><Skeleton className="h-72" /></div>;
  const cats = Object.entries(data.categories).map(([k, v]) => ({ key: k, label: CATEGORIES[k]?.label || k, value: v, color: CATEGORIES[k]?.color })).sort((a, b) => b.value - a.value);
  return (
    <div className="space-y-4">
      <PageHeader title="Commands" sub="What attackers do once they are inside - grouped, classified and mapped to ATT&CK." />
      <Card className="px-5 py-4 grid grid-cols-3 gap-5 max-w-xl">
        <Stat label="Commands run" value={nf.format(data.total)} />
        <Stat label="Distinct commands" value={nf.format(data.unique)} />
        <Stat label="Recurring playbooks" value={data.playbooks.length} />
      </Card>
      {data.total === 0 ? <Card><Empty title="No shell commands in this window" hint="Commands appear once an attacker logs in to the SSH/Telnet honeypot." /></Card> : (
        <>
          <div className="grid gap-4 xl:grid-cols-[320px_1fr]">
            <Card className="self-start"><CardHeader title="By intent" /><div className="px-3 pb-3"><BarList items={cats} /></div></Card>
            <Card className="overflow-hidden">
              <CardHeader title="Most common commands" />
              <Table head={<><Th>Command</Th><Th>Type</Th><Th align="right">Runs</Th><Th align="right">IPs</Th><Th>Last</Th><Th /></>}>
                {data.top.map((c) => (
                  <Tr key={c.command}>
                    <Td className="max-w-[520px]"><Mono className="break-all text-ink">{c.sample}</Mono>
                      {c.techniques?.length > 0 && <div className="mt-1 flex flex-wrap gap-1">{c.techniques.map((t) => (
                        <button key={t.id} onClick={() => go('/sessions', { technique: t.id })} title={`${t.tactic}: ${t.name}`} className="text-[10px] font-mono text-faint hover:text-accent">{t.id}</button>))}</div>}
                    </Td>
                    <Td><Badge color={CATEGORIES[c.category]?.color}>{CATEGORIES[c.category]?.label || c.category}</Badge></Td>
                    <Td align="right">{nf.format(c.count)}</Td><Td align="right">{c.ips}</Td>
                    <Td className="text-mute whitespace-nowrap">{ago(c.last_seen)}</Td>
                    <Td><CopyButton text={c.sample} /></Td>
                  </Tr>
                ))}
              </Table>
            </Card>
          </div>
          {data.playbooks.length > 0 && (
            <Card>
              <CardHeader title="Recurring playbooks" sub="Identical command sequences reused across sessions - the signature of automated tooling" />
              <div className="px-4 pb-4 grid gap-3 lg:grid-cols-2">
                {data.playbooks.slice(0, 6).map((p) => (
                  <div key={p.hash} className="rounded-lg border border-line bg-[#060a12] p-3">
                    <div className="flex justify-between text-[11px] text-faint mb-2"><span className="font-mono">#{p.hash}</span><span>{p.sessions} sessions - {p.ips} IPs</span></div>
                    {p.commands.slice(0, 8).map((c, i) => <div key={i} className="font-mono text-[12px] text-soft break-all"><span className="text-accent">$ </span>{c}</div>)}
                    {p.commands.length > 8 && <div className="text-[11px] text-faint mt-1">+{p.commands.length - 8} more</div>}
                  </div>
                ))}
              </div>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
