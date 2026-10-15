import { useState } from 'react';
import { Plus, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { ago } from '../lib/format';
import { Button, Card, CardHeader, Empty, ErrorBox, IPLink, PageHeader, Skeleton, Table, Td, Th, Tr } from '../ui/primitives';

export default function Blocklist() {
  const { data, error, reload } = useApi('/bans', null, { filters: false, interval: 20000 });
  const { openIP } = useUi();
  const [ip, setIP] = useState('');
  const [reason, setReason] = useState('');
  const [err, setErr] = useState(null);

  const add = async (e) => {
    e.preventDefault(); setErr(null);
    try { await api('/bans', { method: 'POST', body: { ip: ip.trim(), reason } }); setIP(''); setReason(''); reload(); } catch (x) { setErr(x); }
  };
  const del = async (v) => { setErr(null); try { await api(`/bans/${v}`, { method: 'DELETE' }); reload(); } catch (x) { setErr(x); } };

  return (
    <div className="space-y-4">
      <PageHeader title="Blocklist" sub="IPs your edge firewall should drop. The xdp-shield agent polls this list and enforces it in the kernel." />
      <ErrorBox error={error || err} onRetry={reload} />
      <Card>
        <CardHeader title="Block an address" />
        <form onSubmit={add} className="px-4 pb-4 flex flex-wrap gap-2">
          <input value={ip} onChange={(e) => setIP(e.target.value)} placeholder="203.0.113.7" required aria-label="IP address"
            className="h-8 w-48 rounded-lg border border-line bg-panel px-2.5 font-mono text-[13px] focus:border-accent/60 focus:outline-none" />
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (optional)" aria-label="Reason"
            className="h-8 flex-1 min-w-[200px] rounded-lg border border-line bg-panel px-2.5 text-[13px] focus:border-accent/60 focus:outline-none" />
          <Button variant="primary" type="submit"><Plus size={14} /> Block</Button>
        </form>
      </Card>
      <Card className="overflow-hidden">
        <CardHeader title={`Blocked addresses${data ? ` (${data.length})` : ''}`} sub="Enforcement endpoint: GET /api/threats/banned" />
        {!data ? <Skeleton className="h-32 m-4" /> : data.length === 0 ? <Empty icon={ShieldCheck} title="Nothing blocked" hint="Block an attacker from its profile, or add an address above." /> : (
          <Table head={<><Th>IP</Th><Th>Reason</Th><Th>Blocked</Th><Th /></>}>
            {data.map((b) => (
              <Tr key={b.ip}>
                <Td><IPLink ip={b.ip} onClick={openIP} /></Td>
                <Td className="text-soft">{b.reason}</Td>
                <Td className="text-mute whitespace-nowrap">{ago(b.banned_at)}</Td>
                <Td align="right"><Button size="sm" variant="ghost" onClick={() => del(b.ip)}>Unblock</Button></Td>
              </Tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
