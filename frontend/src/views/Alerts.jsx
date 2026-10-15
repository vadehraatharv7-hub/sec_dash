import { useState } from 'react';
import { BellRing, Plus, Send, Trash2 } from 'lucide-react';
import { api } from '../lib/api';
import { useApi } from '../lib/hooks';
import { ago } from '../lib/format';
import { Badge, Button, Card, CardHeader, Empty, ErrorBox, Mono, PageHeader, Select, Skeleton, Table, Td, Th, Tr, cx } from '../ui/primitives';

const TRIGGERS = [
  ['on_login_success', 'Attacker logs in'],
  ['on_malware', 'Payload captured'],
  ['on_critical_command', 'Dangerous command'],
  ['on_web_exploit', 'Web exploit attempt'],
];

function Toggle({ checked, onChange, label }) {
  return (
    <label className="inline-flex items-center gap-2 text-[13px] cursor-pointer select-none">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="accent-[var(--color-accent)] h-3.5 w-3.5" />
      {label}
    </label>
  );
}

export default function Alerts() {
  const hooks = useApi('/webhooks', null, { filters: false });
  const logs = useApi('/webhooks/logs', null, { filters: false, interval: 15000 });
  const [form, setForm] = useState({ name: '', url: '', type: 'slack', on_login_success: true, on_malware: true, on_critical_command: false, on_web_exploit: false, enabled: true });
  const [err, setErr] = useState(null);
  const [test, setTest] = useState({});
  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));

  const add = async (e) => {
    e.preventDefault(); setErr(null);
    try { await api('/webhooks', { method: 'POST', body: form }); setForm((f) => ({ ...f, name: '', url: '' })); hooks.reload(); } catch (x) { setErr(x); }
  };
  const del = async (id) => { try { await api(`/webhooks/${id}`, { method: 'DELETE' }); hooks.reload(); } catch (x) { setErr(x); } };
  const run = async (id) => {
    setTest((t) => ({ ...t, [id]: { busy: true } }));
    try { const r = await api(`/webhooks/${id}/test`, { method: 'POST' }); setTest((t) => ({ ...t, [id]: r })); logs.reload(); } catch (x) { setTest((t) => ({ ...t, [id]: { success: false, message: x.message } })); }
  };

  return (
    <div className="space-y-4">
      <PageHeader title="Alerts" sub="Push high-signal honeypot events to Slack, Discord or any webhook. Repeats from the same IP are suppressed for 10 minutes." />
      <ErrorBox error={err || hooks.error} onRetry={hooks.reload} />
      <div className="grid gap-4 xl:grid-cols-[420px_1fr]">
        <Card className="self-start">
          <CardHeader title="New webhook" />
          <form onSubmit={add} className="px-4 pb-4 space-y-3">
            <input value={form.name} onChange={(e) => set('name', e.target.value)} placeholder="Name (e.g. #soc-alerts)" aria-label="Name"
              className="h-8 w-full rounded-lg border border-line bg-panel px-2.5 text-[13px] focus:border-accent/60 focus:outline-none" />
            <input value={form.url} onChange={(e) => set('url', e.target.value)} placeholder="https://hooks.slack.com/services/..." required type="url" aria-label="Webhook URL"
              className="h-8 w-full rounded-lg border border-line bg-panel px-2.5 font-mono text-[12px] focus:border-accent/60 focus:outline-none" />
            <Select aria-label="Format" value={form.type} onChange={(v) => set('type', v)} className="w-full" options={[{ id: 'slack', label: 'Slack' }, { id: 'discord', label: 'Discord' }, { id: 'generic', label: 'Generic JSON' }]} />
            <fieldset className="space-y-1.5">
              <legend className="text-[11px] uppercase tracking-wider text-mute mb-1">Alert when</legend>
              {TRIGGERS.map(([k, l]) => <div key={k}><Toggle checked={form[k]} onChange={(v) => set(k, v)} label={l} /></div>)}
            </fieldset>
            <Button variant="primary" type="submit" className="w-full"><Plus size={14} /> Add webhook</Button>
            <p className="text-[11px] text-faint">Webhooks to private or loopback addresses are refused.</p>
          </form>
        </Card>

        <div className="space-y-4">
          <Card className="overflow-hidden">
            <CardHeader title="Destinations" />
            {!hooks.data ? <Skeleton className="h-24 m-4" /> : hooks.data.length === 0 ? <Empty icon={BellRing} title="No webhooks yet" hint="Add one to get alerted when something serious happens." /> : (
              <ul className="divide-y divide-line/70">
                {hooks.data.map((h) => (
                  <li key={h.id} className="px-4 py-3 flex flex-wrap items-center gap-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2"><b className="text-[13px]">{h.name}</b><Badge>{h.type}</Badge></div>
                      <Mono className="text-faint block truncate">{h.url.replace(/(https?:\/\/[^/]+\/).*/, '$1…')}</Mono>
                      <div className="flex flex-wrap gap-1 mt-1.5">{TRIGGERS.filter(([k]) => h[k]).map(([k, l]) => <Badge key={k} color="#3dd6c6">{l}</Badge>)}</div>
                    </div>
                    {test[h.id] && !test[h.id].busy && <span className={cx('text-xs', test[h.id].success ? 'text-ok' : 'text-crit')}>{test[h.id].message}</span>}
                    <Button size="sm" onClick={() => run(h.id)} disabled={test[h.id]?.busy}><Send size={13} /> Test</Button>
                    <Button size="sm" variant="ghost" onClick={() => del(h.id)} aria-label="Delete webhook"><Trash2 size={13} /></Button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card className="overflow-hidden">
            <CardHeader title="Delivery log" sub="Latest 100 since the server started" />
            {!logs.data || logs.data.length === 0 ? <Empty title="No alerts sent yet" /> : (
              <Table head={<><Th>When</Th><Th>Webhook</Th><Th>Trigger</Th><Th>Source</Th><Th>Result</Th></>}>
                {logs.data.slice(0, 20).map((l, i) => (
                  <Tr key={i}>
                    <Td className="text-mute whitespace-nowrap">{ago(l.ts)}</Td><Td>{l.webhook}</Td><Td>{l.trigger.replace('_', ' ')}</Td>
                    <Td><Mono>{l.src_ip}</Mono></Td>
                    <Td><Badge color={l.ok ? '#3ddc97' : '#ff5d73'}>{l.ok ? 'delivered' : l.message}</Badge></Td>
                  </Tr>
                ))}
              </Table>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
