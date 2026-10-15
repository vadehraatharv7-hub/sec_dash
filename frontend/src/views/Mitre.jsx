import { go, useApi } from '../lib/hooks';
import { nf } from '../lib/format';
import { Card, CardHeader, ErrorBox, PageHeader, Skeleton, cx } from '../ui/primitives';

export default function Mitre() {
  const { data, error, reload } = useApi('/mitre', null, { interval: 60000 });
  if (!data) return <div className="space-y-4"><PageHeader title="ATT&CK Coverage" /><ErrorBox error={error} onRetry={reload} /><Skeleton className="h-96" /></div>;
  const max = Math.max(1, ...data.flatMap((c) => c.techniques.map((t) => t.sessions)));
  const seen = data.reduce((n, c) => n + c.techniques.length, 0);
  return (
    <div className="space-y-4">
      <PageHeader title="ATT&CK Coverage" sub={`${seen} MITRE ATT&CK techniques observed. Brighter cells mean more sessions. Click a technique to see the sessions.`} />
      <Card className="p-3 overflow-x-auto">
        <div className="grid gap-2 min-w-[1000px]" style={{ gridTemplateColumns: `repeat(${data.length}, minmax(0, 1fr))` }}>
          {data.map((col) => (
            <div key={col.tactic} className="min-w-0">
              <div className="rounded-md bg-panel2 px-2 py-1.5 mb-2 text-center">
                <div className="text-[11px] font-semibold leading-tight">{col.tactic}</div>
                <div className="text-[10px] text-faint">{col.techniques.length} technique{col.techniques.length === 1 ? '' : 's'}</div>
              </div>
              <div className="space-y-1.5">
                {col.techniques.length === 0 && <div className="text-center text-[11px] text-faint/60 py-3">-</div>}
                {col.techniques.map((t) => {
                  const f = t.sessions / max;
                  return (
                    <button key={t.id} onClick={() => go('/sessions', { technique: t.id })}
                      title={`${t.id} ${t.name}\n${nf.format(t.sessions)} sessions from ${t.attackers} IPs`}
                      className={cx('w-full text-left rounded-md border px-2 py-1.5 transition hover:brightness-125')}
                      style={{ background: `color-mix(in srgb, var(--color-accent) ${Math.round(8 + f * 40)}%, var(--color-panel))`, borderColor: `color-mix(in srgb, var(--color-accent) ${Math.round(15 + f * 45)}%, var(--color-line))` }}>
                      <div className="text-[11px] font-medium leading-tight">{t.name}</div>
                      <div className="flex justify-between text-[10px] text-mute mt-0.5"><span className="font-mono">{t.id}</span><span className="num">{nf.format(t.sessions)}</span></div>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <CardHeader title="How this is derived" />
        <p className="px-4 pb-4 text-xs text-mute leading-relaxed max-w-3xl">
          Techniques are inferred from observed behaviour: login patterns (T1110, T1078), each shell command (discovery, ingress tool transfer, persistence, evasion) and web-request signatures (T1190, T1595). Mapping is rule-based, so treat it as triage context, not forensic proof.
        </p>
      </Card>
    </div>
  );
}
