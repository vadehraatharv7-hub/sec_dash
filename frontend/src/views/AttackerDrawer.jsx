import { useState } from 'react';
import { Ban, ExternalLink, ShieldCheck } from 'lucide-react';
import { api } from '../lib/api';
import { go, useApi } from '../lib/hooks';
import { ago, clock, duration, nf } from '../lib/format';
import { CATEGORIES, CLASSES, OUTCOMES, SERIES } from '../lib/theme';
import { StackedBars } from '../ui/charts';
import {
  Badge, Button, Chips, Country, CopyButton, Drawer, ErrorBox, Mono, RiskPill, Skeleton, Stat, cx,
} from '../ui/primitives';

function Section({ title, children, right }) {
  return (
    <section className="mt-5">
      <div className="flex items-center justify-between mb-2">
        <h4 className="text-[11px] uppercase tracking-wider text-mute font-medium">{title}</h4>
        {right}
      </div>
      {children}
    </section>
  );
}

export function TechChips({ techs, max = 10 }) {
  if (!techs?.length) return <span className="text-xs text-faint">None observed</span>;
  return (
    <Chips items={techs} max={max} render={(t) => (
      <Badge key={t.id} color="#8aa4d6" title={`${t.tactic}: ${t.name}`}>
        <span className="font-mono">{t.id}</span> {t.name}
      </Badge>
    )} />
  );
}

function summarize(a) {
  const cls = CLASSES[a.class]?.label?.toLowerCase() || a.class;
  const where = a.geo?.country_name ? ` from ${a.geo.country_name}` : '';
  const bits = [];
  if (a.failed_logins + a.successful_logins) bits.push(`${nf.format(a.failed_logins + a.successful_logins)} login attempts${a.credential_style ? ` (${a.credential_style})` : ''}`);
  if (a.commands) bits.push(`${nf.format(a.commands)} shell commands`);
  if (a.downloads) bits.push(`${a.downloads} payload download${a.downloads > 1 ? 's' : ''}`);
  if (a.web_requests) bits.push(`${nf.format(a.web_requests)} web requests`);
  const span = (new Date(a.last_seen) - new Date(a.first_seen)) / 1000;
  return `${cls[0].toUpperCase()}${cls.slice(1)}${where}. ${bits.length ? bits.join(', ') + '. ' : ''}Active across ${a.sessions} session${a.sessions === 1 ? '' : 's'}${span > 60 ? ` over ${duration(span)}` : ''}.`;
}

export default function AttackerDrawer({ ip, onClose }) {
  const { data, error, loading, reload } = useApi(ip ? `/attackers/${encodeURIComponent(ip)}` : null, null, { filters: false, enabled: !!ip });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const det = data?.detail;
  const a = det?.attacker;

  const toggleBan = async () => {
    setBusy(true); setErr(null);
    try {
      if (data.banned) await api(`/bans/${ip}`, { method: 'DELETE' });
      else await api('/bans', { method: 'POST', body: { ip, reason: `Banned from SecDash (${CLASSES[a.class]?.label || a.class}, risk ${a.risk})` } });
      reload();
    } catch (e) { setErr(e); } finally { setBusy(false); }
  };

  return (
    <Drawer open={!!ip} onClose={onClose} width={640} title={<Mono className="text-base">{ip}</Mono>}
      subtitle={a ? <span className="flex items-center gap-2"><Country geo={a.geo} />{a.geo?.city && <span>- {a.geo.city}</span>}</span> : null}>
      {!det && loading && <div className="space-y-3"><Skeleton className="h-16" /><Skeleton className="h-40" /><Skeleton className="h-32" /></div>}
      {error && !det && <ErrorBox error={error} onRetry={reload} />}
      {det && a && (
        <div>
          <ErrorBox error={err} />
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <Badge color={CLASSES[a.class]?.color}>{CLASSES[a.class]?.label}</Badge>
            {a.credential_style && <Badge color="#a78bfa">{a.credential_style}</Badge>}
            {data.banned && <Badge color="#ff5d73" solid>Blocked</Badge>}
            <div className="flex-1" />
            <CopyButton text={ip} label="Copy IP" />
            <Button size="sm" variant={data.banned ? 'default' : 'danger'} onClick={toggleBan} disabled={busy}>
              {data.banned ? <><ShieldCheck size={14} /> Unblock</> : <><Ban size={14} /> Block IP</>}
            </Button>
          </div>

          <p className="text-[13px] text-soft leading-relaxed">{summarize(a)}</p>

          <div className="grid grid-cols-4 gap-4 mt-4 rounded-xl border border-line bg-panel p-4">
            <div><div className="text-[11px] uppercase tracking-wider text-mute">Risk</div><div className="mt-1.5"><RiskPill score={a.risk} label={a.risk_label} /></div></div>
            <Stat label="Events" value={nf.format(a.events)} />
            <Stat label="First seen" value={ago(a.first_seen)} />
            <Stat label="Last seen" value={ago(a.last_seen)} />
          </div>

          <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-mute">
            {a.geo?.org && <div>Network: <span className="text-soft">{a.geo.org} {a.geo.asn && `(${a.geo.asn})`}</span></div>}
            <div>Sensors: <span className="text-soft">{a.sensors.join(', ')}</span></div>
            {a.ports?.length > 0 && <div>Ports hit: <span className="text-soft font-mono">{a.ports.join(', ')}</span></div>}
            {a.clients?.length > 0 && <div className="col-span-2 truncate">Client: <span className="text-soft font-mono">{a.clients.join(', ')}</span></div>}
          </div>

          <Section title="Activity">
            <div className="rounded-xl border border-line bg-panel p-2">
              <StackedBars data={det.timeline} series={SERIES} bucketSeconds={det.timeline.length > 1 ? det.timeline[1].t - det.timeline[0].t : 3600} height={110} />
            </div>
          </Section>

          {det.campaign && (
            <Section title="Part of a campaign">
              <button onClick={() => { onClose(); go('/campaigns', { id: det.campaign.id }); }}
                className="w-full text-left rounded-xl border border-violet/30 bg-violet/5 p-3 hover:bg-violet/10">
                <div className="flex items-center justify-between"><b className="text-[13px]">{det.campaign.name}</b><Badge color="#a78bfa">{det.campaign.attackers} IPs</Badge></div>
                <p className="text-xs text-mute mt-1">Linked by {det.campaign.linked_by.join(', ')} across {det.campaign.countries.length} countries.</p>
              </button>
            </Section>
          )}

          <Section title="MITRE ATT&CK techniques"><TechChips techs={a.techniques} /></Section>

          {det.credentials?.length > 0 && (
            <Section title={`Credentials tried (${a.distinct_users} users / ${a.distinct_passwords} passwords)`}>
              <div className="rounded-xl border border-line overflow-hidden">
                <table className="w-full text-xs">
                  <tbody className="divide-y divide-line/70">
                    {det.credentials.slice(0, 8).map((c) => (
                      <tr key={c.username + c.password}>
                        <td className="px-3 py-1.5 font-mono">{c.username}</td>
                        <td className="px-3 py-1.5 font-mono text-soft">{c.password || <i className="text-faint">empty</i>}</td>
                        <td className="px-3 py-1.5 text-right num text-mute">{c.count}x</td>
                        <td className="px-3 py-1.5 text-right">{c.success > 0 && <Badge color="#3ddc97">accepted</Badge>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}

          {det.commands?.length > 0 && (
            <Section title="Commands run">
              <ul className="space-y-1.5">
                {det.commands.slice(0, 8).map((c) => (
                  <li key={c.command} className="flex items-start gap-2 rounded-lg bg-panel border border-line px-3 py-2">
                    <Badge color={CATEGORIES[c.category]?.color}>{CATEGORIES[c.category]?.label || c.category}</Badge>
                    <Mono className="break-all flex-1 text-soft">{c.sample}</Mono>
                    {c.count > 1 && <span className="text-xs text-mute num">{c.count}x</span>}
                  </li>
                ))}
              </ul>
            </Section>
          )}

          {det.paths?.length > 0 && (
            <Section title="Web requests">
              <ul className="space-y-1">
                {det.paths.slice(0, 8).map((p) => (
                  <li key={p.value} className="flex justify-between gap-3 text-xs rounded-lg bg-panel border border-line px-3 py-1.5">
                    <Mono className="truncate text-soft">{p.value}</Mono><span className="num text-mute">{p.count}x</span>
                  </li>
                ))}
              </ul>
            </Section>
          )}

          <Section title={`Sessions (${a.sessions})`}>
            <ul className="space-y-1.5">
              {det.sessions.slice(0, 12).map((s) => (
                <li key={s.id}>
                  <button onClick={() => { onClose(); go(`/sessions/${s.id}`); }}
                    className="w-full flex items-center gap-3 rounded-lg border border-line bg-panel px-3 py-2 text-left hover:bg-panel2">
                    <Badge color={OUTCOMES[s.outcome]?.color}>{OUTCOMES[s.outcome]?.label}</Badge>
                    <span className="text-xs text-mute num flex-1">{clock(s.start, true)}</span>
                    <span className="text-xs text-mute num">{duration(s.duration)}</span>
                  </button>
                </li>
              ))}
            </ul>
          </Section>

          <Section title="Look up elsewhere">
            <div className="flex flex-wrap gap-3 text-xs">
              {[['AbuseIPDB', `https://www.abuseipdb.com/check/${ip}`], ['VirusTotal', `https://www.virustotal.com/gui/ip-address/${ip}`], ['Shodan', `https://www.shodan.io/host/${ip}`], ['GreyNoise', `https://viz.greynoise.io/ip/${ip}`]].map(([n, u]) => (
                <a key={n} href={u} target="_blank" rel="noreferrer noopener" className={cx('inline-flex items-center gap-1 text-accent hover:underline')}>{n}<ExternalLink size={11} /></a>
              ))}
            </div>
          </Section>
        </div>
      )}
    </Drawer>
  );
}
