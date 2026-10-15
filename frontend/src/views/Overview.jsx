import { useMemo } from 'react';
import { ArrowDownRight, ArrowUpRight, ChevronRight, Info, ShieldAlert, TriangleAlert } from 'lucide-react';
import { go, useApi, useFilters } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { compact, delta, duration, flag, nf, pct } from '../lib/format';
import { CLASSES, SERIES } from '../lib/theme';
import { BarList, Donut, Funnel, Heatmap, Legend, Sparkline, StackedBars } from '../ui/charts';
import GeoMap from '../ui/GeoMap';
import {
  Badge, Card, CardHeader, Country, Empty, ErrorBox, IPLink, PageHeader, RiskPill, Skeleton, Table, Td, Th, Tr, cx,
} from '../ui/primitives';

function Delta({ cur, prev, inverse }) {
  const d = delta(cur, prev);
  if (d === null) return <span className="text-[11px] text-faint">no baseline</span>;
  if (Math.abs(d) < 0.5) return <span className="text-[11px] text-faint">flat vs prev.</span>;
  const up = d > 0;
  const bad = inverse ? !up : up;
  const Icon = up ? ArrowUpRight : ArrowDownRight;
  return (
    <span className={cx('inline-flex items-center gap-0.5 text-[11px] num font-medium', bad ? 'text-high' : 'text-ok')}>
      <Icon size={12} />{Math.abs(d) >= 1000 ? '>999' : Math.abs(d).toFixed(0)}%
      <span className="text-faint font-normal ml-1">vs prev.</span>
    </span>
  );
}

function Kpi({ label, kpi, spark, color, to, hint, format = compact, inverse }) {
  const v = kpi?.value ?? 0;
  const body = (
    <>
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-wider text-mute">{label}</span>
        {hint && <span title={hint} className="text-faint"><Info size={12} /></span>}
      </div>
      <div className="flex items-end justify-between gap-2 mt-1.5">
        <div>
          <div className="text-[26px] leading-8 font-semibold num" style={{ color }}>{format(v)}</div>
          <div className="mt-1"><Delta cur={v} prev={kpi?.prev} inverse={inverse} /></div>
        </div>
        <Sparkline values={spark} color={color || 'var(--color-accent)'} />
      </div>
    </>
  );
  return to ? (
    <a href={`#${to}`} className="block rounded-xl border border-line bg-panel p-3.5 hover:border-line2 hover:bg-panel2/50 transition-colors">{body}</a>
  ) : <div className="rounded-xl border border-line bg-panel p-3.5">{body}</div>;
}

const SEV = {
  critical: { c: '#ff5d73', Icon: ShieldAlert },
  warn: { c: '#f5c451', Icon: TriangleAlert },
  info: { c: '#5aa9ff', Icon: Info },
};

function Insights({ items }) {
  const nav = (i) => {
    if (!i.view) return;
    const q = Object.fromEntries(new URLSearchParams(i.query || ''));
    go(`/${i.view}`, q);
  };
  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {items.slice(0, 4).map((i) => {
        const s = SEV[i.severity] || SEV.info;
        return (
          <button
            key={i.title}
            onClick={() => nav(i)}
            disabled={!i.view}
            className="text-left rounded-xl border bg-panel p-3.5 hover:bg-panel2/60 transition-colors disabled:cursor-default"
            style={{ borderColor: `color-mix(in srgb, ${s.c} 35%, var(--color-line))` }}
          >
            <div className="flex items-start gap-2.5">
              <s.Icon size={16} style={{ color: s.c }} className="mt-0.5 shrink-0" />
              <div className="min-w-0">
                <div className="text-[13px] font-semibold leading-snug">{i.title}</div>
                <p className="text-xs text-mute mt-1 leading-relaxed">{i.detail}</p>
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}

export default function Overview() {
  const { data, error, loading, reload } = useApi('/overview', null, { interval: 15000 });
  const { data: geo } = useApi('/geo', null, { interval: 60000 });
  const { openIP } = useUi();
  const { sensor } = useFilters();

  const spark = useMemo(() => {
    const tl = data?.timeline || [];
    const pick = (f) => tl.map(f);
    return {
      events: pick((b) => b.total),
      attackers: pick((b) => b.connect + b.failed + b.web),
      compromises: pick((b) => b.success),
      payloads: pick((b) => b.malware),
      commands: pick((b) => b.command),
      sessions: pick((b) => b.connect + b.web),
    };
  }, [data]);

  if (!data) {
    return (
      <div className="space-y-4">
        <PageHeader title="Command Center" />
        <ErrorBox error={error} onRetry={reload} />
        <div className="grid gap-3 grid-cols-2 xl:grid-cols-6">{Array.from({ length: 6 }, (_, i) => <Skeleton key={i} className="h-[92px]" />)}</div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  const k = data.kpis;
  const o = data.outcomes || {};
  const cow = (o.scan || 0) + (o.brute_force || 0) + (o.login_only || 0) + (o.intrusion || 0) + (o.malware || 0);
  const authd = (o.brute_force || 0) + (o.login_only || 0) + (o.intrusion || 0) + (o.malware || 0);
  const comp = (o.login_only || 0) + (o.intrusion || 0) + (o.malware || 0);
  const exec = (o.intrusion || 0) + (o.malware || 0);
  const funnel = [
    { label: 'Sessions opened', value: cow, color: '#4a6a92' },
    { label: 'Tried to authenticate', value: authd, color: '#a78bfa' },
    { label: 'Got in', value: comp, color: '#f5c451' },
    { label: 'Ran commands', value: exec, color: '#ff9a4d' },
    { label: 'Dropped a payload', value: o.malware || 0, color: '#ff5d73' },
  ];
  const classSlices = Object.entries(data.classes || {})
    .map(([id, v]) => ({ label: CLASSES[id]?.label || id, value: v, color: CLASSES[id]?.color || '#7d8ba3' }))
    .sort((a, b) => b.value - a.value);
  const empty = k.events.value === 0;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Command Center"
        sub={sensor === 'all' ? 'Everything your honeypots saw in the selected window.' : `Activity on sensor ${sensor}.`}
        right={loading && <span className="text-xs text-faint">Refreshing...</span>}
      />
      <ErrorBox error={error} onRetry={reload} />

      <div className="grid gap-3 grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6">
        <Kpi label="Events" kpi={k.events} spark={spark.events} to="/live" />
        <Kpi label="Unique attackers" kpi={k.attackers} spark={spark.attackers} color="#5aa9ff" to="/attackers" />
        <Kpi label="Sessions" kpi={k.sessions} spark={spark.sessions} to="/sessions" />
        <Kpi label="Successful logins" kpi={k.login_success} spark={spark.compromises} color="#f5c451" to="/sessions?outcome=login_only,intrusion,malware" hint="Attackers that authenticated against a honeypot" />
        <Kpi label="Payloads captured" kpi={k.downloads} spark={spark.payloads} color="#ff5d73" to="/malware" />
        <Kpi label="High-risk attackers" kpi={k.high_risk_attackers} spark={spark.commands} color="#ff9a4d" to="/attackers?min_risk=60" hint="Risk score 60 or above" />
      </div>

      {empty ? (
        <Card><Empty title="No events in this window" hint="Widen the time range, or check that your sensors are shipping logs (Sensors page)." /></Card>
      ) : (
        <>
          <Insights items={data.insights} />

          <div className="grid gap-4 xl:grid-cols-3">
            <Card className="xl:col-span-2">
              <CardHeader title="Activity over time" sub="Events per interval, by type" />
              <Legend series={SERIES} className="px-4 pb-1" />
              <div className="px-2 pb-3"><StackedBars data={data.timeline} series={SERIES} bucketSeconds={data.bucket_seconds} /></div>
            </Card>
            <Card>
              <CardHeader title="How far did they get?" sub="Cowrie sessions by deepest stage reached" />
              <div className="px-4 pb-4"><Funnel steps={funnel} /></div>
              <div className="px-4 pb-4 pt-1 grid grid-cols-2 gap-3 border-t border-line mt-1">
                <div>
                  <div className="text-[11px] uppercase tracking-wider text-mute mt-3">Compromise rate</div>
                  <div className="text-lg font-semibold num">{pct(k.compromise_rate.value, 1)}</div>
                  <div className="text-[11px] text-faint">of sessions that tried to log in</div>
                </div>
                <div>
                  <div className="text-[11px] uppercase tracking-wider text-mute mt-3">Avg. dwell time</div>
                  <div className="text-lg font-semibold num">{duration(k.avg_session_seconds.value)}</div>
                  <div className="text-[11px] text-faint">per SSH/Telnet session</div>
                </div>
              </div>
            </Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Card className="xl:col-span-2">
              <CardHeader title="Where attacks come from" sub="Bubble size = events, colour = highest risk at that location"
                right={<a href="#/map" className="text-xs text-accent hover:underline inline-flex items-center">Full map <ChevronRight size={13} /></a>} />
              <div className="px-3 pb-3">
                {geo?.points?.length
                  ? <GeoMap points={geo.points} height={320} onSelect={(p) => p.top_ip && openIP(p.top_ip)} />
                  : <Empty title="No located attackers yet" hint="Locations are resolved shortly after an IP is first seen." />}
              </div>
            </Card>
            <Card>
              <CardHeader title="Top source countries" />
              <div className="px-3 pb-3">
                <BarList
                  items={data.countries.slice(0, 9).map((c) => ({
                    key: c.code, label: <span><span className="mr-2">{flag(c.code)}</span>{c.name}</span>, value: c.events, sub: `${c.attackers} IPs`,
                  }))}
                  empty="Waiting for geolocation..."
                />
              </div>
            </Card>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Card className="xl:col-span-2">
              <CardHeader title="Highest-risk attackers" right={<a href="#/attackers" className="text-xs text-accent hover:underline inline-flex items-center">All attackers <ChevronRight size={13} /></a>} />
              <Table head={<><Th>Source</Th><Th>Origin</Th><Th>Behaviour</Th><Th>Sessions</Th><Th>Risk</Th></>}>
                {data.top_attackers.map((a) => (
                  <Tr key={a.ip} onClick={() => openIP(a.ip)}>
                    <Td><IPLink ip={a.ip} onClick={openIP} /></Td>
                    <Td><Country geo={a.geo} short /></Td>
                    <Td><Badge color={CLASSES[a.class]?.color}>{CLASSES[a.class]?.label || a.class}</Badge></Td>
                    <Td className="num">{a.sessions}</Td>
                    <Td><RiskPill score={a.risk} label={a.risk_label} /></Td>
                  </Tr>
                ))}
              </Table>
            </Card>
            <div className="space-y-4">
              <Card>
                <CardHeader title="Attacker profiles" sub="By most serious behaviour observed" />
                <div className="px-4 pb-4">
                  <Donut slices={classSlices} center={<><div className="text-xl font-semibold num">{nf.format(k.attackers.value)}</div><div className="text-[10px] uppercase tracking-wider text-mute">attackers</div></>} />
                </div>
              </Card>
            </div>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Card>
              <CardHeader title="Targeted ports" />
              <div className="px-3 pb-3">
                <BarList items={data.ports.slice(0, 7).map((p) => ({ key: p.port, label: `:${p.port}`, value: p.events }))} mono />
              </div>
            </Card>
            <Card>
              <CardHeader title="Top networks" sub="Hosting providers and ISPs" />
              <div className="px-3 pb-3">
                <BarList
                  items={data.orgs.slice(0, 7).map((p) => ({ key: p.asn, label: p.org || p.asn, value: p.events, sub: p.asn }))}
                  empty="ASN data appears once IPs are resolved."
                />
              </div>
            </Card>
            <Card>
              <CardHeader title="When they strike" sub="Activity by weekday and hour" />
              <div className="px-4 pb-4"><Heatmap matrix={data.heatmap} /></div>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
