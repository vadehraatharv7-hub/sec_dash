import { useApi } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { compact, flag } from '../lib/format';
import { BarList } from '../ui/charts';
import GeoMap from '../ui/GeoMap';
import { Card, CardHeader, Empty, ErrorBox, PageHeader, Skeleton } from '../ui/primitives';

export default function ThreatMap() {
  const { data, error, reload } = useApi('/geo', null, { interval: 30000 });
  const { openIP } = useUi();
  return (
    <div className="space-y-4">
      <PageHeader title="Threat Map" sub="Where the traffic hitting your sensors originates. Click a bubble to open the riskiest attacker at that location." />
      <ErrorBox error={error} onRetry={reload} />
      <div className="grid gap-4 xl:grid-cols-[1fr_340px]">
        <Card className="p-2">
          {!data ? <Skeleton className="h-[560px]" /> : data.points.length === 0
            ? <Empty title="No located attackers in this window" hint="Locations resolve shortly after an IP is first seen." />
            : <GeoMap points={data.points} height={560} onSelect={(p) => p.top_ip && openIP(p.top_ip)} />}
        </Card>
        <Card>
          <CardHeader title="Countries" sub={data ? `${data.countries.length} shown` : ''} />
          <div className="px-3 pb-3 max-h-[540px] overflow-y-auto">
            <BarList
              items={(data?.countries || []).map((c) => ({
                key: c.code, label: <span><span className="mr-2">{flag(c.code)}</span>{c.name}</span>, value: c.events, sub: `${c.attackers} IPs`,
              }))}
              format={compact}
            />
          </div>
        </Card>
      </div>
    </div>
  );
}
