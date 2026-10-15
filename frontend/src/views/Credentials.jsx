import { useApi } from '../lib/hooks';
import { useUi } from '../lib/ui';
import { nf, pct } from '../lib/format';
import { BarList, Donut, MiniBars } from '../ui/charts';
import { Badge, Card, CardHeader, Empty, ErrorBox, IPLink, Mono, PageHeader, Skeleton, Stat, Table, Td, Th, Tr } from '../ui/primitives';

const STYLE_COLORS = { 'credential stuffing': '#ff5d73', 'password spraying': '#ff9a4d', 'dictionary brute force': '#a78bfa', 'mixed guessing': '#5aa9ff', 'low-volume guessing': '#7d8ba3' };

export default function Credentials() {
  const { data, error, reload } = useApi('/credentials', { limit: 15 }, { interval: 30000 });
  const { openIP } = useUi();
  if (!data) return <div className="space-y-4"><PageHeader title="Credentials" /><ErrorBox error={error} onRetry={reload} /><Skeleton className="h-72" /></div>;
  const none = data.attempts === 0;
  return (
    <div className="space-y-4">
      <PageHeader title="Credentials" sub="What attackers try when they hit your SSH and Telnet honeypots - and which guesses actually got in." />
      <Card className="px-5 py-4 grid grid-cols-2 md:grid-cols-5 gap-5">
        <Stat label="Login attempts" value={nf.format(data.attempts)} />
        <Stat label="Unique pairs" value={nf.format(data.unique_pairs)} />
        <Stat label="Unique usernames" value={nf.format(data.unique_users)} />
        <Stat label="Unique passwords" value={nf.format(data.unique_passwords)} />
        <Stat label="Default credentials" value={pct(data.default_pct, 1)} sub="of all attempts" color={data.default_pct > 25 ? '#ff9a4d' : undefined} />
      </Card>
      {none ? <Card><Empty title="No login attempts in this window" /></Card> : (
        <>
          {data.successful.length > 0 && (
            <Card className="border-med/30">
              <CardHeader title="Credentials that worked" sub="Accepted by the honeypot - these are the guesses real servers would have fallen to" />
              <Table head={<><Th>Username</Th><Th>Password</Th><Th align="right">Times accepted</Th><Th align="right">Distinct IPs</Th><Th /></>}>
                {data.successful.slice(0, 8).map((p) => (
                  <Tr key={p.username + p.password}>
                    <Td><Mono>{p.username}</Mono></Td><Td><Mono>{p.password || <i className="text-faint">empty</i>}</Mono></Td>
                    <Td align="right">{p.success}</Td><Td align="right">{p.ips}</Td>
                    <Td>{p.is_default && <Badge color="#ff9a4d">default</Badge>}</Td>
                  </Tr>
                ))}
              </Table>
            </Card>
          )}
          <div className="grid gap-4 lg:grid-cols-3">
            <Card><CardHeader title="Top usernames" /><div className="px-3 pb-3"><BarList mono items={data.usernames.slice(0, 12).map((u) => ({ key: u.value, label: u.value || '(empty)', value: u.count, sub: `${u.ips} IPs` }))} /></div></Card>
            <Card><CardHeader title="Top passwords" /><div className="px-3 pb-3"><BarList mono color="#a78bfa" items={data.passwords.slice(0, 12).map((u) => ({ key: u.value, label: u.value || '(empty)', value: u.count, sub: `${u.ips} IPs` }))} /></div></Card>
            <Card>
              <CardHeader title="Attack style" sub="How each IP is guessing" />
              <div className="px-4 pb-4"><Donut size={120} thickness={16} slices={Object.entries(data.styles).map(([k, v]) => ({ label: k, value: v, color: STYLE_COLORS[k] || '#7d8ba3' }))} /></div>
              <div className="px-4 pb-4 border-t border-line pt-3">
                <div className="text-[11px] uppercase tracking-wider text-mute mb-2">Password length</div>
                <MiniBars items={data.password_lengths.map((l) => ({ label: l.label, value: l.count }))} color="#a78bfa" />
              </div>
            </Card>
          </div>
          <Card className="overflow-hidden">
            <CardHeader title="Most-tried pairs" />
            <Table head={<><Th>Username</Th><Th>Password</Th><Th align="right">Attempts</Th><Th align="right">Distinct IPs</Th><Th align="right">Accepted</Th><Th /></>}>
              {data.pairs.map((p) => (
                <Tr key={p.username + p.password}>
                  <Td><Mono>{p.username}</Mono></Td><Td><Mono>{p.password || <i className="text-faint">empty</i>}</Mono></Td>
                  <Td align="right">{nf.format(p.count)}</Td><Td align="right">{p.ips}</Td><Td align="right">{p.success || '-'}</Td>
                  <Td>{p.is_default && <Badge color="#ff9a4d">default</Badge>}</Td>
                </Tr>
              ))}
            </Table>
          </Card>
          {data.top_sources?.length > 0 && (
            <Card className="overflow-hidden">
              <CardHeader title="Heaviest guessers" sub="IPs with the most login attempts" />
              <Table head={<><Th>Source</Th><Th>Style</Th><Th align="right">Attempts</Th><Th align="right">Users</Th><Th align="right">Passwords</Th></>}>
                {data.top_sources.map((a) => (
                  <Tr key={a.ip} onClick={() => openIP(a.ip)}>
                    <Td><IPLink ip={a.ip} onClick={openIP} /></Td>
                    <Td><Badge color={STYLE_COLORS[a.credential_style]}>{a.credential_style}</Badge></Td>
                    <Td align="right">{nf.format(a.failed_logins + a.successful_logins)}</Td>
                    <Td align="right">{a.distinct_users}</Td><Td align="right">{a.distinct_passwords}</Td>
                  </Tr>
                ))}
              </Table>
            </Card>
          )}
        </>
      )}
    </div>
  );
}
