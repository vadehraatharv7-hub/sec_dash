export const nf = new Intl.NumberFormat('en-US');

export function compact(n) {
  if (n === null || n === undefined || Number.isNaN(n)) return '-';
  const a = Math.abs(n);
  if (a >= 1e9) return (n / 1e9).toFixed(a >= 1e10 ? 0 : 1).replace(/\.0$/, '') + 'B';
  if (a >= 1e6) return (n / 1e6).toFixed(a >= 1e7 ? 0 : 1).replace(/\.0$/, '') + 'M';
  if (a >= 1e4) return (n / 1e3).toFixed(a >= 1e5 ? 0 : 1).replace(/\.0$/, '') + 'k';
  return nf.format(Math.round(n));
}

export function pct(n, d = 0) {
  return `${(n || 0).toFixed(d)}%`;
}

export function duration(sec) {
  if (!sec || sec < 1) return '<1s';
  sec = Math.round(sec);
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  if (m < 60) return `${m}m ${sec % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function ago(iso) {
  if (!iso) return '-';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 0) return 'just now';
  if (s < 45) return 'just now';
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  if (s < 86400 * 30) return `${Math.round(s / 86400)}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function clock(iso, withDate = false) {
  if (!iso) return '-';
  const d = new Date(iso);
  const t = d.toLocaleTimeString('en-GB', { hour12: false });
  if (!withDate) return t;
  return `${d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })} ${t}`;
}

export function bytes(n) {
  if (!n) return '-';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

export function flag(code) {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 127397 + c.charCodeAt(0)));
}

export function delta(cur, prev) {
  if (prev === null || prev === undefined) return null;
  if (prev === 0) return cur === 0 ? 0 : null;
  return ((cur - prev) / prev) * 100;
}

export function bucketLabel(t, bucketSeconds) {
  const d = new Date(t * 1000);
  if (bucketSeconds >= 86400) return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
  if (bucketSeconds >= 3600 * 3) return `${d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })} ${String(d.getHours()).padStart(2, '0')}:00`;
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });
}

export function copy(text) {
  try { return navigator.clipboard.writeText(text); } catch { return Promise.resolve(); }
}
