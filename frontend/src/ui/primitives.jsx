import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, Check, Copy, Inbox, Search, X } from 'lucide-react';
import { copy as copyText, flag } from '../lib/format';
import { RISK, riskColor } from '../lib/theme';

export const cx = (...a) => a.filter(Boolean).join(' ');

export function Card({ className, children, ...rest }) {
  return <section className={cx('min-w-0 rounded-xl border border-line bg-panel', className)} {...rest}>{children}</section>;
}

export function CardHeader({ title, sub, right, className }) {
  return (
    <header className={cx('flex items-start justify-between gap-3 px-4 pt-3.5 pb-2', className)}>
      <div className="min-w-0">
        <h3 className="text-[13px] font-semibold text-ink tracking-tight">{title}</h3>
        {sub && <p className="text-xs text-mute mt-0.5">{sub}</p>}
      </div>
      {right && <div className="flex items-center gap-2 shrink-0">{right}</div>}
    </header>
  );
}

export function PageHeader({ title, sub, right }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 mb-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {sub && <p className="text-sm text-mute mt-0.5 max-w-3xl">{sub}</p>}
      </div>
      {right && <div className="flex items-center gap-2 flex-wrap">{right}</div>}
    </div>
  );
}

export function Badge({ color = '#7d8ba3', children, className, title, solid }) {
  return (
    <span
      title={title}
      className={cx('inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium leading-4 whitespace-nowrap', className)}
      style={solid
        ? { background: color, color: '#08101a' }
        : { background: `color-mix(in srgb, ${color} 14%, transparent)`, color, boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${color} 28%, transparent)` }}
    >
      {children}
    </span>
  );
}

export function RiskPill({ score, label }) {
  const c = riskColor(score);
  const name = label ? RISK[label]?.label : null;
  return (
    <span className="inline-flex items-center gap-1.5 num">
      <span className="inline-block h-1.5 w-8 rounded-full bg-line2 overflow-hidden">
        <span className="block h-full rounded-full" style={{ width: `${Math.max(6, score)}%`, background: c }} />
      </span>
      <span className="text-xs font-medium" style={{ color: c }}>{score}</span>
      {name && <span className="text-[11px] text-mute hidden xl:inline">{name}</span>}
    </span>
  );
}

export function Country({ geo, short }) {
  if (!geo?.country_code) return <span className="text-faint">Unknown</span>;
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span aria-hidden>{flag(geo.country_code)}</span>
      <span>{short ? geo.country_code : geo.country_name}</span>
    </span>
  );
}

export function Mono({ children, className, ...rest }) {
  return <span className={cx('font-mono text-[12px]', className)} {...rest}>{children}</span>;
}

export function IPLink({ ip, onClick, className }) {
  if (!ip) return <span className="text-faint">unknown</span>;
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); onClick?.(ip); }}
      className={cx('font-mono text-[12px] text-accent hover:underline underline-offset-2', className)}
    >
      {ip}
    </button>
  );
}

export function CopyButton({ text, className, label }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      title="Copy"
      onClick={(e) => { e.stopPropagation(); copyText(text); setDone(true); setTimeout(() => setDone(false), 1200); }}
      className={cx('inline-flex items-center gap-1 text-mute hover:text-ink transition-colors', className)}
    >
      {done ? <Check size={13} className="text-ok" /> : <Copy size={13} />}
      {label && <span className="text-xs">{done ? 'Copied' : label}</span>}
    </button>
  );
}

export function Button({ variant = 'default', size = 'md', className, children, ...rest }) {
  const v = {
    default: 'bg-panel2 border-line2 text-ink hover:bg-raised',
    primary: 'bg-accent text-[#04201d] border-accent hover:brightness-110 font-semibold',
    danger: 'bg-crit/10 border-crit/40 text-crit hover:bg-crit/20',
    ghost: 'border-transparent text-soft hover:bg-panel2 hover:text-ink',
  }[variant];
  const s = size === 'sm' ? 'h-7 px-2.5 text-xs' : 'h-8 px-3 text-[13px]';
  return (
    <button
      {...rest}
      className={cx('inline-flex items-center justify-center gap-1.5 rounded-lg border transition-colors', v, s, className)}
    >
      {children}
    </button>
  );
}

export function Segmented({ value, onChange, options, size = 'md' }) {
  return (
    <div className="inline-flex max-w-full overflow-x-auto rounded-lg border border-line bg-panel p-0.5" role="tablist">
      {options.map((o) => (
        <button
          key={o.id}
          role="tab"
          aria-selected={value === o.id}
          onClick={() => onChange(o.id)}
          className={cx(
            'rounded-md font-medium transition-colors num',
            size === 'sm' ? 'px-2 h-6 text-[11px]' : 'px-2.5 h-7 text-xs',
            value === o.id ? 'bg-raised text-ink shadow-sm' : 'text-mute hover:text-soft',
          )}
        >
          {o.label}
          {o.count !== undefined && <span className="ml-1.5 text-faint">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Select({ value, onChange, options, className, 'aria-label': aria }) {
  return (
    <select
      aria-label={aria}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={cx('h-8 rounded-lg border border-line bg-panel px-2.5 text-[13px] text-ink hover:border-line2', className)}
    >
      {options.map((o) => <option key={o.id} value={o.id}>{o.label}</option>)}
    </select>
  );
}

export function SearchInput({ value, onChange, placeholder, className }) {
  return (
    <label className={cx('relative block', className)}>
      <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="h-8 w-full rounded-lg border border-line bg-panel pl-8 pr-7 text-[13px] placeholder:text-faint hover:border-line2 focus:border-accent/60 focus:outline-none"
      />
      {value && (
        <button type="button" onClick={() => onChange('')} className="absolute right-2 top-1/2 -translate-y-1/2 text-faint hover:text-ink" aria-label="Clear">
          <X size={13} />
        </button>
      )}
    </label>
  );
}

export function Skeleton({ className }) {
  return <div className={cx('skeleton', className)} />;
}

export function Empty({ title = 'Nothing here yet', hint, icon: Icon = Inbox }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-10 px-4">
      <Icon size={22} className="text-faint mb-2" />
      <p className="text-sm text-soft">{title}</p>
      {hint && <p className="text-xs text-mute mt-1 max-w-sm">{hint}</p>}
    </div>
  );
}

export function ErrorBox({ error, onRetry }) {
  if (!error) return null;
  return (
    <div className="flex items-center gap-3 rounded-lg border border-crit/30 bg-crit/10 px-3 py-2 text-sm text-crit">
      <AlertTriangle size={16} />
      <span className="flex-1">{error.message || 'Request failed'}</span>
      {onRetry && <Button size="sm" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function Drawer({ open, onClose, title, subtitle, children, width = 560 }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const onKey = (e) => e.key === 'Escape' && onClose();
    document.addEventListener('keydown', onKey);
    ref.current?.focus();
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/55 backdrop-blur-[2px]" onClick={onClose} />
      <aside
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-label={title}
        className="drawer-in absolute right-0 top-0 h-full max-w-full bg-bg border-l border-line2 shadow-2xl flex flex-col outline-none"
        style={{ width }}
      >
        <header className="flex items-start justify-between gap-3 px-5 py-4 border-b border-line">
          <div className="min-w-0">
            <h2 className="text-base font-semibold truncate">{title}</h2>
            {subtitle && <div className="text-xs text-mute mt-0.5">{subtitle}</div>}
          </div>
          <button onClick={onClose} className="text-mute hover:text-ink p-1 -m-1" aria-label="Close"><X size={18} /></button>
        </header>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </aside>
    </div>
  );
}

export function Stat({ label, value, sub, color }) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wider text-mute">{label}</div>
      <div className="text-lg font-semibold num" style={color ? { color } : undefined}>{value}</div>
      {sub && <div className="text-xs text-mute">{sub}</div>}
    </div>
  );
}

export function Th({ children, className, align }) {
  return (
    <th className={cx('px-3 py-2 text-[11px] font-medium uppercase tracking-wider text-mute whitespace-nowrap', align === 'right' ? 'text-right' : 'text-left', className)}>
      {children}
    </th>
  );
}

export function Table({ head, children, className }) {
  return (
    <div className={cx('overflow-x-auto', className)}>
      <table className="w-full text-[13px]">
        <thead className="border-b border-line"><tr>{head}</tr></thead>
        <tbody className="divide-y divide-line/70">{children}</tbody>
      </table>
    </div>
  );
}

export function Tr({ onClick, children, className }) {
  return (
    <tr
      onClick={onClick}
      className={cx('transition-colors', onClick && 'cursor-pointer hover:bg-panel2', className)}
    >
      {children}
    </tr>
  );
}

export const Td = ({ children, className, align }) => (
  <td className={cx('px-3 py-2 align-middle', align === 'right' && 'text-right num', className)}>{children}</td>
);

export function Pager({ total, offset, limit, onChange }) {
  if (total <= limit) return null;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.ceil(total / limit);
  return (
    <div className="flex items-center justify-between px-3 py-2 border-t border-line text-xs text-mute">
      <span className="num">{offset + 1}-{Math.min(total, offset + limit)} of {total}</span>
      <div className="flex gap-1.5 items-center">
        <Button size="sm" variant="ghost" disabled={page <= 1} onClick={() => onChange(Math.max(0, offset - limit))}>Prev</Button>
        <span className="num">{page}/{pages}</span>
        <Button size="sm" variant="ghost" disabled={page >= pages} onClick={() => onChange(offset + limit)}>Next</Button>
      </div>
    </div>
  );
}

export function Chips({ items, render, max = 8 }) {
  const shown = items.slice(0, max);
  return (
    <div className="flex flex-wrap gap-1.5">
      {shown.map(render)}
      {items.length > max && <span className="text-xs text-mute self-center">+{items.length - max}</span>}
    </div>
  );
}
