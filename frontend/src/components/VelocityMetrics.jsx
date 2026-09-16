import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Terminal, 
  Key, 
  Server, 
  Clock, 
  AlertTriangle,
  TrendingUp,
  Cpu
} from 'lucide-react';

export default function VelocityMetrics({ stats }) {
  if (!stats) return null;

  const compromiseRatio = stats.compromise_ratio !== undefined 
    ? stats.compromise_ratio.toFixed(1) 
    : '0.0';

  const avgDuration = stats.avg_session_duration 
    ? `${stats.avg_session_duration.toFixed(1)}s` 
    : '< 1s';

  const metrics = [
    {
      title: 'TOTAL ATTACK EVENTS',
      value: stats.total_events?.toLocaleString() || '0',
      subtitle: 'Intercepted honeypot triggers',
      badge: 'THROUGHPUT: HIGH',
      badgeColor: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
      icon: ShieldAlert,
      iconColor: 'text-cyan-400',
    },
    {
      title: 'COMPROMISE RATIO',
      value: `${compromiseRatio}%`,
      subtitle: `${stats.successful_logins || 0} breached of ${(stats.failed_logins || 0) + (stats.successful_logins || 0)} attempts`,
      badge: Number(compromiseRatio) > 15 ? 'HIGH EXPOSURE' : 'CONTAINED',
      badgeColor: Number(compromiseRatio) > 15 
        ? 'text-rose-400 bg-rose-500/10 border-rose-500/20' 
        : 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
      icon: AlertTriangle,
      iconColor: 'text-amber-400',
    },
    {
      title: 'ADVERSARY ORIGINS',
      value: stats.unique_attackers?.toLocaleString() || '0',
      subtitle: `${stats.unique_asns || 0} Autonomous Systems (ASNs)`,
      badge: 'ROUTING TRACKED',
      badgeColor: 'text-slate-300 bg-slate-800 border-slate-700',
      icon: Server,
      iconColor: 'text-indigo-400',
    },
    {
      title: 'INTERCEPTED SHELL CMDS',
      value: stats.commands_executed?.toLocaleString() || '0',
      subtitle: 'Commands in honeypot sandbox',
      badge: 'SANDBOXED',
      badgeColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
      icon: Terminal,
      iconColor: 'text-rose-400',
    },
    {
      title: 'CAPTURED LOOT',
      value: stats.files_captured?.toLocaleString() || '0',
      subtitle: 'Dropper binaries & scripts',
      badge: 'PAYLOADS ISOLATED',
      badgeColor: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
      icon: Cpu,
      iconColor: 'text-purple-400',
    },
    {
      title: 'AVG SESSION DWELL',
      value: avgDuration,
      subtitle: 'Adversary connection lifespan',
      badge: 'AUTOMATED PROBING',
      badgeColor: 'text-slate-400 bg-slate-800 border-slate-700',
      icon: Clock,
      iconColor: 'text-slate-400',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {metrics.map((m, idx) => {
        const Icon = m.icon;
        return (
          <div
            key={idx}
            className="rounded-lg bg-[#0b1120] border border-slate-800 p-3.5 flex flex-col justify-between hover:border-slate-700 transition-colors"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider font-semibold">
                {m.title}
              </span>
              <div className={`p-1.5 rounded bg-slate-900 border border-slate-800 ${m.iconColor}`}>
                <Icon className="h-3.5 w-3.5" />
              </div>
            </div>

            <div className="text-xl font-bold font-mono text-slate-100 mb-2 tracking-tight">
              {m.value}
            </div>

            <div className="border-t border-slate-850 pt-2 space-y-1 font-mono">
              <div className="text-[10px] text-slate-400 truncate">{m.subtitle}</div>
              <span className={`inline-block px-1.5 py-0.5 rounded text-[9px] font-bold border ${m.badgeColor}`}>
                {m.badge}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
