import React from 'react';
import { 
  ShieldAlert, 
  Users, 
  Terminal, 
  Key, 
  FileCode2, 
  Cpu, 
  TrendingUp,
  AlertTriangle
} from 'lucide-react';

export default function StatsCards({ stats }) {
  if (!stats) return null;

  const cards = [
    {
      title: 'TOTAL ATTACK EVENTS',
      value: stats.total_events?.toLocaleString() || '0',
      sub: 'All honeypot triggers',
      icon: ShieldAlert,
      color: 'cyan',
      glow: 'shadow-cyan-500/10',
      border: 'border-cyan-500/30',
      accent: 'text-cyan-400',
    },
    {
      title: 'UNIQUE ATTACKER IPs',
      value: stats.unique_attackers?.toLocaleString() || '0',
      sub: 'Adversary origins',
      icon: Users,
      color: 'indigo',
      glow: 'shadow-indigo-500/10',
      border: 'border-indigo-500/30',
      accent: 'text-indigo-400',
    },
    {
      title: 'ACTIVE SESSIONS',
      value: stats.active_sessions?.toLocaleString() || '0',
      sub: 'Live adversary links',
      icon: Cpu,
      color: 'emerald',
      glow: 'shadow-emerald-500/10',
      border: 'border-emerald-500/30',
      accent: 'text-emerald-400',
    },
    {
      title: 'BRUTE FORCE LOGINS',
      value: stats.failed_logins?.toLocaleString() || '0',
      sub: `${stats.successful_logins || 0} breached honeypot`,
      icon: Key,
      color: 'amber',
      glow: 'shadow-amber-500/10',
      border: 'border-amber-500/30',
      accent: 'text-amber-400',
    },
    {
      title: 'COMMANDS INTERCEPTED',
      value: stats.commands_executed?.toLocaleString() || '0',
      sub: 'Fake shell instructions',
      icon: Terminal,
      color: 'rose',
      glow: 'shadow-rose-500/10',
      border: 'border-rose-500/30',
      accent: 'text-rose-400',
    },
    {
      title: 'MALWARE DOWNLOADS',
      value: stats.files_captured?.toLocaleString() || '0',
      sub: 'Captured binary drops',
      icon: FileCode2,
      color: 'purple',
      glow: 'shadow-purple-500/10',
      border: 'border-purple-500/30',
      accent: 'text-purple-400',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card, i) => {
        const Icon = card.icon;
        return (
          <div
            key={i}
            className={`relative overflow-hidden rounded-xl bg-slate-900/80 p-4 border ${card.border} ${card.glow} backdrop-blur-sm transition-all hover:bg-slate-900/95`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] font-mono font-bold tracking-wider text-slate-400">
                {card.title}
              </span>
              <div className={`p-1.5 rounded-lg bg-slate-800/80 ${card.accent}`}>
                <Icon className="h-4 w-4" />
              </div>
            </div>

            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-bold font-mono text-slate-100 tracking-tight">
                {card.value}
              </span>
            </div>

            <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span className="truncate">{card.sub}</span>
            </div>

            {/* Subtle corner accent line */}
            <div className={`absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-${card.color}-500/50 to-transparent`} />
          </div>
        );
      })}
    </div>
  );
}
