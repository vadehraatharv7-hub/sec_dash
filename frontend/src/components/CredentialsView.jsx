import React, { useState } from 'react';
import { KeyRound, ShieldAlert, Lock, User, Copy, Check, BarChart3 } from 'lucide-react';

export default function CredentialsView({ credentials = [] }) {
  const [copiedKey, setCopiedKey] = useState(null);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Group top usernames
  const userMap = {};
  const passMap = {};
  credentials.forEach((c) => {
    const u = c.username || '';
    const p = c.password || '';
    if (u) userMap[u] = (userMap[u] || 0) + (c.count || 1);
    if (p) passMap[p] = (passMap[p] || 0) + (c.count || 1);
  });

  const topUsers = Object.entries(userMap)
    .map(([username, count]) => ({ username, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  const topPass = Object.entries(passMap)
    .map(([password, count]) => ({ password, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  const maxUserCount = topUsers[0]?.count || 1;
  const maxPassCount = topPass[0]?.count || 1;

  return (
    <div className="space-y-6">
      {/* Top Section: Split Charts for Usernames & Passwords */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Top Usernames */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-xl backdrop-blur-sm">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <User className="h-4 w-4 text-amber-400" />
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                TOP TARGETED USERNAMES
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-500">ATTACK FREQUENCY</span>
          </div>

          <div className="space-y-3">
            {topUsers.map((item, idx) => {
              const pct = Math.round((item.count / maxUserCount) * 100);
              return (
                <div key={idx} className="space-y-1 font-mono text-xs">
                  <div className="flex justify-between items-center text-slate-300">
                    <span className="font-bold flex items-center gap-1.5">
                      <span className="text-amber-400">#{idx + 1}</span>
                      <span className="text-slate-100 bg-slate-800/80 px-1.5 py-0.5 rounded border border-slate-700">
                        {item.username}
                      </span>
                    </span>
                    <span className="text-slate-400 font-bold">{item.count.toLocaleString()} hits</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className="h-full bg-gradient-to-r from-amber-500 to-orange-500 rounded-full"
                      style={{ width: `${Math.max(pct, 5)}%` }}
                    />
                  </div>
                </div>
              );
            })}

            {topUsers.length === 0 && (
              <p className="text-xs font-mono text-slate-500 py-6 text-center">
                No credential attempts recorded yet.
              </p>
            )}
          </div>
        </div>

        {/* Top Passwords */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-xl backdrop-blur-sm">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-rose-400" />
              <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
                TOP TARGETED PASSWORDS
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-500">DICTIONARY HITS</span>
          </div>

          <div className="space-y-3">
            {topPass.map((item, idx) => {
              const pct = Math.round((item.count / maxPassCount) * 100);
              return (
                <div key={idx} className="space-y-1 font-mono text-xs">
                  <div className="flex justify-between items-center text-slate-300">
                    <span className="font-bold flex items-center gap-1.5">
                      <span className="text-rose-400">#{idx + 1}</span>
                      <span className="text-slate-100 bg-slate-800/80 px-1.5 py-0.5 rounded border border-slate-700">
                        {item.password}
                      </span>
                    </span>
                    <span className="text-slate-400 font-bold">{item.count.toLocaleString()} hits</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-950 rounded-full overflow-hidden border border-slate-800">
                    <div
                      className="h-full bg-gradient-to-r from-rose-500 to-purple-500 rounded-full"
                      style={{ width: `${Math.max(pct, 5)}%` }}
                    />
                  </div>
                </div>
              );
            })}

            {topPass.length === 0 && (
              <p className="text-xs font-mono text-slate-500 py-6 text-center">
                No passwords captured yet.
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Bottom Section: Full Combos Table */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-xl backdrop-blur-sm">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-cyan-400" />
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              CREDENTIAL COMBINATION MATRIX (USERNAME : PASSWORD)
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-500">
            {credentials.length} unique pairs tracked
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase tracking-wider">
                <th className="pb-2">Rank</th>
                <th className="pb-2">Username</th>
                <th className="pb-2">Password</th>
                <th className="pb-2">Attempts</th>
                <th className="pb-2">Entropy / Complexity</th>
                <th className="pb-2 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-855">
              {credentials.map((c, idx) => {
                const username = c.username || '';
                const password = c.password || '';
                const comboKey = `${username}:${password}`;
                const isCopied = copiedKey === comboKey;
                const isWeak = password.length < 8 || !/\d/.test(password);

                return (
                  <tr key={idx} className="hover:bg-slate-850/40 transition-colors">
                    <td className="py-2.5 text-slate-500">#{idx + 1}</td>
                    <td className="py-2.5 font-bold text-amber-300">{username || '<empty>'}</td>
                    <td className="py-2.5 font-bold text-rose-300">
                      {password ? password : <span className="text-slate-500 italic font-normal">&lt;empty&gt;</span>}
                    </td>
                    <td className="py-2.5 text-slate-200 font-bold">{c.count.toLocaleString()}</td>
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        isWeak 
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/30' 
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      }`}>
                        {isWeak ? 'Trivial / Dictionary' : 'Complex'}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => copyToClipboard(comboKey, comboKey)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-850 text-slate-300 hover:text-cyan-300 border border-slate-750 text-[11px]"
                      >
                        {isCopied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        <span>{isCopied ? 'Copied' : 'Copy'}</span>
                      </button>
                    </td>
                  </tr>
                );
              })}

              {credentials.length === 0 && (
                <tr>
                  <td colSpan="6" className="py-8 text-center text-slate-500">
                    No brute force credentials recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
