import React, { useState } from 'react';
import { KeyRound, Download, Copy, Check, Search, Lock, User, ShieldAlert, Sparkles } from 'lucide-react';

export default function CredentialWall({ credentials = [] }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState(null);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const handleExportWordlist = () => {
    const lines = credentials.map((c) => `${c.username || ''}:${c.password || ''}`);
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `honeypot_wordlist_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredCreds = credentials.filter((c) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const u = (c.username || '').toLowerCase();
    const p = (c.password || '').toLowerCase();
    return u.includes(q) || p.includes(q);
  });

  const totalAttempts = credentials.reduce((sum, c) => sum + c.count, 0) || 1;

  // Group top usernames and passwords
  const userFreq = {};
  const passFreq = {};
  credentials.forEach((c) => {
    const u = c.username || '';
    const p = c.password || '';
    if (u) userFreq[u] = (userFreq[u] || 0) + (c.count || 1);
    if (p) passFreq[p] = (passFreq[p] || 0) + (c.count || 1);
  });

  const topUsers = Object.entries(userFreq)
    .map(([user, count]) => ({ user, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  const topPass = Object.entries(passFreq)
    .map(([pass, count]) => ({ pass, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);

  return (
    <div className="space-y-6">
      {/* Top Banner Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-lg bg-[#0b1120] border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">HARVESTED COMBOS</span>
            <div className="text-2xl font-bold font-mono text-slate-100">{credentials.length.toLocaleString()}</div>
          </div>
          <div className="p-2 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400">
            <KeyRound className="h-5 w-5" />
          </div>
        </div>

        <div className="p-4 rounded-lg bg-[#0b1120] border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">BRUTE-FORCE ATTEMPTS</span>
            <div className="text-2xl font-bold font-mono text-rose-400">{totalAttempts.toLocaleString()}</div>
          </div>
          <div className="p-2 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400">
            <ShieldAlert className="h-5 w-5" />
          </div>
        </div>

        <div className="p-4 rounded-lg bg-[#0b1120] border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">DICTIONARY WORDLIST</span>
            <div className="mt-1">
              <button
                onClick={handleExportWordlist}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold transition-all shadow-sm shadow-cyan-500/10"
              >
                <Download className="h-3.5 w-3.5" />
                <span>Export Wordlist (.txt)</span>
              </button>
            </div>
          </div>
          <div className="p-2 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Lock className="h-5 w-5" />
          </div>
        </div>
      </div>

      {/* Split Leaderboards: Top Users & Top Passwords */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Usernames */}
        <div className="rounded-lg bg-[#0b1120] border border-slate-800 p-4">
          <div className="flex items-center gap-2 pb-3 mb-3 border-b border-slate-800">
            <User className="h-4 w-4 text-amber-400" />
            <span className="text-xs font-mono font-bold text-slate-200 uppercase">TOP HARVESTED ACCOUNTS</span>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {topUsers.map((u, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-950/70 border border-slate-850">
                <span className="text-slate-200 font-bold flex items-center gap-2">
                  <span className="text-slate-500 text-[10px]">#{i + 1}</span>
                  <span className="text-amber-400">{u.user}</span>
                </span>
                <span className="text-slate-400 font-semibold">{u.count.toLocaleString()} hits</span>
              </div>
            ))}
          </div>
        </div>

        {/* Passwords */}
        <div className="rounded-lg bg-[#0b1120] border border-slate-800 p-4">
          <div className="flex items-center gap-2 pb-3 mb-3 border-b border-slate-800">
            <Lock className="h-4 w-4 text-rose-400" />
            <span className="text-xs font-mono font-bold text-slate-200 uppercase">TOP HARVESTED PASSWORDS</span>
          </div>

          <div className="space-y-2 font-mono text-xs">
            {topPass.map((p, i) => (
              <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-950/70 border border-slate-850">
                <span className="text-slate-200 font-bold flex items-center gap-2">
                  <span className="text-slate-500 text-[10px]">#{i + 1}</span>
                  <span className="text-rose-400 font-mono">"{p.pass}"</span>
                </span>
                <span className="text-slate-400 font-semibold">{p.count.toLocaleString()} hits</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Main Harvested Credential Wall Table */}
      <div className="rounded-lg bg-[#0b1120] border border-slate-800 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 p-4 border-b border-slate-800 bg-[#090e1b]">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-amber-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              HARVESTED CREDENTIAL INTELLIGENCE MATRIX
            </h3>
            <span className="text-[10px] font-mono text-slate-400">
              ({filteredCreds.length} entries matching)
            </span>
          </div>

          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search user or password..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="rounded bg-slate-950 border border-slate-800 pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase tracking-wider bg-[#080d1a]">
                <th className="py-2.5 px-4">Rank</th>
                <th className="py-2.5 px-4">Username</th>
                <th className="py-2.5 px-4">Password</th>
                <th className="py-2.5 px-4">Attempts</th>
                <th className="py-2.5 px-4">Complexity / Weakness Class</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {filteredCreds.map((c, idx) => {
                const username = c.username || '';
                const password = c.password || '';
                const key = `${username}:${password}`;
                const isCopied = copiedKey === key;
                const isTrivial = password.length <= 6 || /^(123456|password|admin|root|1234)$/i.test(password);

                return (
                  <tr key={idx} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-2.5 px-4 text-slate-500">#{idx + 1}</td>
                    <td className="py-2.5 px-4">
                      <span className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-amber-300 font-bold">
                        {username || '<empty>'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800 text-rose-300 font-bold">
                        {password ? password : <span className="text-slate-500 italic font-normal">&lt;empty&gt;</span>}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-bold text-slate-200">
                      {c.count.toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${
                        isTrivial
                          ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      }`}>
                        {isTrivial ? 'Default / Trivial' : 'Standard Dictionary'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => copyToClipboard(key, key)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 text-slate-300 hover:text-white border border-slate-800 text-[11px]"
                      >
                        {isCopied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                        <span>{isCopied ? 'Copied' : 'Copy Combo'}</span>
                      </button>
                    </td>
                  </tr>
                );
              })}

              {filteredCreds.length === 0 && (
                <tr>
                  <td colSpan="6" className="py-12 text-center text-slate-500">
                    No harvested credentials matching query.
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
