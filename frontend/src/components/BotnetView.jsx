import React, { useState, useEffect } from 'react';
import { Fingerprint, Server, ShieldAlert, Search, RefreshCw, Cpu, Activity } from 'lucide-react';
import { fetchBotnetFingerprints } from '../utils/api';

export default function BotnetView() {
  const [fingerprints, setFingerprints] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  const loadFingerprints = () => {
    setLoading(true);
    fetchBotnetFingerprints(40)
      .then((data) => setFingerprints(data || []))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadFingerprints();
  }, []);

  const totalHits = fingerprints.reduce((sum, f) => sum + f.count, 0) || 1;

  const filtered = fingerprints.filter((f) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      f.client_version.toLowerCase().includes(q) ||
      f.botnet_category.toLowerCase().includes(q) ||
      f.signature_type.toLowerCase().includes(q)
    );
  });

  const getSignatureBadge = (type) => {
    switch (type) {
      case 'Worm':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'Scanner':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'Interactive':
        return 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-lg bg-[#0b1120] border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Fingerprint className="h-4 w-4 text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              BOTNET FINGERPRINTING & SSH HASSH CLIENT PROFILES
            </h2>
            <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[10px] text-cyan-400 border border-cyan-500/20">
              {fingerprints.length} Unique Signatures
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Automated fingerprinting of SSH client protocol strings (`cowrie.client.version`) and known botnet threat families.
          </p>
        </div>

        <button
          onClick={loadFingerprints}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200"
        >
          <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Main Fingerprints Table */}
      <div className="rounded-lg bg-[#0b1120] border border-slate-800 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 p-4 border-b border-slate-800 bg-[#090e1b]">
          <span className="text-xs font-bold text-slate-200 uppercase">
            IDENTIFIED BOTNET SIGNATURES & CLIENT HARDWARE STRINGS
          </span>

          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search fingerprint or botnet..."
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
                <th className="py-2.5 px-4">Threat Family</th>
                <th className="py-2.5 px-4">Signature Type</th>
                <th className="py-2.5 px-4">Raw Client Version Banner</th>
                <th className="py-2.5 px-4">Adversary Volume</th>
                <th className="py-2.5 px-4">Fleet Share</th>
                <th className="py-2.5 px-4 text-right">Activity Window</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {filtered.map((fp, idx) => {
                const pct = ((fp.count / totalHits) * 100).toFixed(1);

                return (
                  <tr key={idx} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-2.5 px-4 font-bold text-slate-200">
                      <div className="flex items-center gap-2">
                        <span className="h-1.5 w-1.5 rounded-full bg-rose-400" />
                        <span>{fp.botnet_category}</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getSignatureBadge(fp.signature_type)}`}>
                        {fp.signature_type}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="bg-slate-950 px-2 py-1 rounded border border-slate-850 text-cyan-300 font-mono text-[11px] block max-w-md truncate">
                        {fp.client_version}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 font-bold text-slate-100">
                      {fp.count.toLocaleString()}
                    </td>
                    <td className="py-2.5 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-cyan-400 rounded-full"
                            style={{ width: `${Math.max(Number(pct), 5)}%` }}
                          />
                        </div>
                        <span className="text-[10px] text-slate-400">{pct}%</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-4 text-right text-slate-400 text-[10px] whitespace-nowrap">
                      {fp.last_seen ? new Date(fp.last_seen).toLocaleDateString() : 'Active'}
                    </td>
                  </tr>
                );
              })}

              {filtered.length === 0 && (
                <tr>
                  <td colSpan="6" className="py-12 text-center text-slate-500">
                    No botnet fingerprints matching query.
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
