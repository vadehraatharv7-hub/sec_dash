import React, { useState, useEffect } from 'react';
import { GitCommit, X, CheckCircle2, XCircle, Clock, ShieldAlert, ArrowDown } from 'lucide-react';
import { fetchSessionKillChain } from '../utils/api';

export default function KillChainModal({ session, onClose }) {
  const [phases, setPhases] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!session) return;
    setLoading(true);
    fetchSessionKillChain(session.session_id)
      .then((data) => setPhases(data || []))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, [session]);

  if (!session) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="w-full max-w-2xl rounded-lg bg-[#0b1120] border border-slate-700 shadow-2xl overflow-hidden flex flex-col max-h-[85vh] font-mono text-xs">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-3.5 bg-[#080d1a] border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-400">
              <GitCommit className="h-4 w-4" />
            </div>
            <div>
              <span className="font-bold text-slate-100 text-sm block">CYBER KILL CHAIN PROGRESSION</span>
              <span className="text-[10px] text-slate-400">
                Session: {session.session_id} &bull; Attacker: {session.src_ip}
              </span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Timeline Body */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {loading ? (
            <div className="py-16 text-center text-slate-400 animate-pulse">
              Reconstructing 7-stage Cyber Kill Chain...
            </div>
          ) : (
            <div className="relative pl-6 space-y-4">
              {/* Vertical line connecting nodes */}
              <div className="absolute left-2.5 top-3 bottom-3 w-0.5 bg-slate-800" />

              {phases.map((p, idx) => {
                const isAchieved = p.status === 'achieved';
                const isBlocked = p.status === 'blocked';

                let nodeColor = 'bg-slate-800 border-slate-700 text-slate-500';
                if (isAchieved) nodeColor = 'bg-rose-500 border-rose-400 text-slate-950 shadow-[0_0_8px_#f43f5e]';
                else if (isBlocked) nodeColor = 'bg-amber-500 border-amber-400 text-slate-950';

                return (
                  <div key={idx} className="relative flex items-start gap-4">
                    {/* Step Icon / Dot */}
                    <div
                      className={`absolute -left-6 mt-0.5 h-5 w-5 rounded-full border-2 flex items-center justify-center text-[10px] font-bold ${nodeColor}`}
                    >
                      {p.phase_number}
                    </div>

                    <div
                      className={`flex-1 p-3 rounded-lg border transition-colors ${
                        isAchieved
                          ? 'bg-[#090e1b] border-rose-500/30'
                          : isBlocked
                          ? 'bg-[#090e1b] border-amber-500/30'
                          : 'bg-slate-950/50 border-slate-850 opacity-60'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-bold text-slate-200">
                          Phase {p.phase_number}: {p.phase_name}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase border ${
                            isAchieved
                              ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                              : isBlocked
                              ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                              : 'bg-slate-900 text-slate-500 border-slate-800'
                          }`}
                        >
                          {p.status.replace('_', ' ')}
                        </span>
                      </div>

                      <div className="text-[11px] text-slate-400">{p.summary}</div>

                      {p.evidence && (
                        <div className="mt-2 p-1.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-emerald-300">
                          Evidence: <span className="font-bold">{p.evidence}</span>
                          {p.timestamp && (
                            <span className="text-slate-500 ml-2">[{p.timestamp}]</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#080d1a] border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs"
          >
            Close Timeline
          </button>
        </div>
      </div>
    </div>
  );
}
