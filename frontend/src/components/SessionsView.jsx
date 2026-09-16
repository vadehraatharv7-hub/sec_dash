import React, { useState } from 'react';
import { 
  Terminal, 
  ExternalLink, 
  ShieldAlert, 
  Play, 
  X, 
  Copy, 
  Check, 
  Sparkles, 
  GitCommit,
  Clock,
  Radio
} from 'lucide-react';
import { fetchSessionCommands } from '../utils/api';
import AIAnalysisModal from './AIAnalysisModal';
import KillChainModal from './KillChainModal';

export default function SessionsView({ sessions = [], onSelectIP }) {
  const [activeSession, setActiveSession] = useState(null);
  const [sessionCommands, setSessionCommands] = useState([]);
  const [loadingCommands, setLoadingCommands] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(null);

  // Modals for AI Analysis and Kill Chain
  const [aiModalSession, setAiModalSession] = useState(null);
  const [killChainSession, setKillChainSession] = useState(null);

  const handleOpenReplay = async (session) => {
    setActiveSession(session);
    setLoadingCommands(true);
    try {
      const cmds = await fetchSessionCommands(session.session_id);
      setSessionCommands(cmds || []);
    } catch (err) {
      console.error(err);
      setSessionCommands([]);
    } finally {
      setLoadingCommands(false);
    }
  };

  const handleCloseReplay = () => {
    setActiveSession(null);
    setSessionCommands([]);
  };

  const handleCopyCommand = (cmd, idx) => {
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(idx);
    setTimeout(() => setCopiedCmd(null), 1500);
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Session Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-lg bg-[#0b1120] border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              HONEYPOT ADVERSARY SESSIONS & TRIAGE
            </h2>
            <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[10px] text-cyan-300 border border-cyan-500/20">
              {sessions.length} Recorded Sessions
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Review completed adversary shell sessions, run LLM-powered threat analysis, or inspect the 7-phase Kill Chain.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[10px] text-slate-500">Autonomous LLM Engine:</span>
          <span className="text-[10px] text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
            READY (Intent Triage)
          </span>
        </div>
      </div>

      {/* Session List Table */}
      <div className="rounded-lg bg-[#0b1120] border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase tracking-wider bg-[#080d1a]">
                <th className="py-2.5 px-4">Session ID</th>
                <th className="py-2.5 px-4">Attacker IP</th>
                <th className="py-2.5 px-4">Origin</th>
                <th className="py-2.5 px-4">Protocol</th>
                <th className="py-2.5 px-4">Duration</th>
                <th className="py-2.5 px-4">Commands</th>
                <th className="py-2.5 px-4">Breach Status</th>
                <th className="py-2.5 px-4 text-right">Forensic Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {sessions.map((s, idx) => (
                <tr key={s.session_id || idx} className="hover:bg-slate-900/50 transition-colors">
                  <td className="py-2.5 px-4 font-bold text-cyan-400">
                    <span className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      {s.session_id}
                    </span>
                  </td>
                  <td className="py-2.5 px-4">
                    <button
                      onClick={() => onSelectIP(s.src_ip)}
                      className="text-slate-200 hover:text-cyan-300 font-bold underline flex items-center gap-1"
                    >
                      <span>{s.src_ip}</span>
                      <ExternalLink className="h-2.5 w-2.5 opacity-50" />
                    </button>
                  </td>
                  <td className="py-2.5 px-4 text-slate-300">
                    {s.country_name ? `${s.country_name} (${s.country_code})` : 'Unknown'}
                  </td>
                  <td className="py-2.5 px-4 uppercase font-bold text-slate-400">{s.protocol || 'SSH'}</td>
                  <td className="py-2.5 px-4 text-slate-300">
                    {s.duration > 0 ? `${s.duration.toFixed(1)}s` : '< 1s'}
                  </td>
                  <td className="py-2.5 px-4 font-bold text-slate-200">
                    {s.commands_count > 0 ? (
                      <span className="text-rose-400 font-bold">{s.commands_count} cmds</span>
                    ) : (
                      <span className="text-slate-500">0</span>
                    )}
                  </td>
                  <td className="py-2.5 px-4">
                    {s.login_success ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40">
                        <ShieldAlert className="h-3 w-3 text-rose-400" />
                        Breached Shell
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-900 text-slate-400 border border-slate-800">
                        Auth Failed
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-right space-x-1.5 whitespace-nowrap">
                    {/* AI Analysis Button */}
                    <button
                      onClick={() => setAiModalSession(s)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-700/50 hover:border-cyan-500 transition-all text-[11px] font-bold shadow-sm"
                      title="Run LLM Threat Intent Analysis"
                    >
                      <Sparkles className="h-3 w-3 text-cyan-400" />
                      <span>AI Analysis</span>
                    </button>

                    {/* Kill Chain Button */}
                    <button
                      onClick={() => setKillChainSession(s)}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-[11px]"
                      title="Inspect 7-Phase Cyber Kill Chain"
                    >
                      <GitCommit className="h-3 w-3 text-rose-400" />
                      <span>Kill Chain</span>
                    </button>

                    {/* Terminal Replay Button */}
                    <button
                      onClick={() => handleOpenReplay(s)}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 text-[11px]"
                      title="Replay Intercepted Shell"
                    >
                      <Play className="h-2.5 w-2.5 fill-current text-slate-400" />
                      <span>Replay</span>
                    </button>
                  </td>
                </tr>
              ))}

              {sessions.length === 0 && (
                <tr>
                  <td colSpan="8" className="py-12 text-center text-slate-500">
                    No adversary sessions recorded yet. Waiting for honeypot connections...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Terminal Replay Modal */}
      {activeSession && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="w-full max-w-3xl rounded-lg bg-slate-950 border border-slate-700 shadow-2xl overflow-hidden flex flex-col max-h-[85vh]">
            <div className="flex items-center justify-between px-4 py-3 bg-[#0b1120] border-b border-slate-800">
              <div className="flex items-center gap-2">
                <div className="flex space-x-1.5 mr-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80 inline-block" />
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80 inline-block" />
                  <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80 inline-block" />
                </div>
                <span className="text-xs font-bold text-slate-200 font-mono">
                  SHELL REPLAY &bull; [{activeSession.session_id}] &bull; {activeSession.src_ip}
                </span>
              </div>

              <button
                onClick={handleCloseReplay}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 bg-slate-900/50 border-b border-slate-800 text-[11px] font-mono text-slate-400">
              <div>Source IP: <span className="text-cyan-400 font-bold">{activeSession.src_ip}</span></div>
              <div>Country: <span className="text-slate-200">{activeSession.country_name || 'N/A'}</span></div>
              <div>Duration: <span className="text-slate-200">{activeSession.duration}s</span></div>
              <div>Status: <span className={activeSession.login_success ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                {activeSession.login_success ? 'SHELL BREACHED' : 'AUTH FAILED'}
              </span></div>
            </div>

            <div className="p-4 overflow-y-auto font-mono text-xs space-y-2 bg-[#060913] text-emerald-400 flex-1 min-h-[300px]">
              <div className="text-slate-600 border-b border-slate-900 pb-2">
                # Intercepted Cowrie SSH Session Stream
                <br />
                # Connected from {activeSession.src_ip} on port 22 ({activeSession.protocol || 'ssh'})
              </div>

              {loadingCommands ? (
                <div className="text-slate-400 py-8 text-center animate-pulse">
                  Retrieving session commands...
                </div>
              ) : sessionCommands.length > 0 ? (
                sessionCommands.map((cmdObj, i) => (
                  <div key={i} className="group flex items-start justify-between gap-2 p-1 rounded hover:bg-slate-900/80 transition-colors">
                    <div className="flex items-center gap-2">
                      <span className="text-rose-400 font-bold select-none">root@honeypot:~#</span>
                      <span className="text-slate-100 font-bold">{cmdObj.command}</span>
                    </div>

                    <button
                      onClick={() => handleCopyCommand(cmdObj.command, i)}
                      className="opacity-0 group-hover:opacity-100 transition-opacity p-1 text-slate-500 hover:text-cyan-300"
                      title="Copy command"
                    >
                      {copiedCmd === i ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    </button>
                  </div>
                ))
              ) : (
                <div className="text-slate-500 italic py-6">
                  Attacker attempted authentication credentials but executed no shell commands.
                </div>
              )}

              <div className="flex items-center gap-2 pt-2">
                <span className="text-rose-400 select-none">root@honeypot:~#</span>
                <span className="h-3.5 w-2 bg-emerald-400 animate-pulse inline-block" />
              </div>
            </div>

            <div className="p-3 bg-[#0b1120] border-t border-slate-800 flex justify-between items-center text-[11px] font-mono text-slate-400">
              <span>{sessionCommands.length} commands captured in honeypot sandbox</span>
              <button
                onClick={handleCloseReplay}
                className="px-3 py-1 rounded bg-slate-800 text-slate-200 hover:bg-slate-700"
              >
                Close Replay
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI Analysis Modal */}
      {aiModalSession && (
        <AIAnalysisModal
          session={aiModalSession}
          onClose={() => setAiModalSession(null)}
        />
      )}

      {/* Kill Chain Modal */}
      {killChainSession && (
        <KillChainModal
          session={killChainSession}
          onClose={() => setKillChainSession(null)}
        />
      )}
    </div>
  );
}
