import React, { useState, useEffect } from 'react';
import { Sparkles, X, ShieldAlert, Cpu, CheckCircle2, AlertTriangle, ArrowRight, ShieldCheck } from 'lucide-react';
import { fetchSessionAIAnalysis } from '../utils/api';

export default function AIAnalysisModal({ session, onClose }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!session) return;
    setLoading(true);
    setError(null);

    fetchSessionAIAnalysis(session.session_id)
      .then((data) => setAnalysis(data))
      .catch((err) => setError('AI threat analysis failed: ' + err.message))
      .finally(() => setLoading(false));
  }, [session]);

  if (!session) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="w-full max-w-3xl rounded-lg bg-[#0b1120] border border-cyan-500/40 shadow-2xl overflow-hidden flex flex-col max-h-[90vh] font-mono text-xs">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 bg-[#080d1a] border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Sparkles className="h-4 w-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-slate-100 text-sm">LLM ADVERSARY INTENT ANALYSIS</span>
                <span className="text-[10px] text-cyan-300 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20">
                  SESSION: {session.session_id}
                </span>
              </div>
              <span className="text-[10px] text-slate-400">
                Automated transcript triage for {session.src_ip} ({session.country_name || 'Origin'})
              </span>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 overflow-y-auto space-y-4 flex-1">
          {loading ? (
            <div className="py-16 text-center space-y-3">
              <div className="inline-block h-8 w-8 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent" />
              <div className="text-slate-400">Routing session transcript through LLM threat classifier...</div>
            </div>
          ) : error ? (
            <div className="py-12 text-center text-rose-400">{error}</div>
          ) : analysis ? (
            <>
              {/* Primary Objective Banner */}
              <div className="p-4 rounded-lg bg-[#090e1b] border border-cyan-500/30 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider">
                    PRIMARY ATTACKER INTENT
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-400">Confidence:</span>
                    <span className="text-cyan-300 font-bold">{analysis.confidence}%</span>
                  </div>
                </div>

                <div className="text-base font-bold text-slate-100">
                  {analysis.attacker_intent}
                </div>

                <div className="flex flex-wrap gap-2 pt-1">
                  <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 text-[10px] font-bold">
                    Class: <strong className="text-rose-400">{analysis.skill_level}</strong>
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800 text-[10px] font-bold">
                    Threat: <strong className="text-amber-400">{analysis.threat_category}</strong>
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800 text-[10px]">
                    Model: <strong className="text-slate-200">{analysis.model_used}</strong>
                  </span>
                </div>
              </div>

              {/* Narrative Summary */}
              <div className="p-3.5 rounded-lg bg-[#080d1a] border border-slate-800">
                <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">
                  TACTICAL EXECUTIVE SUMMARY
                </span>
                <p className="text-slate-300 leading-relaxed text-[11px]">
                  {analysis.summary}
                </p>
              </div>

              {/* MITRE ATT&CK Mapping */}
              <div className="rounded-lg bg-[#080d1a] border border-slate-800 overflow-hidden">
                <div className="px-4 py-2.5 border-b border-slate-800 bg-[#090e1b] flex justify-between items-center">
                  <span className="text-[10px] font-bold text-slate-300 uppercase">
                    MITRE ATT&CK TTP MAPPING
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {analysis.mitre_tactics?.length || 0} Techniques Identified
                  </span>
                </div>

                <div className="divide-y divide-slate-850">
                  {analysis.mitre_tactics?.map((t, idx) => (
                    <div key={idx} className="p-3 hover:bg-slate-900/40 transition-colors">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 text-[10px] font-bold">
                            {t.id}
                          </span>
                          <span className="font-bold text-slate-100">{t.name}</span>
                        </div>
                        <span className="text-[10px] text-slate-400 uppercase font-semibold">
                          {t.phase}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 pl-1">
                        &bull; Evidence: <span className="text-slate-200">{t.evidence}</span>
                      </div>
                    </div>
                  ))}

                  {(!analysis.mitre_tactics || analysis.mitre_tactics.length === 0) && (
                    <div className="p-4 text-slate-500 italic text-center">
                      No explicit MITRE tactics matched on credential-only probe.
                    </div>
                  )}
                </div>
              </div>

              {/* Recommended Action */}
              <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-start gap-2.5">
                <ShieldCheck className="h-4 w-4 shrink-0 mt-0.5 text-emerald-400" />
                <div>
                  <span className="font-bold text-[11px] block">RECOMMENDED REMEDIATION:</span>
                  <span className="text-[11px] text-emerald-200/90">{analysis.recommended_action}</span>
                </div>
              </div>
            </>
          ) : null}
        </div>

        {/* Footer */}
        <div className="p-3 bg-[#080d1a] border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono"
          >
            Close Threat Triage
          </button>
        </div>
      </div>
    </div>
  );
}
