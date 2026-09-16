import React, { useState, useEffect } from 'react';
import { Cpu, Copy, Check, Send, CheckCircle2, ArrowRight, ShieldCheck, FileCode2 } from 'lucide-react';
import { fetchAlloyConfig, sendTestAlloyPayload } from '../utils/api';

export default function AlloyGuideView() {
  const [configText, setConfigText] = useState('');
  const [copied, setCopied] = useState(false);
  const [testStatus, setTestStatus] = useState(null);
  const [sendingTest, setSendingTest] = useState(false);

  useEffect(() => {
    fetchAlloyConfig().then((data) => {
      if (data && data.config) setConfigText(data.config);
    });
  }, []);

  const handleCopy = () => {
    navigator.clipboard.writeText(configText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSendTest = async () => {
    setSendingTest(true);
    setTestStatus(null);
    try {
      const code = await sendTestAlloyPayload();
      setTestStatus({ success: true, message: `Payload ingested successfully (HTTP ${code})! Watch the live feed update.` });
    } catch (err) {
      setTestStatus({ success: false, message: `Failed to send test payload: ${err.message}` });
    } finally {
      setSendingTest(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Architecture Overview */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-xl backdrop-blur-sm">
        <div className="flex items-center gap-2 pb-3 mb-4 border-b border-slate-800">
          <Cpu className="h-4 w-4 text-cyan-400" />
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
            GRAFANA ALLOY REPLACEMENT ARCHITECTURE & PIPELINE
          </h2>
        </div>

        <p className="text-xs font-mono text-slate-300 mb-6 leading-relaxed">
          Grafana Alloy is a telemetry collector that natively tails your Cowrie honeypot JSON logs and forwards them. 
          By redirecting Alloy’s <code className="text-cyan-400 bg-slate-950 px-1 py-0.5 rounded border border-slate-800">loki.write</code> endpoint to SecDash’s Go backend, you eliminate Grafana/Loki server overhead while achieving ~3.7x higher ingestion throughput and sub-millisecond real-time attack streaming.
        </p>

        {/* Visual Architecture Flow */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-center font-mono text-xs">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col items-center justify-center">
            <span className="text-amber-400 font-bold mb-1">COWRIE HONEYPOT</span>
            <span className="text-[11px] text-slate-400">Emits /var/log/cowrie/cowrie.json</span>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col items-center justify-center relative">
            <span className="text-cyan-400 font-bold mb-1">GRAFANA ALLOY</span>
            <span className="text-[11px] text-slate-400">Tails files & batches logs</span>
            <div className="hidden md:block absolute -right-2.5 top-1/2 -translate-y-1/2 z-10">
              <ArrowRight className="h-4 w-4 text-slate-600" />
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-cyan-500/30 flex flex-col items-center justify-center shadow-lg shadow-cyan-500/5 relative">
            <span className="text-emerald-400 font-bold mb-1">SECDASH GO BACKEND</span>
            <span className="text-[11px] text-slate-400">High-throughput ingestion (:8080)</span>
            <div className="hidden md:block absolute -right-2.5 top-1/2 -translate-y-1/2 z-10">
              <ArrowRight className="h-4 w-4 text-slate-600" />
            </div>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col items-center justify-center">
            <span className="text-purple-400 font-bold mb-1">REACT SOC UI</span>
            <span className="text-[11px] text-slate-400">Real-time WebSocket feed (:5173)</span>
          </div>
        </div>
      </div>

      {/* Config file & Test Trigger */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Alloy Configuration */}
        <div className="lg:col-span-2 rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-xl backdrop-blur-sm">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <FileCode2 className="h-4 w-4 text-cyan-400" />
              <span className="text-xs font-mono font-bold text-slate-200">config.alloy</span>
            </div>
            <button
              onClick={handleCopy}
              className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-slate-800 text-slate-200 hover:text-cyan-300 border border-slate-700 font-mono text-xs transition-colors"
            >
              {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copied ? 'Copied to Clipboard' : 'Copy Config'}</span>
            </button>
          </div>

          <pre className="p-4 rounded-lg bg-slate-950 border border-slate-850 text-emerald-400 font-mono text-xs overflow-x-auto leading-relaxed">
            {configText || `// Loading Alloy configuration...`}
          </pre>
        </div>

        {/* Right 1 Col: Instructions & Pipeline Test */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 shadow-xl backdrop-blur-sm flex flex-col justify-between space-y-4">
          <div>
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 mb-3">
              PIPELINE SETUP STEPS
            </h3>

            <ol className="list-decimal list-inside text-xs font-mono text-slate-300 space-y-2.5">
              <li>
                <span className="text-slate-100 font-bold">Copy the config</span> to <code className="text-cyan-300 bg-slate-950 px-1 rounded">/etc/alloy/config.alloy</code> or your project directory.
              </li>
              <li>
                <span className="text-slate-100 font-bold">Launch Grafana Alloy</span>:
                <pre className="mt-1 p-2 rounded bg-slate-950 text-cyan-300 text-[11px] overflow-x-auto">
                  alloy run config.alloy
                </pre>
              </li>
              <li>
                <span className="text-slate-100 font-bold">Verify Ingestion</span>: Attacks appearing in Cowrie will now immediately stream into SecDash.
              </li>
            </ol>
          </div>

          {/* Test Pipeline Ingestion Button */}
          <div className="pt-4 border-t border-slate-800">
            <span className="text-[11px] font-mono text-slate-400 block mb-2 font-bold">
              PIPELINE DIAGNOSTIC TEST
            </span>
            <button
              onClick={handleSendTest}
              disabled={sendingTest}
              className="w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-mono font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
            >
              <Send className="h-3.5 w-3.5" />
              <span>{sendingTest ? 'Sending Test Payload...' : 'Send Test Alloy Ingestion Event'}</span>
            </button>

            {testStatus && (
              <div className={`mt-2.5 p-2 rounded text-[11px] font-mono border ${
                testStatus.success 
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
              }`}>
                {testStatus.message}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
