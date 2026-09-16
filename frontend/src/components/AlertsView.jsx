import React, { useState, useEffect } from 'react';
import { Bell, Plus, Trash2, Send, CheckCircle2, XCircle, ShieldAlert, Radio, Clock, RefreshCw } from 'lucide-react';
import { fetchWebhooks, createWebhook, deleteWebhook, testWebhook, fetchWebhookLogs } from '../utils/api';

export default function AlertsView() {
  const [webhooks, setWebhooks] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  // Form state
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [type, setType] = useState('slack');
  const [loginSuccess, setLoginSuccess] = useState(true);
  const [malware, setMalware] = useState(true);
  const [critCmd, setCritCmd] = useState(true);
  const [testResult, setTestResult] = useState(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [hooksData, logsData] = await Promise.all([
        fetchWebhooks(),
        fetchWebhookLogs(),
      ]);
      setWebhooks(hooksData || []);
      setLogs(logsData || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!name.trim() || !url.trim()) return;

    try {
      await createWebhook({
        name,
        url,
        type,
        alert_on_login_success: loginSuccess,
        alert_on_malware: malware,
        alert_on_critical_cmd: critCmd,
        enabled: true,
      });
      setName('');
      setUrl('');
      loadData();
    } catch (err) {
      alert('Error creating webhook: ' + err.message);
    }
  };

  const handleDelete = async (id) => {
    try {
      await deleteWebhook(id);
      loadData();
    } catch (err) {
      alert('Error deleting webhook');
    }
  };

  const handleTest = async (id) => {
    setTestResult({ id, loading: true });
    try {
      const res = await testWebhook(id);
      setTestResult({ id, success: res.success, message: res.message });
      loadData();
    } catch (err) {
      setTestResult({ id, success: false, message: err.message });
    }
  };

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Banner */}
      <div className="p-4 rounded-lg bg-[#0b1120] border border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Bell className="h-4 w-4 text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              CUSTOM WEBHOOK ALERTING ENGINE
            </h2>
            <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-[10px] text-cyan-400 border border-cyan-500/20">
              Slack &bull; Discord &bull; Generic JSON
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Dispatch instant notifications to your incident response channels when honeypots detect breaches, malware drops, or suspicious commands.
          </p>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200"
        >
          <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Col: Create Webhook Form */}
        <div className="rounded-lg bg-[#0b1120] border border-slate-800 p-5 space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Plus className="h-4 w-4 text-cyan-400" />
            <span className="font-bold text-slate-200 uppercase">ADD ALERT DESTINATION</span>
          </div>

          <form onSubmit={handleCreate} className="space-y-3.5">
            <div>
              <label className="text-[10px] text-slate-400 uppercase block mb-1">Destination Name</label>
              <input
                type="text"
                placeholder="e.g. #soc-alerts, Discord SecOps"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 uppercase block mb-1">Webhook URL</label>
              <input
                type="url"
                placeholder="https://hooks.slack.com/services/..."
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                required
                className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div>
              <label className="text-[10px] text-slate-400 uppercase block mb-1">Platform Format</label>
              <select
                value={type}
                onChange={(e) => setType(e.target.value)}
                className="w-full rounded bg-slate-950 border border-slate-800 px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="slack">Slack Incoming Webhook</option>
                <option value="discord">Discord Webhook</option>
                <option value="generic">Generic JSON (POST RFC-8259)</option>
              </select>
            </div>

            <div className="pt-2 border-t border-slate-850 space-y-2">
              <span className="text-[10px] text-slate-400 uppercase block font-bold">Trigger Conditions</span>
              
              <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={loginSuccess}
                  onChange={(e) => setLoginSuccess(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500"
                />
                <span>Shell Breach (`cowrie.login.success`)</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={malware}
                  onChange={(e) => setMalware(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500"
                />
                <span>Malware Drop (`cowrie.session.file_download`)</span>
              </label>

              <label className="flex items-center gap-2 cursor-pointer text-slate-300">
                <input
                  type="checkbox"
                  checked={critCmd}
                  onChange={(e) => setCritCmd(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-900 text-cyan-500"
                />
                <span>Critical Shell Ingress (`wget`, `curl | sh`, `rm -rf`)</span>
              </label>
            </div>

            <button
              type="submit"
              className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold transition-all mt-3"
            >
              Save Alert Webhook
            </button>
          </form>
        </div>

        {/* Right 2 Cols: Active Webhooks & Dispatch Audit Logs */}
        <div className="lg:col-span-2 space-y-6">
          {/* Active Webhooks List */}
          <div className="rounded-lg bg-[#0b1120] border border-slate-800 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 bg-[#090e1b] flex justify-between items-center">
              <span className="font-bold text-slate-200 uppercase">ACTIVE ALERT DESTINATIONS</span>
              <span className="text-slate-500">{webhooks.length} configured</span>
            </div>

            <div className="divide-y divide-slate-850">
              {webhooks.map((hook) => {
                const isTesting = testResult?.id === hook.id && testResult?.loading;
                const result = testResult?.id === hook.id ? testResult : null;

                return (
                  <div key={hook.id} className="p-4 space-y-2 hover:bg-slate-900/40 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-100">{hook.name}</span>
                        <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-950 text-cyan-300 border border-slate-800">
                          {hook.type}
                        </span>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleTest(hook.id)}
                          disabled={isTesting}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-[11px]"
                        >
                          <Send className="h-3 w-3" />
                          <span>{isTesting ? 'Pinging...' : 'Test Ping'}</span>
                        </button>

                        <button
                          onClick={() => handleDelete(hook.id)}
                          className="p-1 rounded text-slate-500 hover:text-rose-400 hover:bg-slate-900"
                          title="Delete webhook"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>

                    <div className="text-[11px] text-slate-400 truncate">
                      Endpoint: <span className="text-slate-300">{hook.url}</span>
                    </div>

                    {result && !result.loading && (
                      <div className={`p-2 rounded text-[11px] border ${
                        result.success 
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
                          : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      }`}>
                        {result.message}
                      </div>
                    )}
                  </div>
                );
              })}

              {webhooks.length === 0 && (
                <div className="py-10 text-center text-slate-500 italic">
                  No webhooks configured. Add one on the left to receive instant honeypot breach notifications!
                </div>
              )}
            </div>
          </div>

          {/* Audit Logs */}
          <div className="rounded-lg bg-[#0b1120] border border-slate-800 overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-800 bg-[#090e1b] flex justify-between items-center">
              <span className="font-bold text-slate-200 uppercase">RECENT DISPATCH AUDIT LOGS</span>
              <span className="text-slate-500">{logs.length} logged</span>
            </div>

            <div className="max-h-48 overflow-y-auto divide-y divide-slate-850">
              {logs.map((l, i) => (
                <div key={i} className="px-4 py-2 flex items-center justify-between text-[11px] hover:bg-slate-900/30">
                  <div className="flex items-center gap-2 truncate">
                    {l.success ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                    )}
                    <span className="text-slate-300 font-bold">{l.webhook_name}</span>
                    <span className="text-slate-500">({l.event_type})</span>
                    <span className="text-slate-400 truncate">{l.message}</span>
                  </div>

                  <div className="text-slate-500 text-[10px] shrink-0 ml-2">
                    {new Date(l.timestamp).toLocaleTimeString([], { hour12: false })}
                  </div>
                </div>
              ))}

              {logs.length === 0 && (
                <div className="py-6 text-center text-slate-500 italic text-[11px]">
                  No alert dispatches yet.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
