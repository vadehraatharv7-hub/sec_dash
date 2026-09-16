import React, { useState, useEffect } from 'react';
import { 
  X, 
  ShieldAlert, 
  Globe2, 
  Server, 
  Clock, 
  Terminal, 
  KeyRound, 
  Check, 
  Copy, 
  AlertTriangle 
} from 'lucide-react';
import { fetchIPProfile } from '../utils/api';

export default function ThreatProfileModal({ ip, onClose }) {
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!ip) return;
    setLoading(true);
    setError(null);
    fetchIPProfile(ip)
      .then((data) => setProfile(data))
      .catch((err) => setError('Could not load threat forensics for this IP.'))
      .finally(() => setLoading(false));
  }, [ip]);

  const handleCopyIP = () => {
    navigator.clipboard.writeText(ip);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!ip) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
      <div className="w-full max-w-2xl rounded-xl bg-slate-950 border border-cyan-500/40 shadow-2xl shadow-cyan-500/10 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-4 bg-slate-900 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
              <ShieldAlert className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold font-mono text-slate-100">{ip}</h3>
                <button
                  onClick={handleCopyIP}
                  className="text-slate-500 hover:text-cyan-300 p-1 rounded"
                  title="Copy IP"
                >
                  {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>
              <p className="text-[11px] font-mono text-slate-400">ADVERSARY THREAT FORENSICS</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-5 font-mono text-xs flex-1">
          {loading ? (
            <div className="py-12 text-center text-slate-400 animate-pulse">
              Querying honeypot forensics engine for {ip}...
            </div>
          ) : error ? (
            <div className="py-12 text-center text-rose-400">
              {error}
            </div>
          ) : profile ? (
            <>
              {/* Score & Geo Summary */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* Threat Score */}
                <div className="rounded-lg bg-slate-900 border border-slate-800 p-3 flex flex-col justify-between">
                  <span className="text-[10px] text-slate-400 uppercase">Calculated Threat Score</span>
                  <div className="flex items-baseline gap-1 my-1">
                    <span className="text-2xl font-bold text-rose-400">{profile.threat_score}</span>
                    <span className="text-slate-500 text-xs">/ 100</span>
                  </div>
                  <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-rose-500 rounded-full"
                      style={{ width: `${profile.threat_score}%` }}
                    />
                  </div>
                </div>

                {/* Geolocation */}
                <div className="rounded-lg bg-slate-900 border border-slate-800 p-3 flex flex-col justify-between">
                  <span className="text-[10px] text-slate-400 uppercase">Origin Location</span>
                  <div className="font-bold text-slate-100 my-1 truncate">
                    {profile.country_name || 'Unknown'} ({profile.country_code || '??'})
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">
                    City: {profile.city || 'Subnet'}
                  </div>
                </div>

                {/* ASN / ISP */}
                <div className="rounded-lg bg-slate-900 border border-slate-800 p-3 flex flex-col justify-between">
                  <span className="text-[10px] text-slate-400 uppercase">Routing / ASN</span>
                  <div className="font-bold text-cyan-400 my-1 truncate">
                    {profile.asn || 'Unassigned'}
                  </div>
                  <div className="text-[11px] text-slate-400 truncate">
                    {profile.org || 'Internet Host'}
                  </div>
                </div>
              </div>

              {/* Activity Volume & Timestamps */}
              <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-3 space-y-2">
                <span className="text-[10px] text-slate-400 uppercase block font-bold">Activity Window</span>
                <div className="grid grid-cols-3 gap-2 text-[11px]">
                  <div>
                    <span className="text-slate-500 block">Total Events:</span>
                    <span className="text-slate-100 font-bold">{profile.total_events}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">First Seen:</span>
                    <span className="text-slate-300">
                      {new Date(profile.first_seen).toLocaleDateString()} {new Date(profile.first_seen).toLocaleTimeString([], { hour12: false })}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Last Seen:</span>
                    <span className="text-slate-300">
                      {new Date(profile.last_seen).toLocaleDateString()} {new Date(profile.last_seen).toLocaleTimeString([], { hour12: false })}
                    </span>
                  </div>
                </div>
              </div>

              {/* Attempted Credentials */}
              <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-3">
                <div className="flex items-center gap-1.5 text-[10px] text-slate-400 uppercase font-bold mb-2">
                  <KeyRound className="h-3.5 w-3.5 text-amber-400" />
                  <span>Credential Attacks Attempted by this IP</span>
                </div>
                {profile.attempted_creds?.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {profile.attempted_creds.map((c, i) => (
                      <span key={i} className="px-2 py-1 rounded bg-slate-950 text-slate-200 border border-slate-800 text-[11px]">
                        <span className="text-amber-400">{c.username}</span>:<span className="text-rose-400">{c.password}</span>{' '}
                        <span className="text-slate-500">({c.count}x)</span>
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-500 text-[11px] italic">No credentials recorded.</p>
                )}
              </div>

              {/* Commands Executed */}
              <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-3">
                <div className="flex items-center gap-1.5 text-[10px] text-slate-400 uppercase font-bold mb-2">
                  <Terminal className="h-3.5 w-3.5 text-rose-400" />
                  <span>Shell Commands Executed by this IP</span>
                </div>
                {profile.executed_commands?.length > 0 ? (
                  <div className="space-y-1 bg-slate-950 p-2.5 rounded border border-slate-850">
                    {profile.executed_commands.map((cmd, i) => (
                      <div key={i} className="text-slate-100 flex items-center gap-2">
                        <span className="text-rose-400 select-none">#</span>
                        <span className="font-bold">{cmd}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-500 text-[11px] italic">No shell commands executed.</p>
                )}
              </div>

              {/* SSH Scanner Banners */}
              {profile.client_banners?.length > 0 && (
                <div className="rounded-lg bg-slate-900/60 border border-slate-800 p-3">
                  <span className="text-[10px] text-slate-400 uppercase block font-bold mb-2">SSH Client Identifiers</span>
                  <div className="space-y-1 text-[11px] text-slate-300">
                    {profile.client_banners.map((b, i) => (
                      <div key={i} className="bg-slate-950 px-2 py-1 rounded border border-slate-850">
                        {b}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : null}
        </div>

        {/* Modal Footer */}
        <div className="p-3 bg-slate-900 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 text-slate-200 hover:bg-slate-700 font-mono text-xs"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
