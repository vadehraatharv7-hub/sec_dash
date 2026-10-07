import React, { useEffect, useState } from 'react';
import { ShieldAlert, ShieldCheck, Trash2, Plus, Clock, Globe } from 'lucide-react';
import { getBannedIPs, banThreatIP, unbanIP } from '../utils/api';

export default function AccessControl() {
  const [bannedIPs, setBannedIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [manualIP, setManualIP] = useState('');
  const [manualReason, setManualReason] = useState('');

  const loadBanned = async () => {
    try {
      const data = await getBannedIPs();
      setBannedIPs(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadBanned();
  }, []);

  const handleBan = async (e) => {
    e.preventDefault();
    if (!manualIP) return;
    try {
      await banThreatIP(manualIP, manualReason || 'Manual ban from Access Control');
      setManualIP('');
      setManualReason('');
      loadBanned();
    } catch (err) {
      alert("Failed to ban IP: " + err.message);
    }
  };

  const handleUnban = async (ip) => {
    try {
      await unbanIP(ip);
      loadBanned();
    } catch (err) {
      alert("Failed to unban IP: " + err.message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-[#0b1120] border border-slate-800 rounded-lg p-6">
        <h2 className="text-sm font-mono font-bold text-cyan-400 mb-4 flex items-center gap-2">
          <ShieldAlert className="h-4 w-4" /> MANUAL IP BAN
        </h2>
        <form onSubmit={handleBan} className="flex gap-4 items-end">
          <div className="flex-1">
            <label className="block text-xs font-mono text-slate-500 mb-1">IP ADDRESS</label>
            <input
              type="text"
              value={manualIP}
              onChange={(e) => setManualIP(e.target.value)}
              placeholder="e.g. 192.168.1.100"
              className="w-full bg-[#060913] border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
          <div className="flex-1">
            <label className="block text-xs font-mono text-slate-500 mb-1">REASON (OPTIONAL)</label>
            <input
              type="text"
              value={manualReason}
              onChange={(e) => setManualReason(e.target.value)}
              placeholder="e.g. Malicious scanning"
              className="w-full bg-[#060913] border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            disabled={!manualIP}
            className="bg-rose-500/20 hover:bg-rose-500/30 text-rose-400 border border-rose-500/50 rounded px-4 py-2 text-sm font-mono flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <Plus className="h-4 w-4" /> BAN IP
          </button>
        </form>
      </div>

      <div className="bg-[#0b1120] border border-slate-800 rounded-lg overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex justify-between items-center">
          <h2 className="text-sm font-mono font-bold text-slate-200 flex items-center gap-2">
            <Globe className="h-4 w-4 text-slate-400" /> BANNED IP LIST
          </h2>
          <span className="text-xs font-mono text-slate-500">{bannedIPs.length} total blocks</span>
        </div>
        
        {loading ? (
          <div className="p-8 text-center text-slate-500 font-mono text-sm">Loading ACL...</div>
        ) : bannedIPs.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-mono text-sm">No IPs currently banned.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm font-mono text-slate-300">
              <thead className="text-xs text-slate-500 bg-[#080d1a] border-b border-slate-800">
                <tr>
                  <th className="px-4 py-3 font-normal">IP ADDRESS</th>
                  <th className="px-4 py-3 font-normal">REASON</th>
                  <th className="px-4 py-3 font-normal">BANNED AT</th>
                  <th className="px-4 py-3 font-normal text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50">
                {bannedIPs.map((b) => (
                  <tr key={b.ip} className="hover:bg-slate-800/20">
                    <td className="px-4 py-3 text-rose-400 font-bold">{b.ip}</td>
                    <td className="px-4 py-3 text-slate-400">{b.reason}</td>
                    <td className="px-4 py-3 text-slate-500">
                      <div className="flex items-center gap-1.5">
                        <Clock className="h-3 w-3" />
                        {new Date(b.banned_at).toLocaleString()}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleUnban(b.ip)}
                        className="text-emerald-400 hover:text-emerald-300 bg-emerald-400/10 hover:bg-emerald-400/20 px-3 py-1 rounded transition-colors text-xs flex items-center gap-1.5 ml-auto"
                      >
                        <ShieldCheck className="h-3 w-3" /> WHITELIST
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
