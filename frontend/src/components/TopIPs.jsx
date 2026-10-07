import React from 'react';
import { Target } from 'lucide-react';

export default function TopIPs({ ips = [], onSelectIP }) {
  if (!ips || ips.length === 0) return null;

  const maxCount = Math.max(...ips.map(ip => ip.count), 1);

  return (
    <div className="bg-[#0b1120] border border-slate-800 rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-sm font-mono font-bold text-rose-400 flex items-center gap-2">
          <Target className="h-4 w-4" /> RECURRENT THREAT ACTORS
        </h2>
        <span className="text-xs font-mono text-slate-500">Top {ips.length} IPs</span>
      </div>
      
      <div className="space-y-3">
        {ips.map((ipObj, idx) => {
          const pct = Math.max((ipObj.count / maxCount) * 100, 2);
          return (
            <div 
              key={ipObj.ip} 
              className="bg-[#060913] border border-slate-800 rounded p-3 hover:border-slate-700 transition-colors cursor-pointer group"
              onClick={() => onSelectIP && onSelectIP(ipObj.ip)}
            >
              <div className="flex justify-between items-end mb-2">
                <div className="font-mono text-sm text-slate-300 font-bold group-hover:text-cyan-400 transition-colors">
                  {ipObj.ip}
                </div>
                <div className="font-mono text-xs text-rose-500 font-bold">
                  {ipObj.count.toLocaleString()} <span className="text-slate-500 font-normal">hits</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="text-[10px] font-mono text-slate-500 w-6 shrink-0">
                  {ipObj.country_code || '??'}
                </div>
                <div className="flex-1 h-1 bg-slate-900 rounded overflow-hidden">
                  <div 
                    className="h-full bg-rose-500/80 rounded" 
                    style={{ width: `${pct}%` }} 
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
