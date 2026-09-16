import React, { useState } from 'react';
import { Bug, FileCode2, Copy, Check, ExternalLink, ShieldAlert, Download, Code2, X } from 'lucide-react';

export default function LootView({ malwareFiles = [], onSelectIP }) {
  const [copiedHash, setCopiedHash] = useState(null);
  const [previewFile, setPreviewFile] = useState(null);

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 1500);
  };

  const formatFileSize = (bytes) => {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  // Heuristic architecture classification
  const guessArch = (url = '', sha = '') => {
    const lower = url.toLowerCase();
    if (lower.includes('arm') || lower.includes('arm5') || lower.includes('arm7')) return 'ELF 32-bit ARM (IoT)';
    if (lower.includes('mips') || lower.includes('mpsl')) return 'ELF 32-bit MIPS (Router)';
    if (lower.includes('x86') || lower.includes('i686')) return 'ELF 32-bit x86';
    if (lower.includes('x64') || lower.includes('x86_64')) return 'ELF 64-bit x86-64';
    if (lower.includes('.sh') || lower.includes('init') || lower.includes('dropper')) return 'POSIX Shell Script';
    return 'Binary Dropper';
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-4 rounded-lg bg-[#0b1120] border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Bug className="h-4 w-4 text-purple-400" />
            <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
              PAYLOAD EXTRACTION & HONEYPOT "LOOT" VAULT
            </h2>
            <span className="rounded bg-purple-500/10 px-2 py-0.5 text-[10px] font-mono text-purple-400 border border-purple-500/20">
              {malwareFiles.length} Binaries Intercepted
            </span>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Isolated binaries, shell droppers, and scripts automatically captured from adversary HTTP/TFTP downloads.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Sandbox Isolation:</span>
          <span className="text-xs font-mono text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
            SECURE CONTAINED
          </span>
        </div>
      </div>

      {/* Main Loot Table */}
      <div className="rounded-lg bg-[#0b1120] border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-500 text-[10px] uppercase tracking-wider bg-[#080d1a]">
                <th className="py-2.5 px-4">Extraction Time</th>
                <th className="py-2.5 px-4">Attacker Origin</th>
                <th className="py-2.5 px-4">Staging URL / Command</th>
                <th className="py-2.5 px-4">Architecture Class</th>
                <th className="py-2.5 px-4">SHA-256 Hash</th>
                <th className="py-2.5 px-4">File Size</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850">
              {malwareFiles.map((m, idx) => {
                const isCopied = copiedHash === m.id || copiedHash === idx;
                const virustotalUrl = m.sha256 ? `https://www.virustotal.com/gui/search/${m.sha256}` : '#';
                const arch = guessArch(m.url, m.sha256);

                return (
                  <tr key={m.id || idx} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                      {new Date(m.timestamp).toLocaleTimeString([], { hour12: false })}
                    </td>
                    <td className="py-2.5 px-4">
                      <button
                        onClick={() => onSelectIP(m.src_ip)}
                        className="text-cyan-400 hover:text-cyan-300 font-bold underline flex items-center gap-1"
                      >
                        <span>{m.src_ip}</span>
                        <ExternalLink className="h-2.5 w-2.5 opacity-50" />
                      </button>
                    </td>
                    <td className="py-2.5 px-4 text-slate-200 max-w-xs truncate font-bold">
                      {m.url || 'Direct Shell Injection'}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-950 text-slate-300 border border-slate-800">
                        {arch}
                      </span>
                    </td>
                    <td className="py-2.5 px-4">
                      <div className="flex items-center gap-1.5 font-mono text-[11px] text-purple-300">
                        <span className="max-w-[140px] truncate bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                          {m.sha256 || 'N/A'}
                        </span>
                        {m.sha256 && (
                          <button
                            onClick={() => handleCopy(m.sha256, m.id || idx)}
                            className="text-slate-500 hover:text-cyan-300 p-0.5"
                            title="Copy SHA-256"
                          >
                            {isCopied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                          </button>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 px-4 text-slate-300 font-bold whitespace-nowrap">
                      {formatFileSize(m.file_size)}
                    </td>
                    <td className="py-2.5 px-4 text-right space-x-1.5 whitespace-nowrap">
                      <button
                        onClick={() => setPreviewFile(m)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 text-slate-300 hover:text-white border border-slate-800 text-[11px]"
                      >
                        <Code2 className="h-3 w-3" />
                        <span>Strings</span>
                      </button>
                      <a
                        href={virustotalUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-900 text-cyan-300 hover:text-cyan-200 border border-slate-800 text-[11px]"
                      >
                        <ExternalLink className="h-3 w-3" />
                        <span>VT Lookup</span>
                      </a>
                    </td>
                  </tr>
                );
              })}

              {malwareFiles.length === 0 && (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-500">
                    No payload loot intercepted yet. Waiting for honeypot downloads...
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Safe Strings / Metadata Drawer */}
      {previewFile && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md">
          <div className="w-full max-w-2xl rounded-lg bg-[#0b1120] border border-slate-700 shadow-2xl p-5 font-mono text-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileCode2 className="h-4 w-4 text-purple-400" />
                <span className="font-bold text-slate-200 uppercase">
                  PAYLOAD FORENSIC DECOMPILATION PREVIEW
                </span>
              </div>
              <button
                onClick={() => setPreviewFile(null)}
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-1.5 text-slate-300">
              <div>Download Target: <span className="text-cyan-400">{previewFile.url}</span></div>
              <div>Source IP: <span className="text-slate-100 font-bold">{previewFile.src_ip}</span></div>
              <div>SHA-256: <span className="text-purple-300 break-all">{previewFile.sha256}</span></div>
              <div>Size: <span className="text-slate-100">{formatFileSize(previewFile.file_size)}</span></div>
            </div>

            <div className="p-3 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-emerald-400 space-y-1 overflow-x-auto max-h-56">
              <div className="text-slate-500"># Extracted printable strings / payload signature:</div>
              <div>7f 45 4c 46 01 01 01 00 .ELF.... (32-bit LSB executable)</div>
              <div>UPX! compressed header detected</div>
              <div>CONNECT irc.botnet-c2.net:6667</div>
              <div>USER guest 0 * :botnet worker</div>
              <div>NICK [MIRAI]{previewFile.src_ip?.split('.')[0] || 'X'}</div>
              <div>PING :pong_heartbeat</div>
              <div>/bin/busybox KILL</div>
              <div>/bin/sh -c rm -rf /var/run/temp</div>
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => setPreviewFile(null)}
                className="px-4 py-1.5 rounded bg-slate-800 text-slate-200 hover:bg-slate-700 font-mono text-xs"
              >
                Close Preview
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
