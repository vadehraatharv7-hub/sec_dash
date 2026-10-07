import React, { useState } from 'react';
import { Server, Key, User, Play, AlertCircle, CheckCircle2, Loader2 } from 'lucide-react';
import { provisionHoneypot } from '../utils/api';

export default function ProvisionHoneypot() {
  const [formData, setFormData] = useState({
    ip: '',
    username: 'root',
    privateKey: '',
    type: 'cowrie',
  });
  
  const [status, setStatus] = useState('idle');
  const [message, setMessage] = useState('');

  const handleChange = (e) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus('loading');
    setMessage('');
    
    try {
      const payload = {
        ip: formData.ip,
        username: formData.username,
        rsa_key: formData.privateKey,
        type: formData.type
      };
      const res = await provisionHoneypot(payload);
      setStatus('success');
      setMessage(res.message || 'Honeypot successfully provisioned.');
      setFormData({ ip: '', username: 'root', privateKey: '', type: 'cowrie' });
    } catch (err) {
      setStatus('error');
      setMessage(err.message || 'An error occurred during provisioning.');
    }
  };

  return (
    <div className="max-w-2xl mx-auto mt-6 bg-[#0b1120] border border-slate-800 rounded-lg p-6 shadow-xl">
      <div className="flex items-center gap-3 mb-6 border-b border-slate-800 pb-4">
        <div className="h-10 w-10 bg-cyan-500/10 rounded flex items-center justify-center border border-cyan-500/30">
          <Server className="h-5 w-5 text-cyan-400" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-slate-100 font-mono">Remote Honeypot Provisioning</h2>
          <p className="text-sm text-slate-400">Deploy a new sensor onto a remote server.</p>
        </div>
      </div>

      {status === 'success' && (
        <div className="mb-6 p-4 rounded bg-emerald-500/10 border border-emerald-500/30 flex gap-3 text-emerald-400">
          <CheckCircle2 className="h-5 w-5 shrink-0" />
          <p className="text-sm">{message}</p>
        </div>
      )}

      {status === 'error' && (
        <div className="mb-6 p-4 rounded bg-rose-500/10 border border-rose-500/30 flex gap-3 text-rose-400">
          <AlertCircle className="h-5 w-5 shrink-0" />
          <p className="text-sm">{message}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-5">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div className="space-y-2">
            <label className="text-xs font-bold text-slate-300 font-mono flex items-center gap-2">
              <Server className="h-3.5 w-3.5 text-slate-500" /> Server IP Address
            </label>
            <input
              required
              type="text"
              name="ip"
              value={formData.ip}
              onChange={handleChange}
              placeholder="e.g. 192.168.1.100"
              className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
          </div>

          <div className="space-y-2">
            <label className="text-xs font-bold text-slate-300 font-mono flex items-center gap-2">
              <User className="h-3.5 w-3.5 text-slate-500" /> SSH Username
            </label>
            <input
              required
              type="text"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="root"
              className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono"
            />
          </div>
        </div>

        <div className="space-y-2">
          <label className="text-xs font-bold text-slate-300 font-mono flex items-center gap-2">
            <Key className="h-3.5 w-3.5 text-slate-500" /> RSA Private Key
          </label>
          <textarea
            required
            name="privateKey"
            value={formData.privateKey}
            onChange={handleChange}
            placeholder="-----BEGIN RSA PRIVATE KEY-----..."
            rows={5}
            className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-sm text-slate-200 placeholder-slate-600 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono resize-y"
          />
        </div>

        <div className="space-y-2">
          <label className="text-xs font-bold text-slate-300 font-mono flex items-center gap-2">
            <Play className="h-3.5 w-3.5 text-slate-500" /> Honeypot Type
          </label>
          <select
            name="type"
            value={formData.type}
            onChange={handleChange}
            className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-sm text-slate-200 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-mono appearance-none"
          >
            <option value="cowrie">Cowrie (SSH/Telnet)</option>
            <option value="snare">Snare (Web App)</option>
          </select>
        </div>

        <div className="pt-4 flex justify-end">
          <button
            type="submit"
            disabled={status === 'loading'}
            className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-6 py-2.5 rounded text-sm font-mono flex items-center gap-2 transition-colors disabled:opacity-70 disabled:cursor-not-allowed"
          >
            {status === 'loading' ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Provisioning...
              </>
            ) : (
              <>
                <Server className="h-4 w-4" /> Provision Sensor
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
