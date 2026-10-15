import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api, getToken } from './api';

// ---- routing (hash based, so deep links survive static hosting) ------------

function parseHash() {
  const raw = window.location.hash.replace(/^#/, '') || '/';
  const [p, q] = raw.split('?');
  const parts = p.split('/').filter(Boolean).map(decodeURIComponent);
  const query = Object.fromEntries(new URLSearchParams(q || ''));
  return { parts, query };
}

export function useRoute() {
  const [route, setRoute] = useState(parseHash);
  useEffect(() => {
    const on = () => setRoute(parseHash());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return route;
}

export function go(path, query) {
  const q = query ? new URLSearchParams(Object.entries(query).filter(([, v]) => v !== '' && v != null)).toString() : '';
  window.location.hash = `${path}${q ? `?${q}` : ''}`;
}

// ---- global filters --------------------------------------------------------

const FilterCtx = createContext(null);

function load(key, def) {
  try { return localStorage.getItem(key) || def; } catch { return def; }
}

export function FilterProvider({ children }) {
  const [range, setRangeState] = useState(() => load('secdash.range', '24h'));
  const [sensor, setSensorState] = useState(() => load('secdash.sensor', 'all'));
  const setRange = useCallback((v) => { setRangeState(v); try { localStorage.setItem('secdash.range', v); } catch { /* ignore */ } }, []);
  const setSensor = useCallback((v) => { setSensorState(v); try { localStorage.setItem('secdash.sensor', v); } catch { /* ignore */ } }, []);
  const value = useMemo(() => ({ range, sensor, setRange, setSensor }), [range, sensor, setRange, setSensor]);
  return <FilterCtx.Provider value={value}>{children}</FilterCtx.Provider>;
}

export const useFilters = () => useContext(FilterCtx);

// ---- data fetching ---------------------------------------------------------

/**
 * Fetches `path` with the global range/sensor filters merged into `params`.
 * Keeps showing the previous result while a refetch is in flight.
 */
export function useApi(path, params, { interval = 0, filters = true, enabled = true } = {}) {
  const { range, sensor } = useFilters();
  const [state, setState] = useState({ data: null, error: null, loading: true });
  const key = JSON.stringify([path, params, filters ? [range, sensor] : null]);
  const tick = useRef(0);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    if (!enabled || !path) return undefined;
    const ctl = new AbortController();
    const id = ++tick.current;
    setState((s) => ({ ...s, loading: true }));
    const merged = { ...(filters ? { range, sensor } : {}), ...(params || {}) };
    api(path, { params: merged, signal: ctl.signal })
      .then((data) => { if (id === tick.current) setState({ data, error: null, loading: false }); })
      .catch((error) => {
        if (error.name === 'AbortError') return;
        if (id === tick.current) setState((s) => ({ data: s.data, error, loading: false }));
      });
    return () => ctl.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, nonce, enabled]);

  useEffect(() => {
    if (!interval || !enabled) return undefined;
    const t = setInterval(() => { if (!document.hidden) setNonce((n) => n + 1); }, interval);
    return () => clearInterval(t);
  }, [interval, enabled]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { ...state, reload };
}

// ---- live stream -----------------------------------------------------------

/** Connects to /ws and calls onEvent for every pushed event. Returns connection status. */
export function useLive(onEvent) {
  const [status, setStatus] = useState('connecting');
  const cb = useRef(onEvent);
  cb.current = onEvent;
  useEffect(() => {
    let ws; let timer; let closed = false; let attempts = 0;
    const connect = () => {
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
      const token = getToken();
      ws = new WebSocket(`${proto}://${window.location.host}/ws${token ? `?token=${encodeURIComponent(token)}` : ''}`);
      ws.onopen = () => { attempts = 0; setStatus('live'); };
      ws.onmessage = (m) => {
        try {
          const msg = JSON.parse(m.data);
          if (msg.type === 'event') cb.current(msg.event);
        } catch { /* ignore malformed frame */ }
      };
      ws.onclose = () => {
        if (closed) return;
        setStatus('offline');
        timer = setTimeout(connect, Math.min(15000, 1000 * 2 ** attempts++));
      };
      ws.onerror = () => ws.close();
    };
    connect();
    return () => { closed = true; clearTimeout(timer); if (ws) ws.close(); };
  }, []);
  return status;
}

export function useDebounced(value, ms = 300) {
  const [v, setV] = useState(value);
  useEffect(() => { const t = setTimeout(() => setV(value), ms); return () => clearTimeout(t); }, [value, ms]);
  return v;
}

