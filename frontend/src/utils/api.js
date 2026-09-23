// API helpers for SecDash Go Backend

const API_BASE = '/api';

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  return res.json();
}

export async function fetchOverviewStats() {
  const res = await fetch(`${API_BASE}/stats/overview`);
  return res.json();
}

export async function fetchTimeline(limit = 24) {
  const res = await fetch(`${API_BASE}/stats/timeline?limit=${limit}`);
  return res.json();
}

export async function fetchTopCountries(limit = 10) {
  const res = await fetch(`${API_BASE}/stats/countries?limit=${limit}`);
  return res.json();
}

export async function fetchTopCredentials(limit = 15) {
  const res = await fetch(`${API_BASE}/stats/credentials?limit=${limit}`);
  return res.json();
}

export async function fetchTopCommands(limit = 15) {
  const res = await fetch(`${API_BASE}/stats/commands?limit=${limit}`);
  return res.json();
}

export async function fetchEvents({ limit = 50, type = '', ip = '' } = {}) {
  const params = new URLSearchParams();
  if (limit) params.append('limit', limit);
  if (type) params.append('type', type);
  if (ip) params.append('ip', ip);
  const res = await fetch(`${API_BASE}/events?${params.toString()}`);
  return res.json();
}

export async function fetchSessions(limit = 30) {
  const res = await fetch(`${API_BASE}/sessions?limit=${limit}`);
  return res.json();
}

export async function fetchSessionCommands(sessionID) {
  const res = await fetch(`${API_BASE}/sessions/${sessionID}/commands`);
  return res.json();
}

export async function fetchMalwareFiles(limit = 30) {
  const res = await fetch(`${API_BASE}/threats/files?limit=${limit}`);
  return res.json();
}

export async function fetchIPProfile(ip) {
  const res = await fetch(`${API_BASE}/threats/ip/${encodeURIComponent(ip)}`);
  if (!res.ok) throw new Error('IP not found');
  return res.json();
}

export async function fetchBotnetFingerprints(limit = 30) {
  const res = await fetch(`${API_BASE}/stats/fingerprints?limit=${limit}`);
  return res.json();
}

export async function fetchSessionAIAnalysis(sessionID) {
  const res = await fetch(`${API_BASE}/sessions/${sessionID}/ai-analysis`, { method: 'POST' });
  if (!res.ok) throw new Error('AI Analysis failed');
  return res.json();
}

export async function fetchSessionKillChain(sessionID) {
  const res = await fetch(`${API_BASE}/sessions/${sessionID}/killchain`);
  return res.json();
}

export async function fetchWebhooks() {
  const res = await fetch(`${API_BASE}/webhooks`);
  return res.json();
}

export async function createWebhook(data) {
  const res = await fetch(`${API_BASE}/webhooks`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create webhook');
  return res.json();
}

export async function deleteWebhook(id) {
  const res = await fetch(`${API_BASE}/webhooks/${id}`, { method: 'DELETE' });
  return res.json();
}

export async function testWebhook(id) {
  const res = await fetch(`${API_BASE}/webhooks/${id}/test`, { method: 'POST' });
  return res.json();
}

export async function fetchWebhookLogs() {
  const res = await fetch(`${API_BASE}/webhooks/logs`);
  return res.json();
}

export async function fetchAlloyConfig() {
  const res = await fetch(`${API_BASE}/config/alloy`);
  return res.json();
}

export async function sendTestAlloyPayload() {
  const sampleLoki = {
    streams: [
      {
        stream: { app: 'cowrie', honeypot: 'test-node' },
        values: [
          [
            `${Date.now()}000000`,
            JSON.stringify({
              eventid: 'cowrie.login.failed',
              timestamp: new Date().toISOString(),
              session: 'test' + Math.random().toString(16).substring(2, 8),
              src_ip: '185.220.101.5',
              src_port: 43210,
              dst_port: 22,
              protocol: 'ssh',
              username: 'admin',
              password: 'P@ssw0rd' + Math.floor(Math.random() * 999),
              message: 'Test alloy ingestion event',
            }),
          ],
        ],
      },
    ],
  };

  const res = await fetch(`${API_BASE}/ingest/loki`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sampleLoki),
  });
  return res.status;
}

// WebSocket connection utility with auto-reconnect
export function createAttackStream(onEvent, onStatusChange) {
  let ws = null;
  let reconnectTimer = null;
  let isClosedExplicitly = false;

  function connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws`;

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      if (onStatusChange) onStatusChange(true);
    };

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        if (data.type === 'welcome') return;
        if (onEvent) onEvent(data);
      } catch (err) {
        console.error('WS parse error:', err);
      }
    };

    ws.onclose = () => {
      if (onStatusChange) onStatusChange(false);
      if (!isClosedExplicitly) {
        reconnectTimer = setTimeout(connect, 3000);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }

  connect();

  return {
    close: () => {
      isClosedExplicitly = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    },
  };
}

export async function banThreatIP(ip, reason) {
  const res = await fetch(`${API_BASE}/threats/ip/${ip}/ban`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason })
  });
  if (!res.ok) throw new Error('Failed to ban IP');
  return res.json();
}
