const TOKEN_KEY = 'secdash.token';

export const getToken = () => {
  try { return localStorage.getItem(TOKEN_KEY) || ''; } catch { return ''; }
};
export const setToken = (t) => {
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  } catch { /* ignore */ }
};

export class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function qs(params) {
  const u = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '' && v !== 'all') u.set(k, v);
  });
  const s = u.toString();
  return s ? `?${s}` : '';
}

export async function api(path, { params, method = 'GET', body, signal } = {}) {
  const headers = {};
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(`/api${path}${qs(params)}`, {
    method, headers, signal, body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch { /* not json */ }
    throw new ApiError(res.status, msg);
  }
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

export const downloadUrl = (path, params) => `/api${path}${qs(params)}`;
