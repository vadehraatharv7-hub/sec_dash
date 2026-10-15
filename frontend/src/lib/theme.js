// Shared vocabularies: event kinds, attacker classes, outcomes, risk levels.

export const RISK = {
  critical: { label: 'Critical', color: '#ff5d73' },
  high: { label: 'High', color: '#ff9a4d' },
  medium: { label: 'Medium', color: '#f5c451' },
  low: { label: 'Low', color: '#5aa9ff' },
};

export function riskColor(score) {
  if (score >= 80) return RISK.critical.color;
  if (score >= 60) return RISK.high.color;
  if (score >= 35) return RISK.medium.color;
  return RISK.low.color;
}

export const CLASSES = {
  malware_dropper: { label: 'Malware dropper', color: '#ff5d73', hint: 'Downloaded a payload onto the honeypot' },
  intruder: { label: 'Intruder', color: '#ff9a4d', hint: 'Logged in and ran shell commands' },
  compromiser: { label: 'Credential validator', color: '#f5c451', hint: 'Logged in but ran nothing' },
  web_exploiter: { label: 'Web exploiter', color: '#e879f9', hint: 'Sent exploit requests to the web honeypot' },
  brute_forcer: { label: 'Brute-forcer', color: '#a78bfa', hint: 'Guessed credentials without success' },
  web_recon: { label: 'Web recon', color: '#5aa9ff', hint: 'Probed the web honeypot' },
  scanner: { label: 'Scanner', color: '#7d8ba3', hint: 'Connected without authenticating' },
};

export const OUTCOMES = {
  malware: { label: 'Malware dropped', color: '#ff5d73' },
  intrusion: { label: 'Intrusion', color: '#ff9a4d' },
  login_only: { label: 'Login only', color: '#f5c451' },
  brute_force: { label: 'Brute force', color: '#a78bfa' },
  web: { label: 'Web probe', color: '#5aa9ff' },
  scan: { label: 'Scan', color: '#7d8ba3' },
};
export const OUTCOME_ORDER = ['malware', 'intrusion', 'login_only', 'brute_force', 'web', 'scan'];

export const KINDS = {
  connect: { label: 'Connect', color: '#7d8ba3' },
  client_version: { label: 'Banner', color: '#7d8ba3' },
  login_failed: { label: 'Login failed', color: '#a78bfa' },
  login_success: { label: 'Login OK', color: '#f5c451' },
  command: { label: 'Command', color: '#ff9a4d' },
  command_failed: { label: 'Command failed', color: '#b4c0d4' },
  download: { label: 'Download', color: '#ff5d73' },
  upload: { label: 'Upload', color: '#ff5d73' },
  tcp_forward: { label: 'Tunnel', color: '#e879f9' },
  close: { label: 'Close', color: '#56647c' },
  http_request: { label: 'HTTP', color: '#5aa9ff' },
  other: { label: 'Other', color: '#56647c' },
};

export const CATEGORIES = {
  recon: { label: 'Recon', color: '#5aa9ff' },
  download: { label: 'Download', color: '#ff5d73' },
  execution: { label: 'Execution', color: '#ff9a4d' },
  persistence: { label: 'Persistence', color: '#e879f9' },
  evasion: { label: 'Evasion', color: '#f5c451' },
  credential: { label: 'Credential', color: '#a78bfa' },
  miner: { label: 'Cryptominer', color: '#ff5d73' },
  reverse_shell: { label: 'Reverse shell', color: '#ff5d73' },
  destructive: { label: 'Destructive', color: '#ff5d73' },
  exploit: { label: 'Exploit', color: '#ff5d73' },
  other: { label: 'Other', color: '#7d8ba3' },
};

export const SERIES = [
  { key: 'connect', label: 'Connections', color: '#4a6a92' },
  { key: 'failed', label: 'Failed logins', color: '#a78bfa' },
  { key: 'web', label: 'Web requests', color: '#5aa9ff' },
  { key: 'success', label: 'Successful logins', color: '#f5c451' },
  { key: 'command', label: 'Commands', color: '#ff9a4d' },
  { key: 'malware', label: 'Payloads', color: '#ff5d73' },
];

export const STATUS = {
  live: { label: 'Live', color: '#3ddc97' },
  idle: { label: 'Idle', color: '#f5c451' },
  silent: { label: 'Silent', color: '#ff5d73' },
  never: { label: 'No data', color: '#56647c' },
};

export const RANGES = [
  { id: '1h', label: '1h' },
  { id: '6h', label: '6h' },
  { id: '24h', label: '24h' },
  { id: '7d', label: '7d' },
  { id: '30d', label: '30d' },
  { id: 'all', label: 'All' },
];
