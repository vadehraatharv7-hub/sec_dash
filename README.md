# SecDash — Enterprise Cowrie Honeypot Threat Operations Center

[![SecDash CI/CD](https://github.com/vadehraatharv7-hub/sec_dash/actions/workflows/ci.yml/badge.svg)](https://github.com/vadehraatharv7-hub/sec_dash/actions/workflows/ci.yml)

A high-performance security dashboard, real-time logstream, and threat intelligence engine designed specifically for **Cowrie SSH/Telnet honeypots**. 

Built with a **Golang backend** for ultra-high throughput (~3.7x higher than FastAPI/Node.js, sub-millisecond query latency) and an enterprise **React 19 + Tailwind CSS** Security Operations Center (SOC) frontend.

Replaces the Grafana/Loki pipeline with direct, low-latency ingestion via Grafana Alloy.

---

## ⚡ Key Capabilities & Architecture

### 1. The Real-Time Terminal Stream (WebSockets)
- Tailing raw honeypot events in real-time over WebSockets (`ws://localhost:8080/ws`).
- Structured audit logs displaying timestamps, event IDs, source IPs, target ports, credentials, and executed commands.
- Includes **grep regex filtering**, severity level selector (`CRITICAL`, `HIGH`, `WARN`, `INFO`), **autoscroll lock/free**, and one-click `.log` file export.

### 2. The Credential Harvesting Wall
- Complete credential intelligence matrix aggregating all attempted username:password combinations.
- Real-time brute-force volume counters and complexity/entropy classification (Trivial/Default vs Dictionary).
- One-click **"Export Wordlist (.txt)"** button to export discovered credentials for firewall blocklists and password audit dictionaries.

### 3. Attack Velocity & Threat Counters
- Executive threat counters:
  - **Attack Velocity & Throughput**
  - **Compromise Ratio (%)**: Ratio of sessions that successfully breached authentication into the honeypot sandbox
  - **Adversary Routing**: Unique Autonomous System Numbers (ASNs)
  - **Intercepted Shell Commands**
  - **Captured Loot Payloads**
  - **Average Adversary Session Dwell Time**

### 4. Payload Extraction (The "Loot" Tab)
- Isolated sandbox vault for malware binaries and shell scripts dropped via `wget`, `curl`, or `tftp`.
- Computes SHA-256 and MD5 hashes with one-click copy.
- Automatic architecture detection (e.g. `ELF 32-bit ARM (IoT)`, `ELF 32-bit MIPS (Router)`, `POSIX Shell Script`).
- Integrated **VirusTotal lookup** and **Decompilation Strings Preview** drawer.

### 5. IP Geolocation Heatmap & Global Sensor Radar
- Interactive **Leaflet map** rendered with **CartoDB Dark Matter** dark-mode tiles.
- Vector markers for active threat origin hotspots with attack volume radius scaling.
- Trajectory arcs connecting adversary locations directly to the Honeypot sensor node.
- Real-time country leaderboard with search filter and click-to-center navigation.

### 6. LLM-Powered Threat Profiling ("AI Analysis")
- Route completed adversary session transcripts through an automated threat triage engine.
- An **"AI Analysis"** button next to each recorded session.
- Classifies:
  - **Attacker Intent & Primary Objective** (e.g., *Cryptomining Botnet Deployment*, *Host Fingerprinting*, *Mirai/Mozi IoT Dropper*)
  - **Skill Level Assessment** (*Automated Worm*, *Script Kiddie*, *Skilled Intruder*, *APT*)
  - **Confidence Score & Threat Category**
  - **MITRE ATT&CK TTP Mapping** with evidentiary shell commands
  - **Actionable Remediation & Defense Advice**
- Seamlessly uses **Google Gemini 1.5 Flash** if `GEMINI_API_KEY` is provided, with an intelligent built-in cybersecurity heuristic engine fallback.

### 7. Botnet Fingerprinting (HASSH & Client Strings)
- Tracks and groups SSH client version banners (`cowrie.client.version`).
- Classifies botnet families:
  - *Libssh Automated Scanner*
  - *Paramiko Python Brute-Forcer*
  - *Go-Based Mirai/Dropper Variant*
  - *PuTTY Manual Intrusion*
  - *Masscan Port Sweeper*
- Displays fleet percentage share, first seen, and last seen timestamps.

### 8. The "Kill Chain" Session Timeline
- Visual 7-phase **Cyber Kill Chain** progression modal for any recorded session:
  1. *Reconnaissance* (Port scanning / banner grabbing)
  2. *Weaponization & Delivery* (Credential stuffing)
  3. *Exploitation* (Initial access / pseudo-terminal allocated)
  4. *Discovery & Enumeration* (`uname -a`, `cpuinfo`, `id`, `whoami`)
  5. *Ingress Tool Transfer* (`wget`, `curl -O`, payload download)
  6. *Execution & Persistence* (`chmod +x`, `crontab`, background execution)
  7. *Defense Evasion & Action on Objective* (`rm -rf`, `history -c`, `iptables -F`)
- Clear status badges (`ACHIEVED`, `BLOCKED`, `INACTIVE`) with timestamps and command evidence.

### 9. Custom Webhook Alerting Engine
- Configure instant webhook alerts for **Slack**, **Discord**, and **Generic JSON endpoints**.
- Granular triggers:
  - Alert on Shell Breach (`cowrie.login.success`)
  - Alert on Malware Dropped (`cowrie.session.file_download`)
  - Alert on Critical Ingress Commands (`wget`, `curl | sh`, `rm -rf`)
- Diagnostic test ping button and real-time dispatch audit logs with HTTP response codes.

---

## 🚀 Getting Started

### 1. Launch the Stack
```bash
./dev.sh
```
or
```bash
make run
```

- **Frontend Dashboard**: [http://localhost:5173](http://localhost:5173)
- **Backend Ingestion API**: `http://localhost:8080`
- **Real-Time WebSocket Feed**: `ws://localhost:8080/ws`

### 2. Connect Grafana Alloy
In your Grafana Alloy configuration (`/etc/alloy/config.alloy` or `backend/alloy/config.alloy`):

```alloy
local.file_match "cowrie_logs" {
  path_targets = [{
    __path__ = "/var/log/cowrie/cowrie.json*",
    app      = "cowrie",
  }]
  sync_period = "5s"
}

loki.source.file "cowrie_collector" {
  targets    = local.file_match.cowrie_logs.targets
  forward_to = [loki.write.secdash.receiver]
}

loki.write "secdash" {
  endpoint {
    url = "http://127.0.0.1:8080/api/ingest/loki"
  }
}
```

Then run Alloy:
```bash
alloy run backend/alloy/config.alloy
```
