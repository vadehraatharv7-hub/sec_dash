# SecDash - honeypot analytics

Turns raw honeypot logs (Cowrie SSH/Telnet, Snare/Tanner web) into answers: who is attacking, how far they got,
which attackers are the same operation, what malware they dropped and which ATT&CK techniques they used.

```
Cowrie / Snare --> Vector / forwarder --> POST /api/ingest/stream --> SecDash backend (Go) --> MongoDB / Cosmos DB
                                                                          |  in-memory analytics + WebSocket
                                                                          v
                                                                  React dashboard  (+ /api/threats/banned -> xdp-shield)
```

## What's in the dashboard

| Area | Page | What it answers |
|---|---|---|
| Monitor | **Command Center** | KPIs with change vs the previous period, "needs attention" insights, activity timeline, attack funnel (scan -> login -> shell -> payload), map, top countries/networks/ports, weekday x hour heatmap |
| | **Live Feed** | Every event as it arrives (WebSocket), filterable |
| | **Threat Map** | Offline world map; bubble size = events, colour = highest risk at that location |
| Investigate | **Attackers** | Every source IP with a 0-100 risk score, behaviour class (scanner, brute-forcer, credential validator, intruder, malware dropper, web recon/exploiter) and credential style (dictionary, spraying, stuffing). Profile drawer with credentials, commands, sessions, ATT&CK techniques, one-click block |
| | **Sessions** | Reconstructed sessions, **replayable** command transcript, 7-stage kill chain, analysis and recommended actions |
| | **Campaigns** | IPs linked by shared payload hash, payload URL or identical command playbook; named when a known family matches |
| | **Credentials** | Top users/passwords/pairs, which guesses were *accepted*, default-credential share, password lengths |
| | **Commands** | Commands grouped and classified (recon, download, persistence, evasion, miner...), recurring playbooks |
| | **Malware & IOCs** | Captured samples, download URLs/hosts, export of IP blocklist / CSV / JSON |
| Detect & respond | **ATT&CK Coverage** | Matrix of observed MITRE ATT&CK techniques; click through to the sessions |
| | **Alerts** | Slack / Discord / generic webhooks, rate-limited per IP |
| | **Blocklist** | Blocked IPs; `GET /api/threats/banned` is what **xdp-shield** polls |
| Infrastructure | **Sensors** | Health (live / idle / silent), volume sparkline, how to add a sensor |

The range selector (1h-30d, All) and sensor selector in the header apply to every page.

## Run it locally

Needs Go and Node.

```bash
make setup
make demo        # synthetic attack traffic, no database needed -> http://localhost:8080
```

`make dev` runs the Vite dev server (hot reload, :5173) against a demo backend.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `MONGO_URI` | unset | MongoDB / Azure Cosmos DB (Mongo API). Unset = memory-only |
| `PORT` | `8080` | HTTP port |
| `STATIC_DIR` | auto (`../frontend/dist`) | Built frontend |
| `MAX_EVENTS` | `250000` | Events held in memory for analytics (older stay in the database). About 0.45 KB each, plus roughly 0.35 KB each for every cached analytics view. The Ansible role sets `100000` for the 1 GB monitoring VM |
| `GEO_ONLINE` | on | Set `0` to disable the online IP-location fallback (ip-api.com batch endpoint; sends attacker IPs to that service) |
| `GEOIP_CITY_DB`, `GEOIP_ASN_DB` | auto | Path to MaxMind-format `.mmdb` files (GeoLite2 or DB-IP). Preferred over the online fallback |
| `DASH_ADMIN_USER`, `DASH_ADMIN_PASSWORD` | unset | Creates (or resets) a dashboard admin account at startup; password min. 8 chars, stored bcrypt-hashed. With any account present the dashboard shows a username/password login and issues 12-hour signed session tokens |
| `DASH_TOKEN` | unset | If set, the dashboard shows a login screen and every API call and the live stream require the token (`Authorization: Bearer`). Still open: `/api/health`, sensor ingest, and `GET /api/threats/banned` (xdp-shield polls it without a token). Ten wrong tokens in a minute lock the address out for a minute |
| `DEMO` | unset | `1` seeds ~10 days of synthetic traffic |

## How it works

* **Ingest** - `POST /api/ingest/stream[?sensor=name]` accepts a JSON object, array or NDJSON of Cowrie-style events
  (`eventid`, `src_ip`, ...). Events are normalized, geolocated, stored in MongoDB and pushed to the browser.
* **Analytics** - the newest `MAX_EVENTS` events are indexed in memory. Sessions, attackers, campaigns and every
  chart are derived per request from the selected window (cached for a few seconds), so the database is only
  used for writes and one load at startup. That keeps Cosmos DB request-unit usage low.
* **Locations** - never invented. Unresolved IPs have no location until a `.mmdb` or the online fallback resolves them.
* **Detection logic** - `backend/internal/intel` holds the command/web-request signatures and ATT&CK mapping;
  `backend/internal/analytics` holds scoring and campaign clustering. Both are covered by unit tests (`make test`).

## API (selection)

`GET /api/overview|geo|attackers|attackers/{ip}|sessions|sessions/{id}|campaigns|credentials|commands|malware|mitre|sensors|iocs|events`
take `range` (`1h 6h 24h 7d 30d all`) and `sensor`. `GET /api/threats/banned` returns `[{ip, reason, banned_at}]`.
`/ws` streams new events.

## Notes

* Set `DASH_TOKEN` in production. The Ansible monitoring role generates an `admin` password (`~/.secdash_admin_password`) and an API token for scripts (`~/.secdash_token`) on the controller and writes both to the VM. Traffic is plain HTTP unless you add TLS in front, so the token is visible to anyone on the path.
* Webhook targets that resolve to private/loopback addresses are refused.
* The optional AI summary of earlier versions (Gemini) and server-side Ansible provisioning were removed:
  analysis is now a local rule engine, and sensors are deployed with the Ansible roles in `honeypot-infra`.
