# SecDash — Enterprise Threat Operations Center

A high-performance security dashboard, real-time logstream, and threat intelligence engine designed specifically for analyzing distributed honeypot traffic.

## 🚀 Architecture Context

This repository is part of a larger Multi-ML Active Defense Architecture, connecting to two other core components:
- **[infra_honeypot](../infra_honeypot)**: Deploys this dashboard along with the honeypots and message brokers.
- **[xpd-shield](../xpd-shield)**: Edge mitigation agent that performs network blocking based on the intelligence surfaced here.

## ⚡ What It Does

SecDash acts as the single pane of glass for the Security Operations Center (SOC). It replaces traditional Grafana/Loki pipelines with direct, low-latency log ingestion.
- **Real-Time Terminal Stream:** WebSockets provide real-time tailing of raw honeypot events, showing executed commands, credentials, and source IPs.
- **Credential Harvesting Wall:** Aggregates attempted usernames and passwords, calculating brute-force volumes and complexity.
- **Threat Counters:** Executive views showing attack velocity, compromise ratios, and adversary routing (ASN tracking).

## 🛠️ Tech Stack
- **Backend:** Golang for ultra-high throughput and sub-millisecond query latency. Exposes REST and WebSocket endpoints.
- **Frontend:** Enterprise React 19 + Tailwind CSS + Vite.
- **Data:** SQLite (with WAL mode) for fast local querying and persistence.

## 📂 Project Structure
- `backend/`: Go API server handling WebSocket streams, database interactions, and log parsing.
- `frontend/`: React application providing the SOC interface.
- `data/`: SQLite databases and schemas.

## 📖 Usage
To run the dashboard locally:
1. Start the Go backend API from the `backend/` directory.
2. Install frontend dependencies: `cd frontend && npm install`.
3. Start the Vite development server: `npm run dev`.
4. The frontend will be available at `http://localhost:5173`.

## 🤝 Open Source Learning
This project demonstrates how to build high-performance, real-time analytics platforms in Go and React, focusing on low latency WebSocket streaming and threat intelligence visualization.
