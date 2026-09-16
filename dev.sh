#!/usr/bin/env bash
set -e

export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"

echo "========================================================"
echo "🛡️  SecDash Honeypot Security Operations Center Launch"
echo "========================================================"

# Trap to kill both processes on Ctrl+C
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT SIGINT SIGTERM

echo "==> Starting Golang High-Throughput Engine on :8080..."
(cd backend && ./bin/server) &
BACKEND_PID=$!

echo "==> Starting React + Tailwind SOC Frontend on :5173..."
(cd frontend && npm run dev) &
FRONTEND_PID=$!

echo ""
echo "✅ Both services running:"
echo "   - Frontend UI:  http://localhost:5173"
echo "   - Backend API:  http://localhost:8080"
echo "   - WebSocket:    ws://localhost:8080/ws"
echo ""
echo "Press [Ctrl+C] to stop all services."

wait
