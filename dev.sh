#!/usr/bin/env bash
# Starts the backend (with synthetic demo data) and the Vite dev server.
set -e
cd "$(dirname "$0")"
exec make dev
