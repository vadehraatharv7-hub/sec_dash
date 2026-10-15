.PHONY: all setup build test run demo dev clean

all: build

setup:
	cd backend && go mod download
	cd frontend && npm install

build:
	cd backend && go build -o bin/server ./cmd/server
	cd frontend && npm run build

test:
	cd backend && go vet ./... && go test ./...
	cd frontend && npm run lint

# Production-style run: backend serves the built frontend on :8080.
# Needs MONGO_URI (see README); without it the data is kept in memory only.
run: build
	cd backend && STATIC_DIR=../frontend/dist ./bin/server

# Local demo with synthetic attack traffic - no database required.
demo: build
	cd backend && DEMO=1 GEO_ONLINE=0 PORT=8080 STATIC_DIR=../frontend/dist ./bin/server

# Hot-reload UI (Vite on :5173, proxying /api and /ws to a backend on :8080).
dev:
	@trap 'kill 0' SIGINT SIGTERM EXIT; \
	(cd backend && DEMO=1 GEO_ONLINE=0 go run ./cmd/server) & \
	(cd frontend && npm run dev) & \
	wait

clean:
	rm -rf backend/bin frontend/dist
