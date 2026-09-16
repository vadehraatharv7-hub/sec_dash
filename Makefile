.PHONY: all setup build run run-backend run-frontend clean

export PATH := $(HOME)/.local/go/bin:$(HOME)/go/bin:$(PATH)

all: build

setup:
	@echo "==> Setting up Go backend dependencies..."
	cd backend && go mod download
	@echo "==> Setting up Frontend dependencies..."
	cd frontend && npm install

build:
	@echo "==> Building Go backend..."
	cd backend && go build -o bin/server cmd/server/main.go
	@echo "==> Building Frontend..."
	cd frontend && npm run build

run-backend:
	@echo "==> Running Go backend on :8080..."
	cd backend && go run cmd/server/main.go

run-frontend:
	@echo "==> Running Vite React frontend on :5173..."
	cd frontend && npm run dev

run:
	@echo "==> Launching SecDash Honeypot Full Stack..."
	@trap 'kill 0' SIGINT SIGTERM EXIT; \
	(cd backend && go run cmd/server/main.go) & \
	(cd frontend && npm run dev) & \
	wait

clean:
	rm -rf backend/bin backend/data frontend/dist
