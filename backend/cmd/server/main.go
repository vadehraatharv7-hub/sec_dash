package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sec_dash/backend/internal/api"
	"sec_dash/backend/internal/db"
	"sec_dash/backend/internal/ingest"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./data/secdash.db"
	}

	log.Println("==================================================")
	log.Println("🛡️  SecDash Honeypot Production Engine (Golang)")
	log.Println("==================================================")

	// 1. Initialize SQLite storage engine with WAL mode
	storage, err := db.NewStorage(dbPath)
	if err != nil {
		log.Fatalf("Fatal: Database initialization failed: %v", err)
	}
	defer storage.Close()

	// 2. Initialize Parser & WebSocket Hub
	parser := ingest.NewParser()
	hub := api.NewHub()
	go hub.Run()

	// 3. Initialize HTTP Server
	server := api.NewServer(storage, parser, hub)
	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      server.Routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown channel
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("[HTTP] High-throughput API & Ingestion server listening on http://0.0.0.0:%s", port)
		log.Printf("[HTTP] Production Ingestion endpoints:")
		log.Printf("       -> POST http://0.0.0.0:%s/api/ingest/cowrie (Raw Cowrie JSON / Array / NDJSON)", port)
		log.Printf("       -> POST http://0.0.0.0:%s/api/ingest/loki   (Grafana Alloy loki.write)", port)
		log.Printf("       -> POST http://0.0.0.0:%s/loki/api/v1/push (Standard Loki Push API)", port)
		log.Printf("       -> WS   ws://0.0.0.0:%s/ws                (Real-time live attack stream)", port)

		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stop
	log.Println("\n[Server] Shutting down gracefully...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("[Server] Shutdown error: %v", err)
	}

	fmt.Println("🛡️  SecDash Honeypot backend stopped cleanly.")
}
