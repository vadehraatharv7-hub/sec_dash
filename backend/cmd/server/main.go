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
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	log.Println("==================================================")
	log.Println("🛡️  SecDash Honeypot Production Engine (Golang)")
	log.Println("==================================================")

	// 1. Initialize MongoDB storage engine
	storage, err := db.NewStorage(mongoURI)
	if err != nil {
		log.Fatalf("Fatal: Database initialization failed: %v", err)
	}
	defer storage.Close()

	// 2. Initialize Parser & WebSocket Hub
	hub := api.NewHub()
	go hub.Run()

	// 3. Initialize HTTP Server
	server := api.NewServer(storage, hub)
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
