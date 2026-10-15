package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"sec_dash/backend/internal/geo"
	"sec_dash/backend/internal/seed"
	"sec_dash/backend/internal/server"
	"sec_dash/backend/internal/store"
)

func main() {
	_ = godotenv.Load()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	maxEvents := 250000
	if v, err := strconv.Atoi(os.Getenv("MAX_EVENTS")); err == nil && v > 0 {
		maxEvents = v
	}

	var persister store.Persister
	if uri := os.Getenv("MONGO_URI"); uri != "" {
		m, err := store.NewMongo(uri)
		if err != nil {
			log.Fatalf("database: %v", err)
		}
		persister = m
	} else {
		log.Printf("MONGO_URI not set: running in memory-only mode")
		persister = store.NewMemory()
	}
	defer persister.Close()

	st := store.New(persister, maxEvents)
	g := geo.New()
	g.OnResolved = st.SetGeo
	// Back-fill locations for events stored before geolocation was available.
	go func() {
		for _, ip := range st.IPsMissingGeo() {
			if geoRes := g.Lookup(ip); geoRes.CountryCode != "" {
				st.SetGeo(ip, geoRes)
			}
		}
	}()

	if os.Getenv("DEMO") == "1" {
		seed.Populate(st, g)
	}

	srv := server.New(st, g)
	httpSrv := &http.Server{Addr: ":" + port, Handler: srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		log.Printf("SecDash listening on :%s", port)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}
