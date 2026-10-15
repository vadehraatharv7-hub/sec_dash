// Package server exposes the SecDash HTTP/WebSocket API.
package server

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"sec_dash/backend/internal/analytics"
	"sec_dash/backend/internal/auth"
	"sec_dash/backend/internal/geo"
	"sec_dash/backend/internal/store"
)

type Server struct {
	st      *store.Store
	geo     *geo.Resolver
	alerts  *Alerts
	bans    *Bans
	token   string
	limiter *failLimiter
	auth    *auth.Manager
	started time.Time

	cacheMu sync.Mutex
	buildMu sync.Mutex // serializes rebuilds so concurrent requests share one result
	cache   map[string]cached
}

type cached struct {
	ds      *analytics.Dataset
	version int64
	at      time.Time
}

func New(st *store.Store, g *geo.Resolver) *Server {
	s := &Server{st: st, geo: g, token: os.Getenv("DASH_TOKEN"), started: time.Now(), cache: map[string]cached{}, limiter: &failLimiter{m: map[string][]time.Time{}}}
	s.auth = auth.New(st.Persister())
	s.bans = newBans(st.Persister())
	s.alerts = newAlerts(st.Persister())
	return s
}

// dataset returns the (briefly cached) derived dataset for the parameters.
func (s *Server) lookup(key string, ver int64) (*analytics.Dataset, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	c, ok := s.cache[key]
	if ok && (c.version == ver || time.Since(c.at) < 3*time.Second) && time.Since(c.at) < 15*time.Second {
		return c.ds, true
	}
	return nil, false
}

// dataset returns the (briefly cached) derived dataset for the parameters.
// offset shifts the window into the past (used for previous-period deltas).
func (s *Server) dataset(p analytics.Params, offset time.Duration) *analytics.Dataset {
	key := p.Key() + "|" + offset.String()
	ver := s.st.Version()
	if ds, ok := s.lookup(key, ver); ok {
		return ds
	}
	s.buildMu.Lock()
	defer s.buildMu.Unlock()
	if ds, ok := s.lookup(key, s.st.Version()); ok {
		return ds
	}
	ver = s.st.Version()
	var from, to time.Time
	if dur := analytics.RangeDuration(p.Range); dur > 0 {
		to = time.Now().UTC().Add(-offset)
		from = to.Add(-dur)
	}
	if p.Range == "all" && offset > 0 {
		return analytics.Build(p, time.Time{}, time.Time{}, nil)
	}
	ds := analytics.Build(p, from, to, s.st.Range(from, to, p.Sensor))
	s.cacheMu.Lock()
	s.cache[key] = cached{ds, ver, time.Now()}
	if len(s.cache) > 8 { // datasets are large; keep only the freshest few
		for k, v := range s.cache {
			if time.Since(v.at) > 20*time.Second {
				delete(s.cache, k)
			}
		}
	}
	s.cacheMu.Unlock()
	return ds
}

func params(r *http.Request) analytics.Params {
	p := analytics.Params{Range: r.URL.Query().Get("range"), Sensor: r.URL.Query().Get("sensor")}
	switch p.Range {
	case "1h", "6h", "24h", "7d", "30d", "all":
	default:
		p.Range = "24h"
	}
	if p.Sensor == "all" {
		p.Sensor = ""
	}
	return p
}

func respond(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	respond(w, status, map[string]string{"error": msg})
}

// guard enforces DASH_TOKEN. When a token is configured every API call and the
// live stream require it, except the endpoints machines depend on: health,
// ingest from sensors, and the ban list polled by xdp-shield.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authRequired() {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		open := !strings.HasPrefix(p, "/api") && p != "/ws" ||
			p == "/api/health" || p == "/api/auth" || p == "/api/login" || strings.HasPrefix(p, "/api/ingest/") ||
			(p == "/api/threats/banned" && r.Method == http.MethodGet)
		if open || s.tokenOK(r) {
			next.ServeHTTP(w, r)
			return
		}
		if !s.limiter.allow(r.RemoteAddr) {
			fail(w, http.StatusTooManyRequests, "too many failed attempts")
			return
		}
		s.limiter.fail(r.RemoteAddr)
		fail(w, http.StatusUnauthorized, "unauthorized")
	})
}

// authRequired is true once an access token is configured or any account exists.
func (s *Server) authRequired() bool { return s.token != "" || s.auth.HasUsers() }

// BootstrapAdmin creates or resets the admin account from deployment settings.
func (s *Server) BootstrapAdmin(user, password string) error {
	return s.auth.SetPassword(user, password, "admin")
}

// tokenOK accepts the static DASH_TOKEN (for scripts) or a signed session token.
func (s *Server) tokenOK(r *http.Request) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if got == "" && r.URL.Path == "/ws" {
		got = r.URL.Query().Get("token") // browsers cannot set headers on WebSockets
	}
	if got == "" {
		return false
	}
	if s.token != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1 {
		return true
	}
	_, ok := s.auth.Check(got)
	return ok
}

// failLimiter blocks an address after repeated bad tokens (10 per minute).
type failLimiter struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

func (l *failLimiter) key(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func (l *failLimiter) recent(k string) []time.Time {
	cut := time.Now().Add(-time.Minute)
	var keep []time.Time
	for _, t := range l.m[k] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	return keep
}

func (l *failLimiter) allow(addr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(l.key(addr))) < 10
}

func (l *failLimiter) fail(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.key(addr)
	l.m[k] = append(l.recent(k), time.Now())
	if len(l.m) > 10000 {
		l.m = map[string][]time.Time{}
	}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Compress(5, "application/json"))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type"},
		MaxAge:         300,
	}))
	r.Use(s.guard)

	r.Get("/ws", s.handleWS)
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/meta", s.handleMeta)
		r.Get("/auth", s.handleAuth)
		r.Post("/login", s.handleLogin)

		r.Post("/ingest/stream", s.handleIngest)

		r.Get("/overview", s.handleOverview)
		r.Get("/geo", s.handleGeo)
		r.Get("/events", s.handleEvents)
		r.Get("/attackers", s.handleAttackers)
		r.Get("/attackers/{ip}", s.handleAttacker)
		r.Get("/sessions", s.handleSessions)
		r.Get("/sessions/{id}", s.handleSession)
		r.Get("/credentials", s.handleCredentials)
		r.Get("/commands", s.handleCommands)
		r.Get("/malware", s.handleMalware)
		r.Get("/campaigns", s.handleCampaigns)
		r.Get("/mitre", s.handleMitre)
		r.Get("/sensors", s.handleSensors)
		r.Get("/iocs", s.handleIOCs)

		r.Get("/bans", s.handleBans)
		r.Post("/bans", s.handleBanAdd)
		r.Delete("/bans/{ip}", s.handleBanDel)
		// Contract used by xdp-shield (polls this path) and older tooling.
		r.Get("/threats/banned", s.handleBans)
		r.Post("/threats/ip/{ip}/ban", s.handleBanCompat)
		r.Post("/threats/ip/{ip}/unban", s.handleBanDel)

		r.Get("/webhooks", s.handleWebhooks)
		r.Post("/webhooks", s.handleWebhookAdd)
		r.Delete("/webhooks/{id}", s.handleWebhookDel)
		r.Post("/webhooks/{id}/test", s.handleWebhookTest)
		r.Get("/webhooks/logs", s.handleWebhookLogs)
	})

	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		for _, c := range []string{"../frontend/dist", "./frontend/dist", "dist"} {
			if info, err := os.Stat(c); err == nil && info.IsDir() {
				staticDir = c
				break
			}
		}
	}
	if staticDir != "" {
		fs := http.FileServer(http.Dir(staticDir))
		r.Get("/*", func(w http.ResponseWriter, req *http.Request) {
			path := filepath.Join(staticDir, filepath.Clean(req.URL.Path))
			if info, err := os.Stat(path); err != nil || info.IsDir() {
				w.Header().Set("Cache-Control", "no-cache")
				http.ServeFile(w, req, filepath.Join(staticDir, "index.html"))
				return
			}
			if strings.HasPrefix(req.URL.Path, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			fs.ServeHTTP(w, req)
		})
		log.Printf("[http] serving frontend from %s", staticDir)
	}
	return r
}
