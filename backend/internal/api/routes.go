package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"sec_dash/backend/internal/ai"
	"sec_dash/backend/internal/alerts"
	"sec_dash/backend/internal/db"
	"sec_dash/backend/internal/ingest"
	"sec_dash/backend/internal/killchain"
	"sec_dash/backend/internal/models"
)

type Server struct {
	storage   *db.Storage
	parser    *ingest.Parser
	hub       *Hub
	analyst   *ai.Analyst
	alerts    *alerts.Engine
	startTime time.Time
}

func NewServer(storage *db.Storage, parser *ingest.Parser, hub *Hub) *Server {
	return &Server{
		storage:   storage,
		parser:    parser,
		hub:       hub,
		analyst:   ai.NewAnalyst(storage),
		alerts:    alerts.NewEngine(storage),
		startTime: time.Now(),
	}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	// Basic middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.GetHead)

	// Cross-Origin Resource Sharing
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Scope-OrgID"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// WebSocket real-time attack stream
	r.Get("/ws", s.hub.HandleWebSocket)

	// API routes
	r.Route("/api", func(r chi.Router) {
		r.Get("/health", s.handleHealth)

		// Ingestion endpoints
		r.Post("/ingest/cowrie", s.handleIngestCowrie)
		r.Post("/ingest/loki", s.handleIngestLoki)
		r.Post("/ingest/raw", s.handleIngestRaw)
		// Standard Loki API alias so Grafana Alloy can point directly without custom path changes:
		r.Post("/loki/api/v1/push", s.handleIngestLoki)

		// Dashboard analytics & Threat intelligence
		r.Get("/stats/overview", s.handleStatsOverview)
		r.Get("/stats/timeline", s.handleStatsTimeline)
		r.Get("/stats/countries", s.handleStatsCountries)
		r.Get("/stats/credentials", s.handleStatsCredentials)
		r.Get("/stats/commands", s.handleStatsCommands)
		r.Get("/stats/fingerprints", s.handleGetBotnetFingerprints)

		// Events, sessions, loot & threat forensics
		r.Get("/events", s.handleGetEvents)
		r.Get("/sessions", s.handleGetSessions)
		r.Get("/sessions/{sessionID}/commands", s.handleGetSessionCommands)
		r.Get("/sessions/{sessionID}/ai-analysis", s.handleSessionAIAnalysis)
		r.Post("/sessions/{sessionID}/ai-analysis", s.handleSessionAIAnalysis)
		r.Get("/sessions/{sessionID}/killchain", s.handleSessionKillChain)
		r.Get("/threats/files", s.handleGetMalwareFiles)
		r.Get("/loot", s.handleGetMalwareFiles)
		r.Get("/threats/ip/{ip}", s.handleGetThreatIPProfile)
		r.Post("/threats/ip/{ip}/ban", s.handleBanIP)

		// Custom Webhook Alerting Engine
		r.Get("/webhooks", s.handleListWebhooks)
		r.Post("/webhooks", s.handleCreateWebhook)
		r.Delete("/webhooks/{id}", s.handleDeleteWebhook)
		r.Post("/webhooks/{id}/test", s.handleTestWebhook)
		r.Get("/webhooks/logs", s.handleListWebhookLogs)

		// Grafana Alloy pipeline setup guide
		r.Get("/config/alloy", s.handleAlloyConfig)
	})

	// Serve Production PWA Frontend if dist directory exists
	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		candidates := []string{"../frontend/dist", "./frontend/dist", "dist"}
		for _, c := range candidates {
			if info, err := os.Stat(c); err == nil && info.IsDir() {
				staticDir = c
				break
			}
		}
	}

	if staticDir != "" {
		fs := http.FileServer(http.Dir(staticDir))
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			path := filepath.Join(staticDir, filepath.Clean(r.URL.Path))
			if info, err := os.Stat(path); os.IsNotExist(err) || info.IsDir() {
				http.ServeFile(w, r, filepath.Join(staticDir, "index.html"))
				return
			}
			fs.ServeHTTP(w, r)
		})
		log.Printf("[PWA] Standalone production server serving frontend from: %s", staticDir)
	}

	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "healthy",
		"uptime":  time.Since(s.startTime).String(),
		"runtime": "Go 1.27.1 (High Throughput)",
	})
}

// handleIngestCowrie handles native Cowrie JSON or JSON array/stream
func (s *Server) handleIngestCowrie(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	events, err := s.parser.ParseAutoBatch(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.storage.InsertEventsBatch(events); err != nil {
		http.Error(w, "Failed to persist events: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for _, ev := range events {
		s.hub.BroadcastEvent(ev)
		s.alerts.EvaluateAndDispatch(ev)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"ingested": len(events),
		"status":   "success",
	})
}

// handleIngestLoki handles Grafana Alloy loki.write format
func (s *Server) handleIngestLoki(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	events, err := s.parser.ParseLokiPush(r.Body)
	if err != nil {
		// Fallback to auto-batch if not pure Loki JSON
		http.Error(w, "Invalid loki payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.storage.InsertEventsBatch(events); err != nil {
		http.Error(w, "Failed to store batch: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for _, ev := range events {
		s.hub.BroadcastEvent(ev)
		s.alerts.EvaluateAndDispatch(ev)
	}

	// Grafana Alloy expects 204 No Content or 200 OK
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleIngestRaw(w http.ResponseWriter, r *http.Request) {
	s.handleIngestCowrie(w, r)
}

func (s *Server) handleStatsOverview(w http.ResponseWriter, r *http.Request) {
	stats, err := s.storage.GetOverviewStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, stats)
}

func (s *Server) handleStatsTimeline(w http.ResponseWriter, r *http.Request) {
	limit := 24
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	timeline, err := s.storage.GetTimeline(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if timeline == nil {
		timeline = []models.TimelinePoint{}
	}
	respondJSON(w, http.StatusOK, timeline)
}

func (s *Server) handleStatsCountries(w http.ResponseWriter, r *http.Request) {
	limit := 10
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	countries, err := s.storage.GetTopCountries(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if countries == nil {
		countries = []models.CountryAttackStat{}
	}
	respondJSON(w, http.StatusOK, countries)
}

func (s *Server) handleStatsCredentials(w http.ResponseWriter, r *http.Request) {
	limit := 15
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	creds, err := s.storage.GetTopCredentials(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if creds == nil {
		creds = []models.CredentialStat{}
	}
	respondJSON(w, http.StatusOK, creds)
}

func (s *Server) handleStatsCommands(w http.ResponseWriter, r *http.Request) {
	limit := 15
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	cmds, err := s.storage.GetTopCommands(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cmds == nil {
		cmds = []models.CommandStat{}
	}
	respondJSON(w, http.StatusOK, cmds)
}

func (s *Server) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	eventType := r.URL.Query().Get("type")
	ip := r.URL.Query().Get("ip")

	events, err := s.storage.GetRecentEvents(limit, eventType, ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []*models.EnrichedEvent{}
	}
	respondJSON(w, http.StatusOK, events)
}

func (s *Server) handleGetSessions(w http.ResponseWriter, r *http.Request) {
	limit := 30
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	sessions, err := s.storage.GetSessions(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sessions == nil {
		sessions = []db.SessionRecord{}
	}
	respondJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleGetSessionCommands(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	cmds, err := s.storage.GetSessionCommands(sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if cmds == nil {
		cmds = []models.CommandStat{}
	}
	respondJSON(w, http.StatusOK, cmds)
}

func (s *Server) handleGetMalwareFiles(w http.ResponseWriter, r *http.Request) {
	limit := 30
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	files, err := s.storage.GetMalwareFiles(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if files == nil {
		files = []db.MalwareRecord{}
	}
	respondJSON(w, http.StatusOK, files)
}

func (s *Server) handleGetThreatIPProfile(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		http.Error(w, "IP address required", http.StatusBadRequest)
		return
	}
	profile, err := s.storage.GetIPThreatProfile(ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	respondJSON(w, http.StatusOK, profile)
}

func (s *Server) handleGetBotnetFingerprints(w http.ResponseWriter, r *http.Request) {
	limit := 30
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}
	fps, err := s.storage.GetBotnetFingerprints(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if fps == nil {
		fps = []models.BotnetFingerprint{}
	}
	respondJSON(w, http.StatusOK, fps)
}

func (s *Server) handleSessionAIAnalysis(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID is required", http.StatusBadRequest)
		return
	}

	analysis, err := s.analyst.AnalyzeSession(r.Context(), sessionID)
	if err != nil {
		http.Error(w, "AI Analysis failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, analysis)
}

func (s *Server) handleSessionKillChain(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID is required", http.StatusBadRequest)
		return
	}

	events, err := s.storage.GetSessionEvents(sessionID)
	if err != nil {
		http.Error(w, "Failed to load session events: "+err.Error(), http.StatusInternalServerError)
		return
	}

	phases := killchain.Evaluate(events)
	respondJSON(w, http.StatusOK, phases)
}

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	hooks, err := s.storage.ListWebhooks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if hooks == nil {
		hooks = []models.WebhookConfig{}
	}
	respondJSON(w, http.StatusOK, hooks)
}

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	var hook models.WebhookConfig
	if err := json.NewDecoder(r.Body).Decode(&hook); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if hook.Name == "" || hook.URL == "" {
		http.Error(w, "Name and URL are required", http.StatusBadRequest)
		return
	}

	if hook.Type == "" {
		hook.Type = "generic"
	}

	if err := s.storage.CreateWebhook(&hook); err != nil {
		http.Error(w, "Failed to save webhook: "+err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusCreated, hook)
}

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := s.storage.DeleteWebhook(id); err != nil {
		http.Error(w, "Failed to delete webhook: "+err.Error(), http.StatusInternalServerError)
		return
	}
	respondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	hooks, err := s.storage.ListWebhooks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var target *models.WebhookConfig
	for _, h := range hooks {
		if h.ID == id {
			target = &h
			break
		}
	}

	if target == nil {
		http.Error(w, "Webhook not found", http.StatusNotFound)
		return
	}

	success, msg := s.alerts.TestWebhook(*target)
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"success": success,
		"message": msg,
	})
}

func (s *Server) handleListWebhookLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := s.storage.ListWebhookLogs(30)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if logs == nil {
		logs = []models.WebhookLog{}
	}
	respondJSON(w, http.StatusOK, logs)
}

func (s *Server) handleAlloyConfig(w http.ResponseWriter, r *http.Request) {
	cfg := `// Grafana Alloy Configuration for Cowrie Honeypot
// Direct ingestion into SecDash Go Backend (replaces Grafana/Loki pipeline)

local.file_match "cowrie_logs" {
  path_targets = [{
    __path__ = "/var/log/cowrie/cowrie.json*",
  }]
  sync_period = "5s"
}

loki.source.file "cowrie_collector" {
  targets    = local.file_match.cowrie_logs.targets
  forward_to = [loki.write.secdash.receiver]
}

loki.write "secdash" {
  endpoint {
    url = "http://localhost:8080/api/ingest/loki"
  }
}
`
	respondJSON(w, http.StatusOK, map[string]string{
		"config": cfg,
	})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (s *Server) handleBanIP(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		http.Error(w, "IP address required", http.StatusBadRequest)
		return
	}
	
	// Read reason from request body
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Reason == "" {
		req.Reason = "Manual ban from SecDash UI"
	}

	err := s.storage.BanIP(ip, req.Reason)
	if err != nil {
		http.Error(w, "Failed to ban IP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "success", "ip": ip, "reason": req.Reason})
}
