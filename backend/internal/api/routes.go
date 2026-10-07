package api

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"sec_dash/backend/internal/ai"
	"sec_dash/backend/internal/alerts"
	"sec_dash/backend/internal/db"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/redis/go-redis/v9"

	"sec_dash/backend/internal/killchain"
	"sec_dash/backend/internal/models"
)

type Server struct {
	storage *db.Storage

	hub       *Hub
	analyst   *ai.Analyst
	alerts    *alerts.Engine
	startTime time.Time
}

func NewServer(storage *db.Storage, hub *Hub) *Server {
	return &Server{
		storage: storage,

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
		r.Post("/provision", s.handleProvision)

		// Ingestion endpoints
		r.Post("/ingest/stream", s.handleIngestStream)
		// Standard Loki API alias so Grafana Alloy can point directly without custom path changes:

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
func (s *Server) handleIngestCowrie(w http.ResponseWriter, r *http.Request) {}

func (s *Server) handleIngestLoki(w http.ResponseWriter, r *http.Request) {}

func (s *Server) handleIngestRaw(w http.ResponseWriter, r *http.Request) {}

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

func (s *Server) handleAlloyConfig(w http.ResponseWriter, r *http.Request) {}

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

	// Publish to Redis ban_feed
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redisClient.Close()
	if err := redisClient.Publish(r.Context(), "ban_feed", ip).Err(); err != nil {
		log.Printf("Failed to publish banned IP to Redis: %v", err)
	} else {
		log.Printf("Published banned IP %s to Redis ban_feed", ip)
	}

	respondJSON(w, http.StatusOK, map[string]string{"status": "success", "ip": ip, "reason": req.Reason})
}

func (s *Server) handleIngestStream(w http.ResponseWriter, r *http.Request) {
	var payloads []map[string]interface{}

	// Vector might send an array or a single object. Read the raw body first.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if len(bodyBytes) > 0 && bodyBytes[0] == '[' {
		if err := json.Unmarshal(bodyBytes, &payloads); err != nil {
			http.Error(w, "Invalid JSON array payload: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		var single map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &single); err != nil {
			http.Error(w, "Invalid JSON object payload: "+err.Error(), http.StatusBadRequest)
			return
		}
		payloads = append(payloads, single)
	}
	
	if len(payloads) > 0 {
		log.Printf("Received %d payloads. Sample: %+v\n", len(payloads), payloads[0])
	}

	var events []*models.EnrichedEvent

	for _, payload := range payloads {
		var ev models.EnrichedEvent

		if v, ok := payload["eventid"].(string); ok {
			ev.EventID = v
		}
		if v, ok := payload["session"].(string); ok {
			ev.Session = v
		}
		if v, ok := payload["src_ip"].(string); ok {
			ev.SourceIP = v
		}
		if v, ok := payload["protocol"].(string); ok {
			ev.Protocol = v
		}

		switch v := payload["src_port"].(type) {
		case float64:
			ev.SourcePort = int(v)
		}
		switch v := payload["dst_port"].(type) {
		case float64:
			ev.DestPort = int(v)
		}

		if v, ok := payload["username"].(string); ok {
			ev.Username = v
		}
		if v, ok := payload["password"].(string); ok {
			ev.Password = v
		}
		if v, ok := payload["input"].(string); ok {
			ev.Input = v
		}

		if v, ok := payload["timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				ev.Timestamp = t
			}
		}
		if ev.Timestamp.IsZero() {
			ev.Timestamp = time.Now()
		}

		if _, ok := payload["eventid"]; ok {
			ev.HoneypotSource = "cowrie"
		} else if _, ok := payload["http_request"]; ok {
			ev.HoneypotSource = "snare"
		} else {
			ev.HoneypotSource = "unknown"
		}

		events = append(events, &ev)
		s.hub.BroadcastEvent(&ev)
	}

	if len(events) > 0 {
		err := s.storage.InsertEventsBatch(events)
		if err != nil {
			log.Printf("ERROR: Failed to insert events batch: %v\n", err)
		} else {
			log.Printf("Successfully inserted %d events into MongoDB\n", len(events))
		}
	} else {
		log.Printf("No events parsed from payloads\n")
	}

	w.WriteHeader(http.StatusAccepted)
}

type ProvisionRequest struct {
	IP       string `json:"ip"`
	Username string `json:"username"`
	RSAKey   string `json:"rsa_key"`
	Type     string `json:"type"`
}

type ProvisionResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	var req ProvisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if req.IP == "" || req.Username == "" || req.RSAKey == "" || req.Type == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}
	if req.Type != "cowrie" && req.Type != "snare" {
		http.Error(w, "Invalid type, must be cowrie or snare", http.StatusBadRequest)
		return
	}

	keyFile, err := os.CreateTemp("", "prov_rsa_*")
	if err != nil {
		http.Error(w, "Failed to create temp key file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(keyFile.Name())

	if err := os.Chmod(keyFile.Name(), 0600); err != nil {
		http.Error(w, "Failed to set permissions on key file", http.StatusInternalServerError)
		return
	}
	if _, err := keyFile.WriteString(req.RSAKey); err != nil {
		http.Error(w, "Failed to write key to temp file", http.StatusInternalServerError)
		return
	}
	if err := keyFile.Close(); err != nil {
		http.Error(w, "Failed to close key file", http.StatusInternalServerError)
		return
	}

	invFile, err := os.CreateTemp("", "prov_inv_*")
	if err != nil {
		http.Error(w, "Failed to create temp inventory file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(invFile.Name())

	inventoryContent := fmt.Sprintf("[target]\n%s ansible_user=%s ansible_ssh_private_key_file=%s ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n", req.IP, req.Username, keyFile.Name())

	if _, err := invFile.WriteString(inventoryContent); err != nil {
		http.Error(w, "Failed to write inventory", http.StatusInternalServerError)
		return
	}
	if err := invFile.Close(); err != nil {
		http.Error(w, "Failed to close inventory file", http.StatusInternalServerError)
		return
	}

	playbookPath := "/home/marcos_007/Documents/project/infra_honeypot/ansible/site.yml"
	tags := fmt.Sprintf("vector,%s", req.Type)
	cmd := exec.Command("ansible-playbook", playbookPath, "-i", invFile.Name(), "--limit", req.IP, "--tags", tags)

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Ansible playbook failed: %s\nOutput: %s", err, out)
		http.Error(w, "Provisioning failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Ansible playbook succeeded\nOutput: %s", out)
	respondJSON(w, http.StatusOK, ProvisionResponse{
		Status:  "success",
		Message: "Provisioning completed successfully",
	})
}
