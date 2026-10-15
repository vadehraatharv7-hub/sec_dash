package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"sec_dash/backend/internal/intel"
	"sec_dash/backend/internal/model"
	"sec_dash/backend/internal/store"
)

type Webhook struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	URL            string `json:"url"`
	Type           string `json:"type"` // slack | discord | generic
	OnLoginSuccess bool   `json:"on_login_success"`
	OnMalware      bool   `json:"on_malware"`
	OnCriticalCmd  bool   `json:"on_critical_command"`
	OnWebExploit   bool   `json:"on_web_exploit"`
	Enabled        bool   `json:"enabled"`
	CreatedAt      string `json:"created_at"`
}

type WebhookLog struct {
	Time    time.Time `json:"ts"`
	Hook    string    `json:"webhook"`
	Trigger string    `json:"trigger"`
	IP      string    `json:"src_ip"`
	Status  int       `json:"status"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
}

type Alerts struct {
	p      store.Persister
	mu     sync.Mutex
	hooks  map[string]*Webhook
	logs   []WebhookLog
	recent map[string]time.Time
	client *http.Client
}

func newAlerts(p store.Persister) *Alerts {
	a := &Alerts{p: p, hooks: map[string]*Webhook{}, recent: map[string]time.Time{}}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	a.client = &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{
		// Refuse to connect to internal addresses so a webhook cannot be used to probe the VNet or metadata service.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if ip.IP.IsLoopback() || ip.IP.IsPrivate() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsUnspecified() {
					return nil, fmt.Errorf("webhook target %s resolves to a non-public address", host)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		}}}
	if p != nil {
		docs, _ := p.ListDocs("webhooks_v2")
		for _, d := range docs {
			b, _ := json.Marshal(d)
			var h Webhook
			if json.Unmarshal(b, &h) == nil && h.ID != "" {
				a.hooks[h.ID] = &h
			}
		}
	}
	return a
}

func (a *Alerts) trigger(e *model.Event) (string, bool) {
	switch e.Kind {
	case model.KindLoginSuccess:
		return "login_success", true
	case model.KindDownload, model.KindUpload:
		return "malware", true
	case model.KindCommand:
		cats, _ := intel.ClassifyCommand(e.Input)
		switch intel.PrimaryCategory(cats) {
		case "download", "persistence", "miner", "reverse_shell", "destructive", "execution", "evasion":
			return "critical_command", true
		}
	case model.KindHTTP:
		if _, t := intel.ClassifyWeb(e.Path); t.ID == "T1190" {
			return "web_exploit", true
		}
	}
	return "", false
}

// Evaluate dispatches alerts for an incoming event (rate-limited per hook/IP/trigger).
func (a *Alerts) Evaluate(e *model.Event) {
	trig, ok := a.trigger(e)
	if !ok {
		return
	}
	a.mu.Lock()
	var targets []Webhook
	for _, h := range a.hooks {
		if !h.Enabled {
			continue
		}
		if (trig == "login_success" && h.OnLoginSuccess) || (trig == "malware" && h.OnMalware) ||
			(trig == "critical_command" && h.OnCriticalCmd) || (trig == "web_exploit" && h.OnWebExploit) {
			k := h.ID + "|" + e.IP + "|" + trig
			if t, seen := a.recent[k]; seen && time.Since(t) < 10*time.Minute {
				continue
			}
			a.recent[k] = time.Now()
			targets = append(targets, *h)
		}
	}
	if len(a.recent) > 5000 {
		a.recent = map[string]time.Time{}
	}
	a.mu.Unlock()
	for _, h := range targets {
		go a.send(h, trig, e)
	}
}

func (a *Alerts) send(h Webhook, trig string, e *model.Event) {
	status, err := a.post(h, trig, e)
	l := WebhookLog{Time: time.Now().UTC(), Hook: h.Name, Trigger: trig, IP: e.IP, Status: status}
	if err != nil {
		l.Message = err.Error()
	} else if status >= 200 && status < 300 {
		l.OK, l.Message = true, "delivered"
	} else {
		l.Message = fmt.Sprintf("endpoint returned HTTP %d", status)
	}
	a.mu.Lock()
	a.logs = append([]WebhookLog{l}, a.logs...)
	if len(a.logs) > 100 {
		a.logs = a.logs[:100]
	}
	a.mu.Unlock()
}

func summary(trig string, e *model.Event) (title, text string) {
	loc := e.Geo.CountryName
	if loc == "" {
		loc = "unknown location"
	}
	switch trig {
	case "login_success":
		return "Honeypot login", fmt.Sprintf("%s (%s) logged in as %q on %s", e.IP, loc, e.User, e.Sensor)
	case "malware":
		return "Malware captured", fmt.Sprintf("%s (%s) downloaded %s (sha256 %s) on %s", e.IP, loc, e.URL, e.SHA256, e.Sensor)
	case "web_exploit":
		return "Web exploit attempt", fmt.Sprintf("%s (%s) requested %s on %s", e.IP, loc, e.Path, e.Sensor)
	}
	return "Suspicious command", fmt.Sprintf("%s (%s) ran: %s (%s)", e.IP, loc, e.Input, e.Sensor)
}

func (a *Alerts) post(h Webhook, trig string, e *model.Event) (int, error) {
	title, text := summary(trig, e)
	var payload interface{}
	switch h.Type {
	case "slack":
		payload = map[string]interface{}{"text": "SecDash: " + title + "\n" + text}
	case "discord":
		payload = map[string]interface{}{"content": "**SecDash: " + title + "**\n" + text}
	default:
		payload = map[string]interface{}{"trigger": trig, "title": title, "text": text, "event": e}
	}
	body, _ := json.Marshal(payload)
	resp, err := a.client.Post(h.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// ---- handlers --------------------------------------------------------------

func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	a := s.alerts
	a.mu.Lock()
	out := make([]Webhook, 0, len(a.hooks))
	for _, h := range a.hooks {
		out = append(out, *h)
	}
	a.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	respond(w, http.StatusOK, out)
}

func (s *Server) handleWebhookAdd(w http.ResponseWriter, r *http.Request) {
	var h Webhook
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&h); err != nil {
		fail(w, http.StatusBadRequest, "invalid body")
		return
	}
	u, err := url.Parse(h.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		fail(w, http.StatusBadRequest, "URL must be a valid http(s) address")
		return
	}
	if h.Name == "" {
		h.Name = u.Host
	}
	if h.Type != "slack" && h.Type != "discord" {
		h.Type = "generic"
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	h.ID = hex.EncodeToString(b)
	h.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	s.alerts.mu.Lock()
	s.alerts.hooks[h.ID] = &h
	s.alerts.mu.Unlock()
	if s.alerts.p != nil {
		m := map[string]interface{}{}
		raw, _ := json.Marshal(h)
		_ = json.Unmarshal(raw, &m)
		_ = s.alerts.p.PutDoc("webhooks_v2", h.ID, m)
	}
	respond(w, http.StatusOK, h)
}

func (s *Server) handleWebhookDel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s.alerts.mu.Lock()
	delete(s.alerts.hooks, id)
	s.alerts.mu.Unlock()
	if s.alerts.p != nil {
		_ = s.alerts.p.DelDoc("webhooks_v2", id)
	}
	respond(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	s.alerts.mu.Lock()
	h, ok := s.alerts.hooks[chi.URLParam(r, "id")]
	var hc Webhook
	if ok {
		hc = *h
	}
	s.alerts.mu.Unlock()
	if !ok {
		fail(w, http.StatusNotFound, "webhook not found")
		return
	}
	e := &model.Event{Kind: model.KindLoginSuccess, IP: "198.51.100.7", User: "root", Sensor: "test",
		Geo: model.Geo{CountryName: "Testland"}, Time: time.Now()}
	status, err := s.alerts.post(hc, "login_success", e)
	switch {
	case err != nil:
		respond(w, http.StatusOK, map[string]interface{}{"success": false, "message": err.Error()})
	case status >= 200 && status < 300:
		respond(w, http.StatusOK, map[string]interface{}{"success": true, "message": fmt.Sprintf("Delivered (HTTP %d)", status)})
	default:
		respond(w, http.StatusOK, map[string]interface{}{"success": false, "message": fmt.Sprintf("Endpoint returned HTTP %d", status)})
	}
}

func (s *Server) handleWebhookLogs(w http.ResponseWriter, r *http.Request) {
	s.alerts.mu.Lock()
	out := append([]WebhookLog{}, s.alerts.logs...)
	s.alerts.mu.Unlock()
	respond(w, http.StatusOK, out)
}
