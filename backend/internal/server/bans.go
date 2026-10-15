package server

import (
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"sec_dash/backend/internal/store"
)

// BanEntry is the wire format polled by xdp-shield: [{ip, reason, banned_at}].
type BanEntry struct {
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	BannedAt string `json:"banned_at"`
}

type Bans struct {
	p  store.Persister
	mu sync.RWMutex
	m  map[string]BanEntry
}

func newBans(p store.Persister) *Bans {
	b := &Bans{p: p, m: map[string]BanEntry{}}
	if p != nil {
		docs, _ := p.ListDocs("banned_ips")
		for _, d := range docs {
			ip, _ := d["ip"].(string)
			if ip == "" {
				continue
			}
			reason, _ := d["reason"].(string)
			at, _ := d["banned_at"].(string)
			b.m[ip] = BanEntry{ip, reason, at}
		}
	}
	return b
}

func (b *Bans) set() map[string]bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make(map[string]bool, len(b.m))
	for ip := range b.m {
		out[ip] = true
	}
	return out
}

func (b *Bans) list() []BanEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]BanEntry, 0, len(b.m))
	for _, e := range b.m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BannedAt > out[j].BannedAt })
	return out
}

func (b *Bans) add(ip, reason string) error {
	e := BanEntry{ip, reason, time.Now().UTC().Format(time.RFC3339)}
	b.mu.Lock()
	b.m[ip] = e
	b.mu.Unlock()
	if b.p != nil {
		return b.p.PutDoc("banned_ips", ip, map[string]interface{}{"ip": ip, "reason": reason, "banned_at": e.BannedAt})
	}
	return nil
}

func (b *Bans) del(ip string) error {
	b.mu.Lock()
	delete(b.m, ip)
	b.mu.Unlock()
	if b.p != nil {
		return b.p.DelDoc("banned_ips", ip)
	}
	return nil
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, s.bans.list())
}

func (s *Server) handleBanAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.banIP(w, req.IP, req.Reason)
}

func (s *Server) handleBanCompat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req)
	s.banIP(w, chi.URLParam(r, "ip"), req.Reason)
}

func (s *Server) banIP(w http.ResponseWriter, ip, reason string) {
	if net.ParseIP(ip) == nil {
		fail(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	if reason == "" {
		reason = "Manual ban from SecDash"
	}
	if err := s.bans.add(ip, reason); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	respond(w, http.StatusOK, map[string]string{"status": "banned", "ip": ip})
}

func (s *Server) handleBanDel(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if err := s.bans.del(ip); err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	respond(w, http.StatusOK, map[string]string{"status": "unbanned", "ip": ip})
}
