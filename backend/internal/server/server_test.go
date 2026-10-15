package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sec_dash/backend/internal/geo"
	"sec_dash/backend/internal/model"
	"sec_dash/backend/internal/store"
)

// nulls walks decoded JSON and reports paths holding null. The UI reads
// .length / .map on list fields, so a null list crashes a page.
func nulls(v interface{}, path string, out *[]string) {
	switch x := v.(type) {
	case nil:
		*out = append(*out, path)
	case map[string]interface{}:
		for k, c := range x {
			if k == "prev" { // a missing baseline is legitimately null
				continue
			}
			nulls(c, path+"."+k, out)
		}
	case []interface{}:
		for i, c := range x {
			nulls(c, path+"[]", out)
			_ = i
		}
	}
}

func check(t *testing.T, srv *Server, label string) {
	h := srv.Routes()
	for _, p := range []string{"/api/overview", "/api/geo", "/api/attackers", "/api/sessions", "/api/campaigns", "/api/credentials",
		"/api/commands", "/api/malware", "/api/mitre", "/api/sensors", "/api/iocs", "/api/events", "/api/bans", "/api/webhooks",
		"/api/webhooks/logs", "/api/meta", "/api/sessions/a", "/api/attackers/198.51.100.1"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p+"?range=all", nil))
		if rec.Code == 404 && label == "empty" {
			continue // detail pages have nothing to show on an empty store
		}
		if rec.Code != 200 {
			t.Errorf("%s %s: status %d", label, p, rec.Code)
			continue
		}
		var v interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Errorf("%s %s: bad JSON: %v", label, p, err)
			continue
		}
		var bad []string
		nulls(v, "", &bad)
		for _, b := range bad {
			t.Errorf("%s %s: null at %q", label, p, b)
		}
	}
}

func TestNoNullListsWhenEmpty(t *testing.T) {
	check(t, New(store.New(store.NewMemory(), 1000), geo.New()), "empty")
}

func TestNoNullListsWithMinimalData(t *testing.T) {
	st := store.New(store.NewMemory(), 1000)
	now := time.Now().UTC()
	st.Add([]*model.Event{
		{Time: now, Sensor: "vm-honeypot", Source: "cowrie", Kind: model.KindConnect, RawType: "cowrie.session.connect", Session: "a", IP: "198.51.100.1", Proto: "ssh", DstPort: 22},
		{Time: now, Sensor: "vm-snare", Source: "snare", Kind: model.KindHTTP, RawType: "snare.http.request", IP: "", Method: "GET", Path: "/", Proto: "http", DstPort: 80},
	}, false)
	check(t, New(st, geo.New()), "minimal")
}

func TestTokenGuard(t *testing.T) {
	srv := New(store.New(store.NewMemory(), 100), geo.New())
	srv.token = "s3cret"
	h := srv.Routes()
	do := func(method, path, auth string) int {
		req := httptest.NewRequest(method, path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// machine endpoints stay open
	for _, c := range []struct{ m, p string }{{"GET", "/api/health"}, {"GET", "/api/threats/banned"}, {"GET", "/api/auth"}, {"POST", "/api/ingest/stream"}} {
		if code := do(c.m, c.p, ""); code == http.StatusUnauthorized {
			t.Errorf("%s %s should not need a token", c.m, c.p)
		}
	}
	// data and writes need it
	for _, c := range []struct{ m, p string }{{"GET", "/api/overview"}, {"GET", "/api/attackers"}, {"POST", "/api/bans"}, {"GET", "/api/webhooks"}, {"GET", "/ws"}} {
		if code := do(c.m, c.p, ""); code != http.StatusUnauthorized {
			t.Errorf("%s %s without token: got %d, want 401", c.m, c.p, code)
		}
	}
	if code := do("GET", "/api/overview", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d", code)
	}
	if code := do("GET", "/api/overview", "Bearer s3cret"); code != 200 {
		t.Errorf("right token: got %d", code)
	}
}

func TestTokenLockoutAfterRepeatedFailures(t *testing.T) {
	srv := New(store.New(store.NewMemory(), 100), geo.New())
	srv.token = "s3cret"
	h := srv.Routes()
	var last int
	for i := 0; i < 15; i++ {
		req := httptest.NewRequest("GET", "/api/auth", nil)
		req.Header.Set("Authorization", "Bearer nope")
		req.RemoteAddr = "203.0.113.9:5555"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		last = rec.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected lockout (429), got %d", last)
	}
}
