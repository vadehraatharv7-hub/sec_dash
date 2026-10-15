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
