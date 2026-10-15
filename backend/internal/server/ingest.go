package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"sec_dash/backend/internal/ingest"
	"sec_dash/backend/internal/model"
)

// handleIngest accepts a JSON object, JSON array or NDJSON of honeypot events
// (the format emitted by Vector, Cowrie and the Snare forwarder).
func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		fail(w, http.StatusRequestEntityTooLarge, "body too large")
		return
	}
	body = bytes.TrimSpace(body)
	var payloads []map[string]interface{}
	switch {
	case len(body) == 0:
	case body[0] == '[':
		if err := json.Unmarshal(body, &payloads); err != nil {
			fail(w, http.StatusBadRequest, "invalid JSON array")
			return
		}
	default:
		sc := bufio.NewScanner(bytes.NewReader(body))
		sc.Buffer(make([]byte, 1<<20), 4<<20)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var m map[string]interface{}
			if err := json.Unmarshal(line, &m); err != nil {
				fail(w, http.StatusBadRequest, "invalid JSON")
				return
			}
			payloads = append(payloads, m)
		}
	}
	sensor := r.URL.Query().Get("sensor")
	var evs []*model.Event
	for _, p := range payloads {
		ev, err := ingest.Normalize(p, sensor)
		if err != nil {
			continue
		}
		ev.Geo = s.geo.Lookup(ev.IP)
		evs = append(evs, ev)
	}
	if len(evs) > 0 {
		s.st.Add(evs, true)
		for _, ev := range evs {
			s.alerts.Evaluate(ev)
		}
		log.Printf("[ingest] %d events (%s)", len(evs), evs[0].Sensor)
	}
	w.WriteHeader(http.StatusAccepted)
}
