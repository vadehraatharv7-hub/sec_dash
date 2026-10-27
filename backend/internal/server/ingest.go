package server

import (
	"bufio"
	"bytes"
	"crypto/subtle"
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
	// A shared secret keeps a compromised host in a sensor subnet from injecting fake events.
	if s.ingestKey != "" {
		got := r.Header.Get("X-Ingest-Key")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.ingestKey)) != 1 {
			if !s.limiter.allow(r.RemoteAddr) {
				fail(w, http.StatusTooManyRequests, "too many failed attempts")
				return
			}
			s.limiter.fail(r.RemoteAddr)
			fail(w, http.StatusUnauthorized, "invalid ingest key")
			return
		}
	}
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
		// Persist before confirming. If the database is busy the sensor gets a 503 and sends the batch
		// again (Vector and the Snare forwarder both retry), so a slow database delays events, never loses them.
		if err := s.st.Add(evs, true); err != nil {
			log.Printf("[ingest] %d events (%s) NOT stored, asking the sensor to retry: %v", len(evs), evs[0].Sensor, err)
			fail(w, http.StatusServiceUnavailable, "database busy, retry")
			return
		}
		for _, ev := range evs {
			s.alerts.Evaluate(ev)
		}
		log.Printf("[ingest] %d events (%s)", len(evs), evs[0].Sensor)
	}
	w.WriteHeader(http.StatusAccepted)
}
