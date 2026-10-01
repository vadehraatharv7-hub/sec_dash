package ingest

import (
	"encoding/json"
	"fmt"
	"time"

	"sec_dash/backend/internal/models"
)

// SnareRawEvent represents the JSON format from Snare/Tanner
type SnareRawEvent struct {
	UUID    string `json:"uuid"`
	Peer    struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	} `json:"peer"`
	Request struct {
		Method string `json:"method"`
		Path   string `json:"path"`
	} `json:"request"`
	Message string `json:"message"`
	Name    string `json:"name"`
}

// ParseSnareJSON parses Snare/Tanner JSON
func (p *Parser) ParseSnareJSON(raw []byte) (*models.EnrichedEvent, error) {
	var snare SnareRawEvent
	if err := json.Unmarshal(raw, &snare); err != nil {
		return nil, err
	}

	if snare.Peer.IP == "" {
		return nil, fmt.Errorf("missing peer IP in snare payload")
	}

	geo := p.geoResolver.Resolve(snare.Peer.IP)

	desc := snare.Message
	if snare.Request.Method != "" {
		desc = fmt.Sprintf("Web Request: %s %s", snare.Request.Method, snare.Request.Path)
	}

	return &models.EnrichedEvent{
		EventID:     "snare.web.request",
		Timestamp:   time.Now(),
		Session:     snare.UUID,
		SourceIP:    snare.Peer.IP,
		SourcePort:  snare.Peer.Port,
		DestPort:    80,
		Protocol:    "http",
		Geo:         geo,
		Severity:    "warning",
		Description: desc,
		Input:       desc,
	}, nil
}
