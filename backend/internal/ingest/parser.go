package ingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"sec_dash/backend/internal/geoip"
	"sec_dash/backend/internal/models"
)

// Parser handles converting diverse log payloads (Alloy Loki push, NDJSON, JSON array) into EnrichedEvents
type Parser struct {
	geoResolver *geoip.Resolver
}

func NewParser() *Parser {
	return &Parser{
		geoResolver: geoip.GetResolver(),
	}
}

// ParseCowrieJSON parses a single Cowrie JSON event and enriches it
func (p *Parser) ParseCowrieJSON(raw []byte) (*models.EnrichedEvent, error) {
	var cowrie models.CowrieRawEvent
	if err := json.Unmarshal(raw, &cowrie); err != nil {
		return nil, err
	}

	if cowrie.EventID == "" {
		return nil, fmt.Errorf("missing eventid in cowrie payload")
	}

	// Parse timestamp (ISO 8601 / RFC3339)
	ts, err := time.Parse(time.RFC3339Nano, cowrie.Timestamp)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, cowrie.Timestamp)
		if err != nil {
			ts = time.Now()
		}
	}

	// Resolve GeoIP
	geo := p.geoResolver.Resolve(cowrie.SourceIP)

	// Determine severity and human-readable description
	severity, desc := categorizeCowrieEvent(&cowrie)

	protocol := cowrie.Protocol
	if protocol == "" {
		if cowrie.DestPort == 22 || cowrie.DestPort == 2222 || strings.Contains(cowrie.EventID, "ssh") {
			protocol = "ssh"
		} else if cowrie.DestPort == 23 || cowrie.DestPort == 2323 || strings.Contains(cowrie.EventID, "telnet") {
			protocol = "telnet"
		} else {
			protocol = "ssh"
		}
	}

	ev := &models.EnrichedEvent{
		EventID:     cowrie.EventID,
		Timestamp:   ts,
		Session:     cowrie.Session,
		SourceIP:    cowrie.SourceIP,
		SourcePort:  cowrie.SourcePort,
		DestPort:    cowrie.DestPort,
		Protocol:    protocol,
		Username:    cowrie.Username,
		Password:    cowrie.Password,
		Input:       cowrie.Input,
		SSHVersion:  cowrie.Version,
		DownloadURL: cowrie.URL,
		SHA256:      cowrie.SHA256,
		FileSize:    cowrie.Size,
		Duration:    cowrie.Duration,
		Geo:         geo,
		Severity:    severity,
		Description: desc,
	}

	return ev, nil
}

// ParseLokiPush parses the Grafana Alloy loki.write format payload
func (p *Parser) ParseLokiPush(r io.Reader) ([]*models.EnrichedEvent, error) {
	var push models.LokiPushRequest
	if err := json.NewDecoder(r).Decode(&push); err != nil {
		return nil, fmt.Errorf("failed to decode loki push payload: %w", err)
	}

	var events []*models.EnrichedEvent
	for _, stream := range push.Streams {
		for _, val := range stream.Values {
			if len(val) < 2 {
				continue
			}
			logLine := strings.TrimSpace(val[1])
			if logLine == "" {
				continue
			}

			// The log line may be raw JSON string
			ev, err := p.ParseCowrieJSON([]byte(logLine))
			if err == nil && ev != nil {
				events = append(events, ev)
			}
		}
	}

	return events, nil
}

// ParseAutoBatch attempts to parse either a JSON array, single JSON object, or NDJSON stream
func (p *Parser) ParseAutoBatch(body []byte) ([]*models.EnrichedEvent, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}

	// 1. If it's a JSON array
	if trimmed[0] == '[' {
		var rawList []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawList); err == nil {
			var events []*models.EnrichedEvent
			for _, item := range rawList {
				ev, err := p.ParseCowrieJSON(item)
				if err == nil && ev != nil {
					events = append(events, ev)
				}
			}
			return events, nil
		}
	}

	// 2. If it's a Loki push format payload
	if bytes.Contains(trimmed, []byte(`"streams"`)) {
		var push models.LokiPushRequest
		if err := json.Unmarshal(trimmed, &push); err == nil && len(push.Streams) > 0 {
			return p.ParseLokiPush(bytes.NewReader(trimmed))
		}
	}

	// 3. Check for NDJSON / line-by-line JSON
	var events []*models.EnrichedEvent
	scanner := bufio.NewScanner(bytes.NewReader(trimmed))
	// Increase buffer limit to 1MB per line for large files or commands
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		ev, err := p.ParseCowrieJSON(line)
		if err == nil && ev != nil {
			events = append(events, ev)
		}
	}

	if len(events) > 0 {
		return events, nil
	}

	// 4. Try parsing as a single Cowrie object
	ev, err := p.ParseCowrieJSON(trimmed)
	if err == nil && ev != nil {
		return []*models.EnrichedEvent{ev}, nil
	}

	return nil, fmt.Errorf("unrecognized cowrie log format: %v", err)
}

func categorizeCowrieEvent(c *models.CowrieRawEvent) (severity string, desc string) {
	switch c.EventID {
	case "cowrie.login.success":
		return "critical", fmt.Sprintf("Attacker successfully authenticated with '%s':'%s'", c.Username, c.Password)
	case "cowrie.login.failed":
		return "warning", fmt.Sprintf("Failed login attempt with '%s':'%s'", c.Username, c.Password)
	case "cowrie.command.input":
		return "high", fmt.Sprintf("Shell command executed: %s", c.Input)
	case "cowrie.command.failed":
		return "warning", fmt.Sprintf("Command not found/failed: %s", c.Input)
	case "cowrie.session.file_download":
		return "critical", fmt.Sprintf("Malicious file downloaded from %s (SHA256: %s)", c.URL, c.SHA256)
	case "cowrie.session.connect":
		return "info", fmt.Sprintf("New connection established from %s:%d", c.SourceIP, c.SourcePort)
	case "cowrie.session.closed":
		return "info", fmt.Sprintf("Connection terminated after %.1fs", c.Duration)
	case "cowrie.client.version":
		return "info", fmt.Sprintf("Client banner identification: %s", c.Version)
	case "cowrie.direct-tcpip.request":
		return "high", "Attempted TCP/IP port forward tunnel"
	default:
		if c.Message != "" {
			return "info", c.Message
		}
		return "info", fmt.Sprintf("Cowrie event %s", c.EventID)
	}
}
