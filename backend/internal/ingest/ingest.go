// Package ingest turns raw honeypot log payloads into normalized events.
package ingest

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"sec_dash/backend/internal/model"
)

// DefaultSensor returns the sensor name used when a payload carries none.
func DefaultSensor(source string) string {
	if source == "snare" {
		return "vm-snare"
	}
	return "vm-honeypot"
}

func str(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func num(m map[string]interface{}, k string) float64 {
	switch v := m[k].(type) {
	case float64:
		return v
	case json.Number:
		f, _ := v.Float64()
		return f
	}
	return 0
}

// Normalize converts one decoded payload into an Event. querySensor is the
// optional ?sensor= value from the ingest request.
func Normalize(p map[string]interface{}, querySensor string) (*model.Event, error) {
	raw := str(p, "eventid")
	if raw == "" {
		return nil, fmt.Errorf("payload has no eventid")
	}
	ev := &model.Event{
		RawType:  raw,
		Session:  str(p, "session"),
		IP:       str(p, "src_ip"),
		Port:     int(num(p, "src_port")),
		DstPort:  int(num(p, "dst_port")),
		Proto:    strings.ToLower(str(p, "protocol")),
		User:     str(p, "username"),
		Pass:     str(p, "password"),
		Input:    str(p, "input"),
		Client:   str(p, "version"),
		URL:      str(p, "url"),
		SHA256:   str(p, "shasum"),
		Size:     int64(num(p, "size")),
		Duration: num(p, "duration"),
	}
	if ev.SHA256 == "" {
		ev.SHA256 = str(p, "sha256")
	}

	if strings.HasPrefix(raw, "snare.") || strings.HasPrefix(raw, "tanner.") {
		ev.Source = "snare"
	} else {
		ev.Source = "cowrie"
	}

	switch {
	case querySensor != "":
		ev.Sensor = querySensor
	case str(p, "sensor") != "":
		ev.Sensor = str(p, "sensor")
	default:
		ev.Sensor = DefaultSensor(ev.Source)
	}

	if ts := str(p, "timestamp"); ts != "" {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999Z0700"} {
			if t, err := time.Parse(layout, ts); err == nil {
				ev.Time = t.UTC()
				break
			}
		}
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}

	ev.Kind = kindOf(raw)
	// Cowrie also reports a hash for every terminal recording (cowrie.log.closed). That is
	// not an attacker file, so only real downloads/uploads carry a hash and size.
	if ev.Kind != model.KindDownload && ev.Kind != model.KindUpload {
		ev.SHA256, ev.Size = "", 0
	}
	if ev.Source == "snare" {
		ev.Kind = model.KindHTTP
		ev.Method, ev.Path = parseRequestLine(ev.Input)
		if ev.Proto == "" {
			ev.Proto = "http"
		}
		if ev.DstPort == 0 {
			ev.DstPort = 80
		}
	}
	if ev.Proto == "" {
		switch {
		case ev.DstPort == 23 || ev.DstPort == 2323 || strings.Contains(raw, "telnet"):
			ev.Proto = "telnet"
		default:
			ev.Proto = "ssh"
		}
	}
	if ip := net.ParseIP(ev.IP); ip == nil {
		ev.IP = ""
	}
	return ev, nil
}

func kindOf(raw string) string {
	switch raw {
	case "cowrie.session.connect":
		return model.KindConnect
	case "cowrie.client.version":
		return model.KindClientVersion
	case "cowrie.login.failed":
		return model.KindLoginFailed
	case "cowrie.login.success":
		return model.KindLoginSuccess
	case "cowrie.command.input":
		return model.KindCommand
	case "cowrie.command.failed":
		return model.KindCommandFailed
	case "cowrie.session.file_download":
		return model.KindDownload
	case "cowrie.session.file_upload":
		return model.KindUpload
	case "cowrie.direct-tcpip.request", "cowrie.direct-tcpip.data":
		return model.KindForward
	case "cowrie.session.closed":
		return model.KindClose
	}
	return model.KindOther
}

// parseRequestLine extracts method and path from "GET /path HTTP/1.1".
func parseRequestLine(line string) (method, path string) {
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return strings.ToUpper(parts[0]), parts[1]
	}
	if len(parts) == 1 {
		return "GET", parts[0]
	}
	return "", ""
}

// FromStored converts a persisted document into an Event.
func FromStored(s *model.Stored) *model.Event {
	ev := &model.Event{
		Time: s.Time.UTC(), Sensor: s.Sensor, Source: s.Source, RawType: s.EventID,
		Session: s.Session, IP: s.IP, Port: s.Port, DstPort: s.DstPort, Proto: s.Proto,
		User: s.User, Pass: s.Pass, Input: s.Input, Client: s.Client, URL: s.URL,
		SHA256: s.SHA256, Size: s.Size, Duration: s.Duration, Geo: s.Geo,
	}
	if strings.HasPrefix(ev.RawType, "snare.") {
		ev.Source = "snare"
	}
	if ev.Source == "" || ev.Source == "unknown" {
		ev.Source = "cowrie"
	}
	if ev.Sensor == "" {
		ev.Sensor = DefaultSensor(ev.Source)
	}
	ev.Kind = kindOf(ev.RawType)
	if ev.Kind != model.KindDownload && ev.Kind != model.KindUpload {
		ev.SHA256, ev.Size = "", 0
	}
	if ev.Source == "snare" {
		ev.Kind = model.KindHTTP
		ev.Method, ev.Path = parseRequestLine(ev.Input)
	}
	if ev.Proto == "" {
		ev.Proto = "ssh"
	}
	return ev
}

// ToStored converts an Event into its persisted shape.
func ToStored(e *model.Event) *model.Stored {
	return &model.Stored{
		EventID: e.RawType, Sensor: e.Sensor, Source: e.Source, Time: e.Time,
		Session: e.Session, IP: e.IP, Port: e.Port, DstPort: e.DstPort, Proto: e.Proto,
		User: e.User, Pass: e.Pass, Input: e.Input, Client: e.Client, URL: e.URL,
		SHA256: e.SHA256, Size: e.Size, Duration: e.Duration, Geo: e.Geo,
	}
}
