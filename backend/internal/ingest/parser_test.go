package ingest

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"sec_dash/backend/internal/models"
)

func TestParseCowrieJSON(t *testing.T) {
	parser := NewParser()

	raw := []byte(`{
		"eventid": "cowrie.login.failed",
		"timestamp": "2026-09-18T01:00:00.000Z",
		"src_ip": "185.220.101.5",
		"src_port": 43210,
		"dst_port": 2222,
		"session": "sess-test-123",
		"username": "root",
		"password": "toor",
		"message": "Login failed"
	}`)

	ev, err := parser.ParseCowrieJSON(raw)
	if err != nil {
		t.Fatalf("ParseCowrieJSON failed: %v", err)
	}

	if ev.EventID != "cowrie.login.failed" {
		t.Errorf("expected eventid 'cowrie.login.failed', got '%s'", ev.EventID)
	}
	if ev.SourceIP != "185.220.101.5" {
		t.Errorf("expected src_ip '185.220.101.5', got '%s'", ev.SourceIP)
	}
	if ev.Username != "root" || ev.Password != "toor" {
		t.Errorf("expected creds root:toor, got %s:%s", ev.Username, ev.Password)
	}
	if ev.Severity != "warning" {
		t.Errorf("expected severity 'warning', got '%s'", ev.Severity)
	}
}

func TestParseLokiPush(t *testing.T) {
	parser := NewParser()

	lokiPayload := models.LokiPushRequest{
		Streams: []models.LokiStream{
			{
				Stream: map[string]string{"app": "cowrie", "honeypot": "node-1"},
				Values: [][]string{
					{
						"1726617600000000000",
						`{"eventid":"cowrie.command.input","timestamp":"2026-09-18T01:05:00.000Z","src_ip":"198.51.100.2","src_port":51234,"dst_port":22,"session":"s1","input":"uname -a"}`,
					},
					{
						"1726617601000000000",
						`{"eventid":"cowrie.session.file_download","timestamp":"2026-09-18T01:06:00.000Z","src_ip":"198.51.100.2","src_port":51234,"dst_port":22,"session":"s1","url":"http://malware.biz/bot.arm","shasum":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":1024}`,
					},
				},
			},
		},
	}

	data, err := json.Marshal(lokiPayload)
	if err != nil {
		t.Fatalf("failed to marshal test loki payload: %v", err)
	}

	events, err := parser.ParseLokiPush(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ParseLokiPush failed: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 parsed events from loki push, got %d", len(events))
	}

	if events[0].Input != "uname -a" {
		t.Errorf("expected first event input 'uname -a', got '%s'", events[0].Input)
	}
	if events[1].SHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("expected sha256 match, got '%s'", events[1].SHA256)
	}
}

func TestParseAutoBatchNDJSON(t *testing.T) {
	parser := NewParser()

	ndjson := []byte("{\"eventid\":\"cowrie.login.success\",\"timestamp\":\"" + time.Now().Format(time.RFC3339) + "\",\"src_ip\":\"10.0.0.1\",\"session\":\"s2\",\"username\":\"admin\",\"password\":\"\"}\n{\"eventid\":\"cowrie.command.input\",\"timestamp\":\"" + time.Now().Format(time.RFC3339) + "\",\"src_ip\":\"10.0.0.1\",\"session\":\"s2\",\"input\":\"cat /etc/passwd\"}")

	events, err := parser.ParseAutoBatch(ndjson)
	if err != nil {
		t.Fatalf("ParseAutoBatch failed: %v", err)
	}

	if len(events) != 2 {
		t.Fatalf("expected 2 events from NDJSON, got %d", len(events))
	}
	if events[0].Password != "" {
		t.Errorf("expected empty password, got '%s'", events[0].Password)
	}
}
