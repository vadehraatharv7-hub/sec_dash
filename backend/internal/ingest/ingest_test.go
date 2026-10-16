package ingest

import (
	"testing"

	"sec_dash/backend/internal/model"
)

func TestNormalizeCowrie(t *testing.T) {
	ev, err := Normalize(map[string]interface{}{
		"eventid": "cowrie.login.failed", "src_ip": "198.51.100.4", "username": "root", "password": "x",
		"dst_port": float64(22), "session": "abc", "timestamp": "2026-10-15T10:00:00.123456Z",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Kind != model.KindLoginFailed || ev.Source != "cowrie" || ev.Sensor != "vm-honeypot" || ev.Proto != "ssh" {
		t.Fatalf("unexpected normalization: %+v", ev)
	}
	if ev.Time.Year() != 2026 {
		t.Fatalf("timestamp not parsed: %v", ev.Time)
	}
}

func TestNormalizeSnareUsesQuerySensorAndParsesRequest(t *testing.T) {
	ev, err := Normalize(map[string]interface{}{"eventid": "snare.http.request", "input": "GET /wp-login.php HTTP/1.1"}, "edge-1")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Source != "snare" || ev.Sensor != "edge-1" || ev.Kind != model.KindHTTP || ev.Method != "GET" || ev.Path != "/wp-login.php" {
		t.Fatalf("unexpected: %+v", ev)
	}
	if ev.IP != "" {
		t.Fatalf("a missing source IP must stay empty, got %q", ev.IP)
	}
}

func TestNormalizeRejectsGarbageIPAndMissingEventID(t *testing.T) {
	if _, err := Normalize(map[string]interface{}{"src_ip": "1.2.3.4"}, ""); err == nil {
		t.Fatal("expected error without eventid")
	}
	ev, _ := Normalize(map[string]interface{}{"eventid": "cowrie.session.connect", "src_ip": "not-an-ip"}, "")
	if ev.IP != "" {
		t.Fatalf("invalid IP should be dropped, got %q", ev.IP)
	}
}

func TestStoredRoundTripKeepsLegacyDocsReadable(t *testing.T) {
	legacy := &model.Stored{EventID: "cowrie.command.input", Input: "uname -a", IP: "198.51.100.4"} // no sensor, no source
	ev := FromStored(legacy)
	if ev.Sensor != "vm-honeypot" || ev.Source != "cowrie" || ev.Kind != model.KindCommand {
		t.Fatalf("legacy doc not upgraded: %+v", ev)
	}
}

func TestTTYLogHashIsNotMalware(t *testing.T) {
	ev, _ := Normalize(map[string]interface{}{
		"eventid": "cowrie.log.closed", "src_ip": "198.51.100.4", "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "size": float64(345),
	}, "")
	if ev.SHA256 != "" || ev.Size != 0 {
		t.Fatalf("terminal recording hash must not be kept: %+v", ev)
	}
	dl, _ := Normalize(map[string]interface{}{"eventid": "cowrie.session.file_download", "src_ip": "198.51.100.4", "shasum": "ab", "url": "http://x/y", "size": float64(10)}, "")
	if dl.SHA256 != "ab" || dl.Size != 10 {
		t.Fatalf("real downloads keep their hash: %+v", dl)
	}
	legacy := FromStored(&model.Stored{EventID: "cowrie.log.closed", SHA256: "e3b0", IP: "198.51.100.4"})
	if legacy.SHA256 != "" {
		t.Fatal("legacy documents must be cleaned on load too")
	}
}
