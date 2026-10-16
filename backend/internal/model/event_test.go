package model

import (
	"testing"
	"time"
)

func TestFingerprintIgnoresSubMillisecondAndDistinguishesContent(t *testing.T) {
	base := Event{Time: time.Date(2026, 10, 15, 23, 33, 20, 123456789, time.UTC), Sensor: "s", RawType: "cowrie.command.input", Session: "a", IP: "198.51.100.1", Input: "sh"}
	same := base
	same.Time = base.Time.Add(400 * time.Microsecond) // same millisecond
	if base.Fingerprint() != same.Fingerprint() {
		t.Fatal("events in the same millisecond with the same content must match")
	}
	other := base
	other.Input = "shell"
	later := base
	later.Time = base.Time.Add(2 * time.Millisecond)
	if base.Fingerprint() == other.Fingerprint() || base.Fingerprint() == later.Fingerprint() {
		t.Fatal("different content or time must not match")
	}
}
