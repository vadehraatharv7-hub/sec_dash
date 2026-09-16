package killchain

import (
	"strings"

	"sec_dash/backend/internal/models"
)

// Evaluate constructs the 7-stage Cyber Kill Chain progression for a session
func Evaluate(events []*models.EnrichedEvent) []models.KillChainPhase {
	phases := []models.KillChainPhase{
		{
			PhaseNumber: 1,
			PhaseName:   "Reconnaissance",
			Status:      "not_attempted",
			Summary:     "Pre-attack scanning, banner grabbing, and port mapping.",
		},
		{
			PhaseNumber: 2,
			PhaseName:   "Weaponization & Delivery",
			Status:      "not_attempted",
			Summary:     "Brute-force credential stuffing and exploit payload delivery.",
		},
		{
			PhaseNumber: 3,
			PhaseName:   "Exploitation (Initial Access)",
			Status:      "blocked",
			Summary:     "Authentication bypass or credential verification for interactive shell.",
		},
		{
			PhaseNumber: 4,
			PhaseName:   "Discovery & Enumeration",
			Status:      "inactive",
			Summary:     "Host enumeration: OS version, CPU architecture, UID permissions.",
		},
		{
			PhaseNumber: 5,
			PhaseName:   "Ingress Tool Transfer",
			Status:      "inactive",
			Summary:     "Staging secondary malware payloads, dropper scripts, or ELF binaries.",
		},
		{
			PhaseNumber: 6,
			PhaseName:   "Execution & Persistence",
			Status:      "inactive",
			Summary:     "Granting execute permissions (chmod +x) or scheduling cron persistence.",
		},
		{
			PhaseNumber: 7,
			PhaseName:   "Defense Evasion / Action on Objective",
			Status:      "inactive",
			Summary:     "Flushing iptables, clearing /tmp traces, or executing DDoS/Miner payload.",
		},
	}

	if len(events) == 0 {
		return phases
	}

	// Scan events
	for _, ev := range events {
		// Phase 1: Reconnaissance
		if ev.EventID == "cowrie.session.connect" || ev.EventID == "cowrie.client.version" {
			phases[0].Status = "achieved"
			phases[0].Timestamp = ev.Timestamp.Format("15:04:05")
			if ev.SSHVersion != "" {
				phases[0].Evidence = "Client Version: " + ev.SSHVersion
			} else {
				phases[0].Evidence = "Inbound connection on port " + string(rune(ev.DestPort))
			}
		}

		// Phase 2: Weaponization & Delivery
		if ev.EventID == "cowrie.login.failed" || ev.EventID == "cowrie.login.success" {
			phases[1].Status = "achieved"
			phases[1].Timestamp = ev.Timestamp.Format("15:04:05")
			phases[1].Evidence = "Attempted credentials: " + ev.Username + " / " + ev.Password
		}

		// Phase 3: Exploitation
		if ev.EventID == "cowrie.login.success" {
			phases[2].Status = "achieved"
			phases[2].Timestamp = ev.Timestamp.Format("15:04:05")
			phases[2].Evidence = "Authenticated as " + ev.Username + " (Pseudo-terminal granted)"
		}

		// Phase 4, 5, 6, 7 from commands and downloads
		if ev.Input != "" {
			cmdLower := strings.ToLower(ev.Input)

			// Phase 4: Discovery
			if strings.Contains(cmdLower, "uname") || strings.Contains(cmdLower, "cpuinfo") ||
				strings.Contains(cmdLower, "whoami") || strings.Contains(cmdLower, "id") ||
				strings.Contains(cmdLower, "cat /etc") {
				phases[3].Status = "achieved"
				phases[3].Timestamp = ev.Timestamp.Format("15:04:05")
				phases[3].Evidence = "Command: " + ev.Input
			}

			// Phase 5: Ingress Tool Transfer
			if strings.Contains(cmdLower, "wget") || strings.Contains(cmdLower, "curl") ||
				strings.Contains(cmdLower, "tftp") || strings.Contains(cmdLower, "ftpget") {
				phases[4].Status = "achieved"
				phases[4].Timestamp = ev.Timestamp.Format("15:04:05")
				phases[4].Evidence = "Payload Fetch: " + ev.Input
			}

			// Phase 6: Execution & Persistence
			if strings.Contains(cmdLower, "chmod") || strings.Contains(cmdLower, "crontab") ||
				strings.Contains(cmdLower, "/tmp/") || strings.Contains(cmdLower, ".sh") {
				phases[5].Status = "achieved"
				phases[5].Timestamp = ev.Timestamp.Format("15:04:05")
				phases[5].Evidence = "Execution: " + ev.Input
			}

			// Phase 7: Defense Evasion
			if strings.Contains(cmdLower, "rm -rf") || strings.Contains(cmdLower, "history") ||
				strings.Contains(cmdLower, "iptables") {
				phases[6].Status = "achieved"
				phases[6].Timestamp = ev.Timestamp.Format("15:04:05")
				phases[6].Evidence = "Anti-Forensics: " + ev.Input
			}
		}

		if ev.EventID == "cowrie.session.file_download" {
			phases[4].Status = "achieved"
			phases[4].Timestamp = ev.Timestamp.Format("15:04:05")
			phases[4].Evidence = "Downloaded: " + ev.DownloadURL + " (SHA256: " + ev.SHA256 + ")"
		}
	}

	return phases
}
