package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"sec_dash/backend/internal/db"
	"sec_dash/backend/internal/models"
)

type Engine struct {
	storage *db.Storage
	client  *http.Client
}

func NewEngine(storage *db.Storage) *Engine {
	return &Engine{
		storage: storage,
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

// EvaluateAndDispatch evaluates incoming events against configured webhook alert rules
func (e *Engine) EvaluateAndDispatch(ev *models.EnrichedEvent) {
	// Fast filter for alertable events
	isLoginSuccess := ev.EventID == "cowrie.login.success"
	isMalware := ev.EventID == "cowrie.session.file_download" || ev.SHA256 != ""
	isCritCmd := ev.EventID == "cowrie.command.input" && isCriticalCommand(ev.Input)

	if !isLoginSuccess && !isMalware && !isCritCmd {
		return
	}

	webhooks, err := e.storage.GetActiveWebhooks()
	if err != nil || len(webhooks) == 0 {
		return
	}

	for _, hook := range webhooks {
		shouldSend := false
		if isLoginSuccess && hook.AlertOnLoginSuccess {
			shouldSend = true
		} else if isMalware && hook.AlertOnMalware {
			shouldSend = true
		} else if isCritCmd && hook.AlertOnCriticalCmd {
			shouldSend = true
		}

		if shouldSend {
			go e.sendAlert(hook, ev)
		}
	}
}

func (e *Engine) sendAlert(hook models.WebhookConfig, ev *models.EnrichedEvent) {
	payload := formatAlertPayload(hook.Type, ev)
	resp, err := e.client.Post(hook.URL, "application/json", bytes.NewReader(payload))

	logEntry := &models.WebhookLog{
		Timestamp:   time.Now(),
		WebhookID:   hook.ID,
		WebhookName: hook.Name,
		EventType:   ev.EventID,
		Success:     false,
	}

	if err != nil {
		logEntry.Message = fmt.Sprintf("Network dispatch failed: %v", err)
		log.Printf("[Alerts] Webhook error (%s): %v", hook.Name, err)
	} else {
		defer resp.Body.Close()
		logEntry.StatusCode = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			logEntry.Success = true
			logEntry.Message = "Alert delivered successfully"
		} else {
			logEntry.Message = fmt.Sprintf("Remote endpoint rejected alert with HTTP %d", resp.StatusCode)
		}
	}

	_ = e.storage.LogWebhookAlert(logEntry)
}

// TestWebhook dispatches a verification payload
func (e *Engine) TestWebhook(hook models.WebhookConfig) (bool, string) {
	testEvent := &models.EnrichedEvent{
		EventID:     "cowrie.login.success",
		Timestamp:   time.Now(),
		Session:     "test_diagnostic",
		SourceIP:    "198.51.100.42",
		Username:    "root",
		Password:    "honey_pass",
		Description: "Diagnostic test alert from SecDash Honeypot Engine",
		Geo: models.GeoLocation{
			CountryCode: "US",
			CountryName: "United States",
			City:        "Test Subnet",
		},
	}

	payload := formatAlertPayload(hook.Type, testEvent)
	resp, err := e.client.Post(hook.URL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, fmt.Sprintf("Test alert delivered successfully (HTTP %d)", resp.StatusCode)
	}
	return false, fmt.Sprintf("Remote webhook returned HTTP %d", resp.StatusCode)
}

func isCriticalCommand(cmd string) bool {
	lower := strings.ToLower(cmd)
	critTokens := []string{
		"curl", "wget", "chmod +x", "rm -rf", "iptables -f", "crontab",
		"/tmp/", "nc ", "bash -i", "/dev/tcp", "sh <", "| sh", "| bash",
	}
	for _, tok := range critTokens {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

func formatAlertPayload(hookType string, ev *models.EnrichedEvent) []byte {
	title := fmt.Sprintf("🚨 SECDASH HONEYPOT ALERT: %s", ev.EventID)
	text := fmt.Sprintf("Adversary %s (%s) triggered %s.\nDetails: %s\nSession: %s",
		ev.SourceIP, ev.Geo.CountryName, ev.EventID, ev.Description, ev.Session)

	switch hookType {
	case "slack":
		payload := map[string]interface{}{
			"text": title,
			"attachments": []map[string]interface{}{
				{
					"color": "#f43f5e",
					"fields": []map[string]interface{}{
						{"title": "Event", "value": ev.EventID, "short": true},
						{"title": "Source IP", "value": ev.SourceIP, "short": true},
						{"title": "Location", "value": fmt.Sprintf("%s (%s)", ev.Geo.CountryName, ev.Geo.CountryCode), "short": true},
						{"title": "Activity", "value": ev.Description, "short": false},
					},
				},
			},
		}
		data, _ := json.Marshal(payload)
		return data

	case "discord":
		payload := map[string]interface{}{
			"content": title,
			"embeds": []map[string]interface{}{
				{
					"title":       title,
					"description": text,
					"color":       16007774, // Rose red
					"fields": []map[string]interface{}{
						{"name": "Attacker IP", "value": ev.SourceIP, "inline": true},
						{"name": "Country", "value": ev.Geo.CountryName, "inline": true},
						{"name": "Activity", "value": ev.Description, "inline": false},
					},
				},
			},
		}
		data, _ := json.Marshal(payload)
		return data

	default: // Generic JSON
		data, _ := json.Marshal(ev)
		return data
	}
}
