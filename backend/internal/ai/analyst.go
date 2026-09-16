package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"sec_dash/backend/internal/db"
	"sec_dash/backend/internal/models"
)

type Analyst struct {
	storage *db.Storage
}

func NewAnalyst(storage *db.Storage) *Analyst {
	return &Analyst{storage: storage}
}

// AnalyzeSession classifies the completed session transcript using either LLM API or Expert Heuristic engine
func (a *Analyst) AnalyzeSession(ctx context.Context, sessionID string) (*models.AIAnalysisResult, error) {
	// 1. Check cache first
	if cached, err := a.storage.GetAIAnalysis(sessionID); err == nil && cached != nil {
		return cached, nil
	}

	// 2. Fetch session commands & events
	events, err := a.storage.GetSessionEvents(sessionID)
	if err != nil || len(events) == 0 {
		return nil, fmt.Errorf("no events recorded for session %s", sessionID)
	}

	var commands []string
	var creds []string
	srcIP := events[0].SourceIP
	clientBanner := ""

	for _, ev := range events {
		if ev.Input != "" {
			commands = append(commands, ev.Input)
		}
		if ev.Username != "" {
			creds = append(creds, fmt.Sprintf("%s:%s", ev.Username, ev.Password))
		}
		if ev.SSHVersion != "" {
			clientBanner = ev.SSHVersion
		}
	}

	// 3. If GEMINI_API_KEY is available, call Gemini API
	geminiKey := os.Getenv("GEMINI_API_KEY")
	if geminiKey != "" {
		res, err := a.callGeminiLLM(ctx, geminiKey, sessionID, srcIP, clientBanner, creds, commands)
		if err == nil && res != nil {
			_ = a.storage.SaveAIAnalysis(sessionID, res)
			return res, nil
		}
	}

	// 4. Fallback to built-in cybersecurity expert heuristic engine
	res := a.heuristicAnalyze(sessionID, srcIP, clientBanner, creds, commands)
	_ = a.storage.SaveAIAnalysis(sessionID, res)
	return res, nil
}

func (a *Analyst) callGeminiLLM(ctx context.Context, apiKey, sessionID, srcIP, banner string, creds, commands []string) (*models.AIAnalysisResult, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=%s", apiKey)

	prompt := fmt.Sprintf(`You are a Principal Threat Intelligence Analyst for a SOC honeypot. Analyze this Cowrie session transcript and classify the attacker.
Session ID: %s
Source IP: %s
Client Banner: %s
Credentials Attempted: %v
Commands Executed in Shell: %v

Respond strictly with valid JSON with this exact schema:
{
  "attacker_intent": "string (1 line summary of intent)",
  "skill_level": "string (Automated Worm / Script Kiddie / Experienced Intruder / APT)",
  "confidence": 85,
  "summary": "string (2-3 sentences detailed analysis)",
  "threat_category": "string (Botnet Spread / Cryptojacking / Reconnaissance / Privilege Escalation / Credential Stuffer)",
  "mitre_tactics": [
    { "id": "Txxxx", "name": "string", "phase": "string", "evidence": "string" }
  ],
  "compromised_services": ["SSH"],
  "recommended_action": "string (actionable firewall or hardening advice)"
}`, sessionID, srcIP, banner, creds, commands)

	reqBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{"text": prompt},
				},
			},
		},
	}

	jsonBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gemini api error code: %d", resp.StatusCode)
	}

	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, err
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty gemini response")
	}

	rawText := geminiResp.Candidates[0].Content.Parts[0].Text
	rawText = strings.TrimPrefix(rawText, "```json")
	rawText = strings.TrimPrefix(rawText, "```")
	rawText = strings.TrimSuffix(rawText, "```")
	rawText = strings.TrimSpace(rawText)

	var result models.AIAnalysisResult
	if err := json.Unmarshal([]byte(rawText), &result); err != nil {
		return nil, err
	}

	result.SessionID = sessionID
	result.SourceIP = srcIP
	result.AnalyzedAt = time.Now()
	result.ModelUsed = "Google Gemini 1.5 Flash"
	return &result, nil
}

func (a *Analyst) heuristicAnalyze(sessionID, srcIP, banner string, creds, commands []string) *models.AIAnalysisResult {
	cmdText := strings.ToLower(strings.Join(commands, " "))

	var tactics []models.MitreTactic
	var intent string
	var category string
	var skillLevel string
	var confidence int = 90
	var summary string
	var recAction string

	// 1. Reconnaissance & Discovery
	if strings.Contains(cmdText, "uname") || strings.Contains(cmdText, "cpuinfo") || strings.Contains(cmdText, "cat /etc/passwd") {
		tactics = append(tactics, models.MitreTactic{
			ID:       "T1082",
			Name:     "System Information Discovery",
			Phase:    "Discovery",
			Evidence: "Attacker checked CPU, kernel architecture, or OS release",
		})
	}
	if strings.Contains(cmdText, "whoami") || strings.Contains(cmdText, "id") || strings.Contains(cmdText, "w") {
		tactics = append(tactics, models.MitreTactic{
			ID:       "T1033",
			Name:     "System Owner/User Discovery",
			Phase:    "Discovery",
			Evidence: "Attacker verified privileged UID 0 / root permissions",
		})
	}

	// 2. Ingress Tool Transfer / Malware Staging
	hasDownload := strings.Contains(cmdText, "wget") || strings.Contains(cmdText, "curl") || strings.Contains(cmdText, "tftp")
	if hasDownload {
		tactics = append(tactics, models.MitreTactic{
			ID:       "T1105",
			Name:     "Ingress Tool Transfer",
			Phase:    "Command and Control",
			Evidence: "Attacker executed web download client (wget/curl/tftp) to stage remote payload",
		})
	}

	// 3. Execution
	if strings.Contains(cmdText, "sh") || strings.Contains(cmdText, "bash") || strings.Contains(cmdText, "chmod +x") {
		tactics = append(tactics, models.MitreTactic{
			ID:       "T1059.004",
			Name:     "Unix Shell",
			Phase:    "Execution",
			Evidence: "Attacker granted execution permissions or piped remote payload into /bin/sh",
		})
	}

	// 4. Defense Evasion
	if strings.Contains(cmdText, "rm -rf") || strings.Contains(cmdText, "iptables -f") || strings.Contains(cmdText, "history -c") {
		tactics = append(tactics, models.MitreTactic{
			ID:       "T1070.004",
			Name:     "Indicator Removal on Host",
			Phase:    "Defense Evasion",
			Evidence: "Attacker cleared /tmp directory or flushed firewall tables to evade logging",
		})
	}

	// Determine high-level threat classification
	if hasDownload && (strings.Contains(cmdText, "bot") || strings.Contains(cmdText, "arm") || strings.Contains(cmdText, "mips")) {
		intent = "IoT/Mirai Botnet Recruitment & Dropper Deployment"
		category = "Botnet Spread"
		skillLevel = "Automated Worm / Botnet"
		summary = fmt.Sprintf("Adversary at %s gained shell access and executed automated staging scripts to fetch an ELF payload. The payload staging pattern matches standard Mirai/Mozi IoT botnet recruitment procedures.", srcIP)
		recAction = fmt.Sprintf("Block source IP %s at network edge; inspect egress traffic for C2 beaconing on IRC/HTTP ports.", srcIP)
	} else if hasDownload {
		intent = "Remote Staging & Arbitrary Code Execution"
		category = "Ingress Tool Transfer"
		skillLevel = "Script Kiddie / Automated Script"
		summary = fmt.Sprintf("Adversary at %s successfully authenticated and attempted to download an external shell script into /tmp. High probability of malicious secondary payload dropper.", srcIP)
		recAction = "Block external outbound HTTP/HTTPS curl requests from honeypot perimeter; monitor firewall drop logs."
	} else if len(commands) > 0 {
		intent = "Host Fingerprinting & Interactive Reconnaissance"
		category = "Reconnaissance"
		skillLevel = "Interactive Intruder"
		summary = fmt.Sprintf("Adversary connected from %s and executed reconnaissance binaries to map internal hardware and user accounts before disconnecting or proceeding.", srcIP)
		recAction = fmt.Sprintf("Add %s to firewall blocklist; check for simultaneous scanning on adjacent subnets.", srcIP)
	} else {
		intent = "Automated SSH Credential Stuffing"
		category = "Credential Stuffer"
		skillLevel = "Automated Scanner"
		summary = fmt.Sprintf("Adversary engaged in brute-force dictionary attacks against default system accounts (%s) without establishing an interactive shell session.", strings.Join(creds, ", "))
		recAction = "Enforce rate limiting on SSH port 22; disable password authentication on production hosts."
	}

	return &models.AIAnalysisResult{
		SessionID:           sessionID,
		SourceIP:            srcIP,
		AttackerIntent:      intent,
		SkillLevel:          skillLevel,
		Confidence:          confidence,
		Summary:             summary,
		ThreatCategory:      category,
		MitreTactics:        tactics,
		CompromisedServices: []string{"SSH (Port 22)"},
		RecommendedAction:   recAction,
		AnalyzedAt:          time.Now(),
		ModelUsed:           "SecDash Threat Engine (Rule-based TTP Classifier)",
	}
}
