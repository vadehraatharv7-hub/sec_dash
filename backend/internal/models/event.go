package models

import "time"

// CowrieRawEvent represents the JSON event format emitted by Cowrie honeypot
type CowrieRawEvent struct {
	EventID       string      `json:"eventid"`
	Timestamp     string      `json:"timestamp"`
	Session       string      `json:"session"`
	SourceIP      string      `json:"src_ip"`
	SourcePort    int         `json:"src_port"`
	DestIP        string      `json:"dst_ip,omitempty"`
	DestPort      int         `json:"dst_port,omitempty"`
	Message       string      `json:"message,omitempty"`
	System        string      `json:"system,omitempty"`
	Username      string      `json:"username,omitempty"`
	Password      string      `json:"password,omitempty"`
	Input         string      `json:"input,omitempty"`
	Duration      float64     `json:"duration,omitempty"`
	Protocol      string      `json:"protocol,omitempty"`
	Version       string      `json:"version,omitempty"`       // SSH client version
	URL           string      `json:"url,omitempty"`           // file download URL
	Outfile       string      `json:"outfile,omitempty"`       // saved file path
	SHA256        string      `json:"shasum,omitempty"`        // file hash
	Size          int64       `json:"size,omitempty"`          // file size
	Data          interface{} `json:"data,omitempty"`
	RawPayload    string      `json:"-"`
}

// GeoLocation holds geographical metadata for an IP
type GeoLocation struct {
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ASN         string  `json:"asn,omitempty"`
	Org         string  `json:"org,omitempty"`
}

// EnrichedEvent represents a normalized, geo-enriched event ready for querying and UI streaming
type EnrichedEvent struct {
	ID          int64       `json:"id"`
	EventID     string      `json:"eventid"`
	Timestamp   time.Time   `json:"timestamp"`
	Session     string      `json:"session"`
	SourceIP    string      `json:"src_ip"`
	SourcePort  int         `json:"src_port"`
	DestPort    int         `json:"dst_port"`
	Protocol    string      `json:"protocol"`
	Username    string      `json:"username,omitempty"`
	Password    string      `json:"password,omitempty"`
	Input       string      `json:"input,omitempty"`
	SSHVersion  string      `json:"ssh_version,omitempty"`
	DownloadURL string      `json:"download_url,omitempty"`
	SHA256      string      `json:"sha256,omitempty"`
	FileSize    int64       `json:"file_size,omitempty"`
	Duration    float64     `json:"duration,omitempty"`
	Geo         GeoLocation `json:"geo"`
	Severity    string      `json:"severity"` // "info", "warning", "high", "critical"
	Description string      `json:"description"`
}

// LokiPushRequest represents the payload structure sent by Grafana Alloy (loki.write)
type LokiPushRequest struct {
	Streams []LokiStream `json:"streams"`
}

type LokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][]string        `json:"values"` // [ [ "timestamp_nanos", "log_line" ], ... ]
}

// OverviewStats contains key performance indicators for the security dashboard
type OverviewStats struct {
	TotalEvents         int64         `json:"total_events"`
	UniqueAttackers     int64         `json:"unique_attackers"`
	ActiveSessions      int64         `json:"active_sessions"`
	FailedLogins        int64         `json:"failed_logins"`
	SuccessfulLogins    int64         `json:"successful_logins"`
	CommandsExecuted    int64         `json:"commands_executed"`
	FilesCaptured       int64         `json:"files_captured"`
	TopAttackedPorts    map[int]int64 `json:"top_attacked_ports"`
	IngestionRatePerSec float64       `json:"ingestion_rate_per_sec"`
	CompromiseRatio     float64       `json:"compromise_ratio"` // successful / total connections
	UniqueASNs          int64         `json:"unique_asns"`
	AvgSessionDuration  float64       `json:"avg_session_duration"`
}

// CountryAttackStat represents aggregated attack counts by country
type CountryAttackStat struct {
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Count       int64   `json:"count"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// CredentialStat represents brute-force username/password frequencies
type CredentialStat struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	Count     int64     `json:"count"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// CommandStat represents attacker shell command frequencies
type CommandStat struct {
	Command string `json:"command"`
	Count   int64  `json:"count"`
}

// TimelinePoint represents attacks in a specific time bucket
type TimelinePoint struct {
	TimeBucket string `json:"time_bucket"`
	Total      int64  `json:"total"`
	SSH        int64  `json:"ssh"`
	Telnet     int64  `json:"telnet"`
}

// MitreTactic details a specific technique mapped to MITRE ATT&CK
type MitreTactic struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Phase    string `json:"phase"`
	Evidence string `json:"evidence"`
}

// AIAnalysisResult holds the automated LLM threat triage
type AIAnalysisResult struct {
	SessionID           string        `json:"session_id"`
	SourceIP            string        `json:"src_ip"`
	AttackerIntent      string        `json:"attacker_intent"`
	SkillLevel          string        `json:"skill_level"`
	Confidence          int           `json:"confidence"`
	Summary             string        `json:"summary"`
	ThreatCategory      string        `json:"threat_category"`
	MitreTactics        []MitreTactic `json:"mitre_tactics"`
	CompromisedServices []string      `json:"compromised_services"`
	RecommendedAction   string        `json:"recommended_action"`
	AnalyzedAt          time.Time     `json:"analyzed_at"`
	ModelUsed           string        `json:"model_used"`
}

// KillChainPhase represents one stage of the Cyber Kill Chain for a session
type KillChainPhase struct {
	PhaseNumber int    `json:"phase_number"`
	PhaseName   string `json:"phase_name"`
	Status      string `json:"status"` // "achieved", "blocked", "inactive"
	Timestamp   string `json:"timestamp,omitempty"`
	Summary     string `json:"summary"`
	Evidence    string `json:"evidence,omitempty"`
}

// BotnetFingerprint groups client version strings and botnet signatures
type BotnetFingerprint struct {
	ClientVersion  string    `json:"client_version"`
	BotnetCategory string    `json:"botnet_category"`
	SignatureType  string    `json:"signature_type"` // "Worm", "Scanner", "Interactive", "Custom"
	Count          int64     `json:"count"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
	CommonCommands []string  `json:"common_commands"`
}

// WebhookConfig defines an alert destination
type WebhookConfig struct {
	ID                  int64     `json:"id"`
	Name                string    `json:"name"`
	URL                 string    `json:"url"`
	Type                string    `json:"type"` // "slack", "discord", "generic"
	AlertOnLoginSuccess bool      `json:"alert_on_login_success"`
	AlertOnMalware      bool      `json:"alert_on_malware"`
	AlertOnCriticalCmd  bool      `json:"alert_on_critical_cmd"`
	Enabled             bool      `json:"enabled"`
	CreatedAt           time.Time `json:"created_at"`
}

// WebhookLog records dispatched alert status
type WebhookLog struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	WebhookID   int64     `json:"webhook_id"`
	WebhookName string    `json:"webhook_name"`
	EventType   string    `json:"event_type"`
	StatusCode  int       `json:"status_code"`
	Success     bool      `json:"success"`
	Message     string    `json:"message"`
}
