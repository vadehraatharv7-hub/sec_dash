package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"sec_dash/backend/internal/models"
)

type Storage struct {
	db   *sql.DB
	lock sync.RWMutex
}

func NewStorage(dbPath string) (*Storage, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	// SQLite connection string with WAL and high-throughput pragmas
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-64000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(time.Hour)

	s := &Storage{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	log.Printf("[DB] Initialized SQLite database at %s (WAL mode enabled)", dbPath)
	return s, nil
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		eventid TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		session TEXT NOT NULL,
		src_ip TEXT NOT NULL,
		src_port INTEGER,
		dst_port INTEGER,
		protocol TEXT,
		username TEXT,
		password TEXT,
		input TEXT,
		ssh_version TEXT,
		download_url TEXT,
		sha256 TEXT,
		file_size INTEGER,
		duration REAL,
		country_code TEXT,
		country_name TEXT,
		city TEXT,
		latitude REAL,
		longitude REAL,
		asn TEXT,
		org TEXT,
		severity TEXT,
		description TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
	CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
	CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
	CREATE INDEX IF NOT EXISTS idx_events_session ON events(session);
	CREATE INDEX IF NOT EXISTS idx_events_country ON events(country_code);

	CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		src_ip TEXT NOT NULL,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		duration REAL DEFAULT 0,
		protocol TEXT,
		country_code TEXT,
		country_name TEXT,
		commands_count INTEGER DEFAULT 0,
		login_success INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time DESC);
	CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip);

	CREATE TABLE IF NOT EXISTS credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		src_ip TEXT NOT NULL,
		username TEXT NOT NULL,
		password TEXT NOT NULL,
		success INTEGER NOT NULL,
		session TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(username);
	CREATE INDEX IF NOT EXISTS idx_credentials_pass ON credentials(password);

	CREATE TABLE IF NOT EXISTS commands (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		src_ip TEXT NOT NULL,
		session TEXT NOT NULL,
		command TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_commands_command ON commands(command);
	CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session);

	CREATE TABLE IF NOT EXISTS malware (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		src_ip TEXT NOT NULL,
		session TEXT NOT NULL,
		url TEXT,
		sha256 TEXT,
		file_size INTEGER
	);

	CREATE INDEX IF NOT EXISTS idx_malware_sha ON malware(sha256);

	CREATE TABLE IF NOT EXISTS banned_ips (
		ip TEXT PRIMARY KEY,
		reason TEXT,
		banned_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS webhooks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		url TEXT NOT NULL,
		type TEXT NOT NULL,
		alert_login_success INTEGER DEFAULT 1,
		alert_malware INTEGER DEFAULT 1,
		alert_crit_cmd INTEGER DEFAULT 1,
		enabled INTEGER DEFAULT 1,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS webhook_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		webhook_id INTEGER NOT NULL,
		webhook_name TEXT NOT NULL,
		event_type TEXT NOT NULL,
		status_code INTEGER,
		success INTEGER NOT NULL,
		message TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_webhook_logs_ts ON webhook_logs(timestamp DESC);

	CREATE TABLE IF NOT EXISTS ai_analyses (
		session_id TEXT PRIMARY KEY,
		analysis_json TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);
	`

	_, err := s.db.Exec(schema)
	return err
}

// InsertEventsBatch performs high-throughput transaction batch insert
func (s *Storage) InsertEventsBatch(events []*models.EnrichedEvent) error {
	if len(events) == 0 {
		return nil
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	eventStmt, err := tx.Prepare(`
		INSERT INTO events (
			eventid, timestamp, session, src_ip, src_port, dst_port,
			protocol, username, password, input, ssh_version, download_url,
			sha256, file_size, duration, country_code, country_name, city,
			latitude, longitude, asn, org, severity, description
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer eventStmt.Close()

	credStmt, err := tx.Prepare(`
		INSERT INTO credentials (timestamp, src_ip, username, password, success, session)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer credStmt.Close()

	cmdStmt, err := tx.Prepare(`
		INSERT INTO commands (timestamp, src_ip, session, command)
		VALUES (?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer cmdStmt.Close()

	malwareStmt, err := tx.Prepare(`
		INSERT INTO malware (timestamp, src_ip, session, url, sha256, file_size)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer malwareStmt.Close()

	sessionUpsertStmt, err := tx.Prepare(`
		INSERT INTO sessions (session_id, src_ip, start_time, end_time, duration, protocol, country_code, country_name, commands_count, login_success)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			end_time = excluded.end_time,
			duration = MAX(sessions.duration, excluded.duration),
			commands_count = sessions.commands_count + excluded.commands_count,
			login_success = MAX(sessions.login_success, excluded.login_success)
	`)
	if err != nil {
		return err
	}
	defer sessionUpsertStmt.Close()

	for _, ev := range events {
		res, err := eventStmt.Exec(
			ev.EventID, ev.Timestamp, ev.Session, ev.SourceIP, ev.SourcePort, ev.DestPort,
			ev.Protocol, ev.Username, ev.Password, ev.Input, ev.SSHVersion, ev.DownloadURL,
			ev.SHA256, ev.FileSize, ev.Duration, ev.Geo.CountryCode, ev.Geo.CountryName, ev.Geo.City,
			ev.Geo.Latitude, ev.Geo.Longitude, ev.Geo.ASN, ev.Geo.Org, ev.Severity, ev.Description,
		)
		if err != nil {
			return err
		}
		ev.ID, _ = res.LastInsertId()

		// Credential attempts
		if ev.EventID == "cowrie.login.success" || ev.EventID == "cowrie.login.failed" {
			success := 0
			if ev.EventID == "cowrie.login.success" {
				success = 1
			}
			_, _ = credStmt.Exec(ev.Timestamp, ev.SourceIP, ev.Username, ev.Password, success, ev.Session)
		}

		// Shell commands
		if ev.EventID == "cowrie.command.input" && ev.Input != "" {
			_, _ = cmdStmt.Exec(ev.Timestamp, ev.SourceIP, ev.Session, ev.Input)
		}

		// Malware / File downloads
		if ev.EventID == "cowrie.session.file_download" || ev.SHA256 != "" {
			_, _ = malwareStmt.Exec(ev.Timestamp, ev.SourceIP, ev.Session, ev.DownloadURL, ev.SHA256, ev.FileSize)
		}

		// Session update
		cmdInc := 0
		if ev.EventID == "cowrie.command.input" {
			cmdInc = 1
		}
		loginSuccess := 0
		if ev.EventID == "cowrie.login.success" {
			loginSuccess = 1
		}

		_, _ = sessionUpsertStmt.Exec(
			ev.Session, ev.SourceIP, ev.Timestamp, ev.Timestamp, ev.Duration, ev.Protocol,
			ev.Geo.CountryCode, ev.Geo.CountryName, cmdInc, loginSuccess,
		)
	}

	return tx.Commit()
}

// GetOverviewStats returns high-level security metrics
func (s *Storage) GetOverviewStats() (*models.OverviewStats, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	stats := &models.OverviewStats{
		TopAttackedPorts: make(map[int]int64),
	}

	// Total events
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&stats.TotalEvents)

	// Unique attacker IPs
	_ = s.db.QueryRow(`SELECT COUNT(DISTINCT src_ip) FROM events`).Scan(&stats.UniqueAttackers)

	// Active sessions (sessions in last 10 minutes)
	tenMinAgo := time.Now().Add(-10 * time.Minute)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE end_time >= ?`, tenMinAgo).Scan(&stats.ActiveSessions)

	// Failed & successful logins
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE success = 0`).Scan(&stats.FailedLogins)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE success = 1`).Scan(&stats.SuccessfulLogins)

	// Commands executed
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM commands`).Scan(&stats.CommandsExecuted)

	// Files captured
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM malware`).Scan(&stats.FilesCaptured)

	// Top attacked ports
	rows, err := s.db.Query(`SELECT dst_port, COUNT(*) as cnt FROM events WHERE dst_port > 0 GROUP BY dst_port ORDER BY cnt DESC LIMIT 5`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var port int
			var cnt int64
			if err := rows.Scan(&port, &cnt); err == nil {
				stats.TopAttackedPorts[port] = cnt
			}
		}
	}

	// Unique ASNs
	_ = s.db.QueryRow(`SELECT COUNT(DISTINCT asn) FROM events WHERE asn != '' AND asn != 'AS0'`).Scan(&stats.UniqueASNs)

	// Avg session duration
	_ = s.db.QueryRow(`SELECT COALESCE(AVG(duration), 0) FROM sessions WHERE duration > 0`).Scan(&stats.AvgSessionDuration)

	// Compromise ratio (%)
	totalLogins := stats.FailedLogins + stats.SuccessfulLogins
	if totalLogins > 0 {
		stats.CompromiseRatio = (float64(stats.SuccessfulLogins) / float64(totalLogins)) * 100.0
	} else {
		stats.CompromiseRatio = 0.0
	}

	return stats, nil
}

// GetTimeline returns attack count aggregated over time slices
func (s *Storage) GetTimeline(limit int) ([]models.TimelinePoint, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `
		SELECT 
			strftime('%Y-%m-%d %H:00', timestamp) as hour_bucket,
			COUNT(*) as total,
			SUM(CASE WHEN protocol = 'ssh' OR dst_port = 22 OR dst_port = 2222 THEN 1 ELSE 0 END) as ssh_cnt,
			SUM(CASE WHEN protocol = 'telnet' OR dst_port = 23 OR dst_port = 2323 THEN 1 ELSE 0 END) as telnet_cnt
		FROM events
		GROUP BY hour_bucket
		ORDER BY hour_bucket DESC
		LIMIT ?
	`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var points []models.TimelinePoint
	for rows.Next() {
		var p models.TimelinePoint
		if err := rows.Scan(&p.TimeBucket, &p.Total, &p.SSH, &p.Telnet); err == nil {
			points = append(points, p)
		}
	}

	// Reverse to chronological order
	for i, j := 0, len(points)-1; i < j; i, j = i+1, j-1 {
		points[i], points[j] = points[j], points[i]
	}

	return points, nil
}

// GetTopCountries returns aggregated attacks by country code
func (s *Storage) GetTopCountries(limit int) ([]models.CountryAttackStat, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `
		SELECT country_code, country_name, AVG(latitude) as lat, AVG(longitude) as lon, COUNT(*) as cnt
		FROM events
		WHERE country_code != '' AND country_code != 'LOC'
		GROUP BY country_code, country_name
		ORDER BY cnt DESC
		LIMIT ?
	`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.CountryAttackStat
	for rows.Next() {
		var item models.CountryAttackStat
		if err := rows.Scan(&item.CountryCode, &item.CountryName, &item.Latitude, &item.Longitude, &item.Count); err == nil {
			list = append(list, item)
		}
	}
	return list, nil
}

// GetTopCredentials returns the most frequent brute force username/password attempts
func (s *Storage) GetTopCredentials(limit int) ([]models.CredentialStat, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `
		SELECT username, COALESCE(password, '') as password, COUNT(*) as cnt
		FROM credentials
		WHERE username != ''
		GROUP BY username, password
		ORDER BY cnt DESC
		LIMIT ?
	`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.CredentialStat
	for rows.Next() {
		var item models.CredentialStat
		if err := rows.Scan(&item.Username, &item.Password, &item.Count); err == nil {
			list = append(list, item)
		}
	}
	return list, nil
}

// GetTopCommands returns the most frequent commands entered in the honeypot
func (s *Storage) GetTopCommands(limit int) ([]models.CommandStat, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `
		SELECT command, COUNT(*) as cnt
		FROM commands
		WHERE command != ''
		GROUP BY command
		ORDER BY cnt DESC
		LIMIT ?
	`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.CommandStat
	for rows.Next() {
		var item models.CommandStat
		if err := rows.Scan(&item.Command, &item.Count); err == nil {
			list = append(list, item)
		}
	}
	return list, nil
}

// GetRecentEvents returns paginated and filtered events
func (s *Storage) GetRecentEvents(limit int, eventFilter, ipFilter string) ([]*models.EnrichedEvent, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var conditions []string
	var args []interface{}

	if eventFilter != "" && eventFilter != "all" {
		conditions = append(conditions, "eventid = ?")
		args = append(args, eventFilter)
	}
	if ipFilter != "" {
		conditions = append(conditions, "src_ip LIKE ?")
		args = append(args, "%"+ipFilter+"%")
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT id, eventid, timestamp, session, src_ip, src_port, dst_port, protocol,
		       username, password, input, ssh_version, download_url, sha256, file_size,
		       duration, country_code, country_name, city, latitude, longitude, asn, org,
		       severity, description
		FROM events
		%s
		ORDER BY timestamp DESC
		LIMIT ?
	`, whereClause)

	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.EnrichedEvent
	for rows.Next() {
		ev := &models.EnrichedEvent{}
		var ts time.Time
		err := rows.Scan(
			&ev.ID, &ev.EventID, &ts, &ev.Session, &ev.SourceIP, &ev.SourcePort, &ev.DestPort, &ev.Protocol,
			&ev.Username, &ev.Password, &ev.Input, &ev.SSHVersion, &ev.DownloadURL, &ev.SHA256, &ev.FileSize,
			&ev.Duration, &ev.Geo.CountryCode, &ev.Geo.CountryName, &ev.Geo.City, &ev.Geo.Latitude, &ev.Geo.Longitude,
			&ev.Geo.ASN, &ev.Geo.Org, &ev.Severity, &ev.Description,
		)
		if err == nil {
			ev.Timestamp = ts
			list = append(list, ev)
		}
	}
	return list, nil
}

// SessionRecord holds aggregated session information
type SessionRecord struct {
	SessionID     string    `json:"session_id"`
	SourceIP      string    `json:"src_ip"`
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Duration      float64   `json:"duration"`
	Protocol      string    `json:"protocol"`
	CountryCode   string    `json:"country_code"`
	CountryName   string    `json:"country_name"`
	CommandsCount int       `json:"commands_count"`
	LoginSuccess  bool      `json:"login_success"`
}

// GetSessions returns a list of sessions
func (s *Storage) GetSessions(limit int) ([]SessionRecord, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `
		SELECT session_id, src_ip, start_time, end_time, duration, protocol, country_code, country_name, commands_count, login_success
		FROM sessions
		ORDER BY start_time DESC
		LIMIT ?
	`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []SessionRecord
	for rows.Next() {
		var rec SessionRecord
		var success int
		if err := rows.Scan(&rec.SessionID, &rec.SourceIP, &rec.StartTime, &rec.EndTime, &rec.Duration, &rec.Protocol, &rec.CountryCode, &rec.CountryName, &rec.CommandsCount, &success); err == nil {
			rec.LoginSuccess = success == 1
			list = append(list, rec)
		}
	}
	return list, nil
}

// GetSessionCommands returns the chronological commands executed in a session
func (s *Storage) GetSessionCommands(sessionID string) ([]models.CommandStat, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `SELECT command, 1 FROM commands WHERE session = ? ORDER BY timestamp ASC`
	rows, err := s.db.Query(query, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cmds []models.CommandStat
	for rows.Next() {
		var cmd models.CommandStat
		var dummy int
		if err := rows.Scan(&cmd.Command, &dummy); err == nil {
			cmds = append(cmds, cmd)
		}
	}
	return cmds, nil
}

// MalwareRecord represents a captured malicious payload
type MalwareRecord struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"src_ip"`
	Session   string    `json:"session"`
	URL       string    `json:"url"`
	SHA256    string    `json:"sha256"`
	FileSize  int64     `json:"file_size"`
}

// GetMalwareFiles returns recently captured malicious binaries
func (s *Storage) GetMalwareFiles(limit int) ([]MalwareRecord, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `
		SELECT id, timestamp, src_ip, session, COALESCE(url, ''), COALESCE(sha256, ''), COALESCE(file_size, 0)
		FROM malware
		ORDER BY timestamp DESC
		LIMIT ?
	`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []MalwareRecord
	for rows.Next() {
		var m MalwareRecord
		if err := rows.Scan(&m.ID, &m.Timestamp, &m.SourceIP, &m.Session, &m.URL, &m.SHA256, &m.FileSize); err == nil {
			list = append(list, m)
		}
	}
	return list, nil
}

// IPThreatProfile aggregates complete threat intelligence on a specific attacker IP
type IPThreatProfile struct {
	IP               string               `json:"ip"`
	TotalEvents      int64                `json:"total_events"`
	FirstSeen        time.Time            `json:"first_seen"`
	LastSeen         time.Time            `json:"last_seen"`
	CountryCode      string               `json:"country_code"`
	CountryName      string               `json:"country_name"`
	City             string               `json:"city"`
	ASN              string               `json:"asn"`
	Org              string               `json:"org"`
	ThreatScore      int                  `json:"threat_score"` // 0-100
	AttemptedCreds   []models.CredentialStat `json:"attempted_creds"`
	ExecutedCommands []string             `json:"executed_commands"`
	ClientBanners    []string             `json:"client_banners"`
	IsBanned         bool                 `json:"is_banned"`
}

// GetIPThreatProfile gathers full forensics for an attacker IP
func (s *Storage) GetIPThreatProfile(ip string) (*IPThreatProfile, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	profile := &IPThreatProfile{
		IP:               ip,
		AttemptedCreds:   []models.CredentialStat{},
		ExecutedCommands: []string{},
		ClientBanners:    []string{},
	}

	// 1. Basic event stats & geo
	var firstSeenStr, lastSeenStr sql.NullString
	err := s.db.QueryRow(`
		SELECT COUNT(*), MIN(timestamp), MAX(timestamp),
		       COALESCE(country_code, ''), COALESCE(country_name, ''), COALESCE(city, ''),
		       COALESCE(asn, ''), COALESCE(org, '')
		FROM events
		WHERE src_ip = ?
	`, ip).Scan(
		&profile.TotalEvents, &firstSeenStr, &lastSeenStr,
		&profile.CountryCode, &profile.CountryName, &profile.City,
		&profile.ASN, &profile.Org,
	)
	if err != nil {
		return nil, err
	}

	if firstSeenStr.Valid && firstSeenStr.String != "" {
		if t, err := time.Parse(time.RFC3339Nano, firstSeenStr.String); err == nil {
			profile.FirstSeen = t
		} else if t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", firstSeenStr.String); err == nil {
			profile.FirstSeen = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", firstSeenStr.String); err == nil {
			profile.FirstSeen = t
		} else {
			profile.FirstSeen = time.Now()
		}
	}
	if lastSeenStr.Valid && lastSeenStr.String != "" {
		if t, err := time.Parse(time.RFC3339Nano, lastSeenStr.String); err == nil {
			profile.LastSeen = t
		} else if t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", lastSeenStr.String); err == nil {
			profile.LastSeen = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", lastSeenStr.String); err == nil {
			profile.LastSeen = t
		} else {
			profile.LastSeen = time.Now()
		}
	}

	// 2. Credentials attempted
	credRows, err := s.db.Query(`
		SELECT username, COALESCE(password, ''), COUNT(*) as cnt
		FROM credentials
		WHERE src_ip = ?
		GROUP BY username, password
		ORDER BY cnt DESC
		LIMIT 10
	`, ip)
	if err == nil {
		defer credRows.Close()
		for credRows.Next() {
			var c models.CredentialStat
			if err := credRows.Scan(&c.Username, &c.Password, &c.Count); err == nil {
				profile.AttemptedCreds = append(profile.AttemptedCreds, c)
			}
		}
	}

	// 3. Shell commands
	cmdRows, err := s.db.Query(`
		SELECT DISTINCT command
		FROM commands
		WHERE src_ip = ?
		ORDER BY timestamp DESC
		LIMIT 15
	`, ip)
	if err == nil {
		defer cmdRows.Close()
		for cmdRows.Next() {
			var cmd string
			if err := cmdRows.Scan(&cmd); err == nil {
				profile.ExecutedCommands = append(profile.ExecutedCommands, cmd)
			}
		}
	}

	// 4. SSH client banners
	bannerRows, err := s.db.Query(`
		SELECT DISTINCT ssh_version
		FROM events
		WHERE src_ip = ? AND ssh_version IS NOT NULL AND ssh_version != ''
		LIMIT 5
	`, ip)
	if err == nil {
		defer bannerRows.Close()
		for bannerRows.Next() {
			var b string
			if err := bannerRows.Scan(&b); err == nil {
				profile.ClientBanners = append(profile.ClientBanners, b)
			}
		}
	}

	// Calculate threat score
	score := 20
	if profile.TotalEvents > 20 {
		score += 20
	}
	if len(profile.AttemptedCreds) > 3 {
		score += 20
	}
	if len(profile.ExecutedCommands) > 0 {
		score += 30 // Gained shell access
	}
	if score > 100 {
		score = 100
	}
	profile.ThreatScore = score

	var banCount int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM banned_ips WHERE ip = ?`, ip).Scan(&banCount)
	profile.IsBanned = banCount > 0

	return profile, nil
}

// GetBotnetFingerprints aggregates client banners into classified botnet signatures
func (s *Storage) GetBotnetFingerprints(limit int) ([]models.BotnetFingerprint, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `
		SELECT ssh_version, COUNT(*) as cnt, MIN(timestamp), MAX(timestamp)
		FROM events
		WHERE ssh_version IS NOT NULL AND ssh_version != ''
		GROUP BY ssh_version
		ORDER BY cnt DESC
		LIMIT ?
	`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.BotnetFingerprint
	for rows.Next() {
		var fp models.BotnetFingerprint
		var firstStr, lastStr sql.NullString
		if err := rows.Scan(&fp.ClientVersion, &fp.Count, &firstStr, &lastStr); err == nil {
			if firstStr.Valid {
				fp.FirstSeen = parseFlexibleTime(firstStr.String)
			}
			if lastStr.Valid {
				fp.LastSeen = parseFlexibleTime(lastStr.String)
			}

			// Classify botnet signature
			verLower := strings.ToLower(fp.ClientVersion)
			if strings.Contains(verLower, "libssh") {
				fp.BotnetCategory = "Libssh Automated Scanner"
				fp.SignatureType = "Scanner"
			} else if strings.Contains(verLower, "paramiko") {
				fp.BotnetCategory = "Paramiko Python Brute-Forcer"
				fp.SignatureType = "Worm"
			} else if strings.Contains(verLower, "go") {
				fp.BotnetCategory = "Go-Based Mirai/Dropper Variant"
				fp.SignatureType = "Worm"
			} else if strings.Contains(verLower, "putty") {
				fp.BotnetCategory = "PuTTY Manual Intrusion"
				fp.SignatureType = "Interactive"
			} else if strings.Contains(verLower, "masscan") {
				fp.BotnetCategory = "Masscan Port Sweeper"
				fp.SignatureType = "Scanner"
			} else {
				fp.BotnetCategory = "OpenSSH Weaponized Probe"
				fp.SignatureType = "Custom"
			}

			list = append(list, fp)
		}
	}
	return list, nil
}

// GetSessionEvents returns all chronological events for a specific session ID
func (s *Storage) GetSessionEvents(sessionID string) ([]*models.EnrichedEvent, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	query := `
		SELECT id, eventid, timestamp, session, src_ip, src_port, dst_port, protocol,
		       username, password, input, ssh_version, download_url, sha256, file_size,
		       duration, country_code, country_name, city, latitude, longitude, asn, org,
		       severity, description
		FROM events
		WHERE session = ?
		ORDER BY timestamp ASC
	`
	rows, err := s.db.Query(query, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.EnrichedEvent
	for rows.Next() {
		ev := &models.EnrichedEvent{}
		var ts time.Time
		err := rows.Scan(
			&ev.ID, &ev.EventID, &ts, &ev.Session, &ev.SourceIP, &ev.SourcePort, &ev.DestPort, &ev.Protocol,
			&ev.Username, &ev.Password, &ev.Input, &ev.SSHVersion, &ev.DownloadURL, &ev.SHA256, &ev.FileSize,
			&ev.Duration, &ev.Geo.CountryCode, &ev.Geo.CountryName, &ev.Geo.City, &ev.Geo.Latitude, &ev.Geo.Longitude,
			&ev.Geo.ASN, &ev.Geo.Org, &ev.Severity, &ev.Description,
		)
		if err == nil {
			ev.Timestamp = ts
			events = append(events, ev)
		}
	}
	return events, nil
}

// SaveAIAnalysis caches the LLM threat triage result
func (s *Storage) SaveAIAnalysis(sessionID string, res *models.AIAnalysisResult) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	data, err := json.Marshal(res)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(`
		INSERT INTO ai_analyses (session_id, analysis_json, created_at)
		VALUES (?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			analysis_json = excluded.analysis_json,
			created_at = excluded.created_at
	`, sessionID, string(data), time.Now())
	return err
}

// GetAIAnalysis retrieves cached LLM analysis if available
func (s *Storage) GetAIAnalysis(sessionID string) (*models.AIAnalysisResult, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var jsonStr string
	err := s.db.QueryRow(`SELECT analysis_json FROM ai_analyses WHERE session_id = ?`, sessionID).Scan(&jsonStr)
	if err != nil {
		return nil, err
	}

	var res models.AIAnalysisResult
	if err := json.Unmarshal([]byte(jsonStr), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListWebhooks returns all configured alert webhooks
func (s *Storage) ListWebhooks() ([]models.WebhookConfig, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	rows, err := s.db.Query(`SELECT id, name, url, type, alert_login_success, alert_malware, alert_crit_cmd, enabled, created_at FROM webhooks ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.WebhookConfig
	for rows.Next() {
		var w models.WebhookConfig
		var sLogin, sMal, sCmd, sEn int
		if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.Type, &sLogin, &sMal, &sCmd, &sEn, &w.CreatedAt); err == nil {
			w.AlertOnLoginSuccess = sLogin == 1
			w.AlertOnMalware = sMal == 1
			w.AlertOnCriticalCmd = sCmd == 1
			w.Enabled = sEn == 1
			list = append(list, w)
		}
	}
	return list, nil
}

// CreateWebhook saves a new webhook config
func (s *Storage) CreateWebhook(cfg *models.WebhookConfig) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	sLogin := 0
	if cfg.AlertOnLoginSuccess {
		sLogin = 1
	}
	sMal := 0
	if cfg.AlertOnMalware {
		sMal = 1
	}
	sCmd := 0
	if cfg.AlertOnCriticalCmd {
		sCmd = 1
	}
	sEn := 1
	if !cfg.Enabled {
		sEn = 0
	}

	res, err := s.db.Exec(`
		INSERT INTO webhooks (name, url, type, alert_login_success, alert_malware, alert_crit_cmd, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, cfg.Name, cfg.URL, cfg.Type, sLogin, sMal, sCmd, sEn, time.Now())
	if err != nil {
		return err
	}
	cfg.ID, _ = res.LastInsertId()
	return nil
}

// DeleteWebhook removes a webhook
func (s *Storage) DeleteWebhook(id int64) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	_, err := s.db.Exec(`DELETE FROM webhooks WHERE id = ?`, id)
	return err
}

// GetActiveWebhooks returns webhooks currently enabled
func (s *Storage) GetActiveWebhooks() ([]models.WebhookConfig, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	rows, err := s.db.Query(`SELECT id, name, url, type, alert_login_success, alert_malware, alert_crit_cmd, enabled, created_at FROM webhooks WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.WebhookConfig
	for rows.Next() {
		var w models.WebhookConfig
		var sLogin, sMal, sCmd, sEn int
		if err := rows.Scan(&w.ID, &w.Name, &w.URL, &w.Type, &sLogin, &sMal, &sCmd, &sEn, &w.CreatedAt); err == nil {
			w.AlertOnLoginSuccess = sLogin == 1
			w.AlertOnMalware = sMal == 1
			w.AlertOnCriticalCmd = sCmd == 1
			w.Enabled = true
			list = append(list, w)
		}
	}
	return list, nil
}

// LogWebhookAlert records an alert dispatch event
func (s *Storage) LogWebhookAlert(l *models.WebhookLog) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	successInt := 0
	if l.Success {
		successInt = 1
	}

	_, err := s.db.Exec(`
		INSERT INTO webhook_logs (timestamp, webhook_id, webhook_name, event_type, status_code, success, message)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, time.Now(), l.WebhookID, l.WebhookName, l.EventType, l.StatusCode, successInt, l.Message)
	return err
}

// ListWebhookLogs returns recent alert dispatch logs
func (s *Storage) ListWebhookLogs(limit int) ([]models.WebhookLog, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	rows, err := s.db.Query(`SELECT id, timestamp, webhook_id, webhook_name, event_type, status_code, success, message FROM webhook_logs ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.WebhookLog
	for rows.Next() {
		var l models.WebhookLog
		var sInt int
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.WebhookID, &l.WebhookName, &l.EventType, &l.StatusCode, &sInt, &l.Message); err == nil {
			l.Success = sInt == 1
			list = append(list, l)
		}
	}
	return list, nil
}

func parseFlexibleTime(s string) time.Time {
	if s == "" {
		return time.Now()
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t
		}
	}
	return time.Now()
}



// BanIP adds an IP to the active blocklist
func (s *Storage) BanIP(ip string, reason string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO banned_ips (ip, reason, banned_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(ip) DO UPDATE SET reason = excluded.reason, banned_at = CURRENT_TIMESTAMP
	`, ip, reason)
	return err
}

// IsIPBanned checks if an IP is on the blocklist
func (s *Storage) IsIPBanned(ip string) (bool, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM banned_ips WHERE ip = ?`, ip).Scan(&count)
	return count > 0, err
}
