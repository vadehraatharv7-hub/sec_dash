package db

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"sec_dash/backend/internal/models"
)

type Storage struct {
	client *mongo.Client
	db     *mongo.Database
}

func NewStorage(mongoURI string) (*Storage, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(mongoURI)
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mongodb: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("failed to ping mongodb: %w", err)
	}

	database := client.Database("honeypot_db")

	return &Storage{
		client: client,
		db:     database,
	}, nil
}

func (s *Storage) Close() error {
	return s.client.Disconnect(context.Background())
}

// InsertEventsBatch inserts a batch of events (mostly for testing or manual ingest)
func (s *Storage) InsertEventsBatch(events []*models.EnrichedEvent) error {
	if len(events) == 0 {
		return nil
	}
	var docs []interface{}
	for _, ev := range events {
		docs = append(docs, ev)
	}
	_, err := s.db.Collection("logs").InsertMany(context.Background(), docs)
	return err
}

func (s *Storage) GetRecentEvents(limit int, eventFilter, ipFilter string) ([]*models.EnrichedEvent, error) {
	ctx := context.Background()
	filter := bson.M{}
	if eventFilter != "" {
		filter["eventid"] = eventFilter
	}
	if ipFilter != "" {
		filter["src_ip"] = ipFilter
	}

	opts := options.Find().SetSort(bson.D{{"timestamp", -1}}).SetLimit(int64(limit))
	cursor, err := s.db.Collection("logs").Find(ctx, filter, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var events []*models.EnrichedEvent
	if err = cursor.All(ctx, &events); err != nil {
		return nil, err
	}
	return events, nil
}

// The following types must be defined to match the original SQLite db package
type SessionRecord struct {
	SessionID  string    `json:"session_id"`
	SourceIP   string    `json:"src_ip"`
	StartTime  time.Time `json:"start_time"`
	EndTime    time.Time `json:"end_time"`
	Duration   float64   `json:"duration"`
	EventCount int       `json:"event_count"`
}

type MalwareRecord struct {
	SHA256    string    `json:"sha256"`
	URL       string    `json:"url"`
	Size      int64     `json:"size"`
	Timestamp time.Time `json:"timestamp"`
	SessionID string    `json:"session_id"`
	SourceIP  string    `json:"src_ip"`
}

type IPThreatProfile struct {
	IP          string    `json:"ip"`
	CountryCode string    `json:"country_code"`
	City        string    `json:"city"`
	ASN         string    `json:"asn"`
	TotalEvents int64     `json:"total_events"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
}

// Stubs for the rest of the read-heavy analytics methods
// In a full implementation, these would use MongoDB Aggregation Pipelines

func (s *Storage) GetOverviewStats() (*models.OverviewStats, error) {
	ctx := context.Background()
	total, _ := s.db.Collection("logs").CountDocuments(ctx, bson.M{})
	failed, _ := s.db.Collection("logs").CountDocuments(ctx, bson.M{"eventid": "cowrie.login.failed"})
	return &models.OverviewStats{
		TotalEvents: total,
		FailedLogins: failed,
	}, nil
}

func (s *Storage) GetTimeline(limit int) ([]models.TimelinePoint, error) {
	return []models.TimelinePoint{}, nil
}

func (s *Storage) GetTopCountries(limit int) ([]models.CountryAttackStat, error) {
	return []models.CountryAttackStat{}, nil
}

func (s *Storage) GetTopCredentials(limit int) ([]models.CredentialStat, error) {
	return []models.CredentialStat{}, nil
}

func (s *Storage) GetTopCommands(limit int) ([]models.CommandStat, error) {
	return []models.CommandStat{}, nil
}

func (s *Storage) GetSessions(limit int) ([]SessionRecord, error) {
	ctx := context.Background()
	opts := options.Find().SetLimit(int64(limit))
	cursor, err := s.db.Collection("logs").Find(ctx, bson.M{"eventid": bson.M{"$in": []string{"cowrie.session.connect", "cowrie.session.closed"}}}, opts)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)
	var events []*models.EnrichedEvent
	if err = cursor.All(ctx, &events); err != nil {
		return nil, err
	}
	var sessions []SessionRecord
	for _, ev := range events {
		sessions = append(sessions, SessionRecord{
			SessionID: ev.Session,
			SourceIP:  ev.SourceIP,
			StartTime: ev.Timestamp,
			Duration:  ev.Duration,
		})
	}
	return sessions, nil
}

func (s *Storage) GetSessionCommands(sessionID string) ([]models.CommandStat, error) {
	return []models.CommandStat{}, nil
}

func (s *Storage) GetMalwareFiles(limit int) ([]MalwareRecord, error) {
	return []MalwareRecord{}, nil
}

func (s *Storage) GetIPThreatProfile(ip string) (*IPThreatProfile, error) {
	return &IPThreatProfile{IP: ip}, nil
}

func (s *Storage) GetBotnetFingerprints(limit int) ([]models.BotnetFingerprint, error) {
	return []models.BotnetFingerprint{}, nil
}

func (s *Storage) GetSessionEvents(sessionID string) ([]*models.EnrichedEvent, error) {
	return []*models.EnrichedEvent{}, nil
}

func (s *Storage) SaveAIAnalysis(sessionID string, res *models.AIAnalysisResult) error {
	ctx := context.Background()
	_, err := s.db.Collection("ai_analyses").UpdateOne(
		ctx,
		bson.M{"session_id": sessionID},
		bson.M{"$set": res},
		options.Update().SetUpsert(true),
	)
	return err
}

func (s *Storage) GetAIAnalysis(sessionID string) (*models.AIAnalysisResult, error) {
	ctx := context.Background()
	var res models.AIAnalysisResult
	err := s.db.Collection("ai_analyses").FindOne(ctx, bson.M{"session_id": sessionID}).Decode(&res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (s *Storage) ListWebhooks() ([]models.WebhookConfig, error) {
	return []models.WebhookConfig{}, nil
}

func (s *Storage) CreateWebhook(cfg *models.WebhookConfig) error {
	return nil
}

func (s *Storage) DeleteWebhook(id int64) error {
	return nil
}

func (s *Storage) GetActiveWebhooks() ([]models.WebhookConfig, error) {
	return []models.WebhookConfig{}, nil
}

func (s *Storage) LogWebhookAlert(l *models.WebhookLog) error {
	return nil
}

func (s *Storage) ListWebhookLogs(limit int) ([]models.WebhookLog, error) {
	return []models.WebhookLog{}, nil
}

func (s *Storage) BanIP(ip string, reason string) error {
	ctx := context.Background()
	_, err := s.db.Collection("banned_ips").UpdateOne(
		ctx,
		bson.M{"ip": ip},
		bson.M{"$set": bson.M{"reason": reason, "banned_at": time.Now()}},
		options.Update().SetUpsert(true),
	)
	return err
}

func (s *Storage) IsIPBanned(ip string) (bool, error) {
	ctx := context.Background()
	count, err := s.db.Collection("banned_ips").CountDocuments(ctx, bson.M{"ip": ip})
	return count > 0, err
}
