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

	// Ensure indexes for Cosmos DB sorting
	indexCtx, cancelIndex := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelIndex()
	_, err = database.Collection("logs").Indexes().CreateOne(indexCtx, mongo.IndexModel{
		Keys: bson.D{{"timestamp", -1}},
	})
	if err != nil {
		fmt.Printf("Warning: Failed to create index on timestamp: %v\n", err)
	}


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

	opts := options.Find().SetLimit(int64(limit))
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
	success, _ := s.db.Collection("logs").CountDocuments(ctx, bson.M{"eventid": "cowrie.login.success"})
	cmds, _ := s.db.Collection("logs").CountDocuments(ctx, bson.M{"eventid": "cowrie.command.input"})
	files, _ := s.db.Collection("logs").CountDocuments(ctx, bson.M{"eventid": "cowrie.session.file_download"})
	
	uniqueIPs, _ := s.db.Collection("logs").Distinct(ctx, "src_ip", bson.M{})
	uniqueASNs, _ := s.db.Collection("logs").Distinct(ctx, "geo.asn", bson.M{})
	
	compRatio := 0.0
	if (success + failed) > 0 {
		compRatio = (float64(success) / float64(success + failed)) * 100.0
	}
	
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"duration": bson.M{"$gt": 0}}}},
		{{Key: "$group", Value: bson.M{"_id": nil, "avgDuration": bson.M{"$avg": "$duration"}}}},
	}
	cursor, _ := s.db.Collection("logs").Aggregate(ctx, pipeline)
	avgDuration := 0.0
	if cursor != nil && cursor.Next(ctx) {
		var res struct {
			AvgDuration float64 `bson:"avgDuration"`
		}
		cursor.Decode(&res)
		avgDuration = res.AvgDuration
		cursor.Close(ctx)
	}

	return &models.OverviewStats{
		TotalEvents: total,
		FailedLogins: failed,
		SuccessfulLogins: success,
		CommandsExecuted: cmds,
		FilesCaptured: files,
		UniqueAttackers: int64(len(uniqueIPs)),
		UniqueASNs: int64(len(uniqueASNs)),
		CompromiseRatio: compRatio,
		AvgSessionDuration: avgDuration,
	}, nil
}

func (s *Storage) GetTimeline(limit int) ([]models.TimelinePoint, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$group", Value: bson.M{
			"_id": bson.M{"$dateToString": bson.M{"format": "%Y-%m-%d", "date": "$timestamp"}},
			"total": bson.M{"$sum": 1},
			"ssh": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$protocol", "ssh"}}, 1, 0}}},
			"telnet": bson.M{"$sum": bson.M{"$cond": []interface{}{bson.M{"$eq": []interface{}{"$protocol", "telnet"}}, 1, 0}}},
		}}},
		{{Key: "$sort", Value: bson.M{"_id": -1}}},
		{{Key: "$limit", Value: limit}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []models.TimelinePoint
	for cursor.Next(ctx) {
		var res struct {
			ID     string `bson:"_id"`
			Total  int64  `bson:"total"`
			SSH    int64  `bson:"ssh"`
			Telnet int64  `bson:"telnet"`
		}
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		results = append(results, models.TimelinePoint{
			TimeBucket: res.ID,
			Total:      res.Total,
			SSH:        res.SSH,
			Telnet:     res.Telnet,
		})
	}
	return results, nil
}

func (s *Storage) GetTopCountries(limit int) ([]models.CountryAttackStat, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$group", Value: bson.M{
			"_id": "$geo.country_code",
			"country_name": bson.M{"$first": "$geo.country_name"},
			"latitude": bson.M{"$first": "$geo.latitude"},
			"longitude": bson.M{"$first": "$geo.longitude"},
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$sort", Value: bson.M{"count": -1}}},
		{{Key: "$limit", Value: limit}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []models.CountryAttackStat
	for cursor.Next(ctx) {
		var res struct {
			ID          string  `bson:"_id"`
			CountryName string  `bson:"country_name"`
			Count       int64   `bson:"count"`
			Lat         float64 `bson:"latitude"`
			Lon         float64 `bson:"longitude"`
		}
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		if res.ID != "" {
			results = append(results, models.CountryAttackStat{
				CountryCode: res.ID,
				CountryName: res.CountryName,
				Count:       res.Count,
				Latitude:    res.Lat,
				Longitude:   res.Lon,
			})
		}
	}
	return results, nil
}

func (s *Storage) GetTopCredentials(limit int) ([]models.CredentialStat, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"eventid": bson.M{"$in": []string{"cowrie.login.failed", "cowrie.login.success"}}}}},
		{{Key: "$group", Value: bson.M{
			"_id": bson.M{"username": "$username", "password": "$password"},
			"count": bson.M{"$sum": 1},
			"last_seen": bson.M{"$max": "$timestamp"},
		}}},
		{{Key: "$sort", Value: bson.M{"count": -1}}},
		{{Key: "$limit", Value: limit}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []models.CredentialStat
	for cursor.Next(ctx) {
		var res struct {
			ID struct {
				Username string `bson:"username"`
				Password string `bson:"password"`
			} `bson:"_id"`
			Count    int64     `bson:"count"`
			LastSeen time.Time `bson:"last_seen"`
		}
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		results = append(results, models.CredentialStat{
			Username: res.ID.Username,
			Password: res.ID.Password,
			Count:    res.Count,
			LastSeen: res.LastSeen,
		})
	}
	return results, nil
}

func (s *Storage) GetTopCommands(limit int) ([]models.CommandStat, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"eventid": "cowrie.command.input"}}},
		{{Key: "$group", Value: bson.M{
			"_id": "$input",
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$sort", Value: bson.M{"count": -1}}},
		{{Key: "$limit", Value: limit}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []models.CommandStat
	for cursor.Next(ctx) {
		var res struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		results = append(results, models.CommandStat{
			Command: res.ID,
			Count:   res.Count,
		})
	}
	return results, nil
}

func (s *Storage) GetSessions(limit int) ([]SessionRecord, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$group", Value: bson.M{
			"_id": "$session",
			"src_ip": bson.M{"$first": "$src_ip"},
			"start_time": bson.M{"$min": "$timestamp"},
			"end_time": bson.M{"$max": "$timestamp"},
			"event_count": bson.M{"$sum": 1},
		}}},
		{{Key: "$sort", Value: bson.M{"start_time": -1}}},
		{{Key: "$limit", Value: limit}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var sessions []SessionRecord
	for cursor.Next(ctx) {
		var res struct {
			SessionID  string    `bson:"_id"`
			SourceIP   string    `bson:"src_ip"`
			StartTime  time.Time `bson:"start_time"`
			EndTime    time.Time `bson:"end_time"`
			EventCount int       `bson:"event_count"`
		}
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		duration := res.EndTime.Sub(res.StartTime).Seconds()
		sessions = append(sessions, SessionRecord{
			SessionID:  res.SessionID,
			SourceIP:   res.SourceIP,
			StartTime:  res.StartTime,
			EndTime:    res.EndTime,
			Duration:   duration,
			EventCount: res.EventCount,
		})
	}
	return sessions, nil
}

func (s *Storage) GetSessionCommands(sessionID string) ([]models.CommandStat, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"session": sessionID, "eventid": "cowrie.command.input"}}},
		{{Key: "$group", Value: bson.M{
			"_id": "$input",
			"count": bson.M{"$sum": 1},
		}}},
		{{Key: "$sort", Value: bson.M{"count": -1}}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []models.CommandStat
	for cursor.Next(ctx) {
		var res struct {
			ID    string `bson:"_id"`
			Count int64  `bson:"count"`
		}
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		results = append(results, models.CommandStat{
			Command: res.ID,
			Count:   res.Count,
		})
	}
	return results, nil
}

func (s *Storage) GetMalwareFiles(limit int) ([]MalwareRecord, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"eventid": "cowrie.session.file_download"}}},
		{{Key: "$sort", Value: bson.M{"timestamp": -1}}},
		{{Key: "$limit", Value: limit}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []MalwareRecord
	for cursor.Next(ctx) {
		var ev models.EnrichedEvent
		if err := cursor.Decode(&ev); err != nil {
			return nil, err
		}
		results = append(results, MalwareRecord{
			SHA256:    ev.SHA256,
			URL:       ev.DownloadURL,
			Size:      ev.FileSize,
			Timestamp: ev.Timestamp,
			SessionID: ev.Session,
			SourceIP:  ev.SourceIP,
		})
	}
	return results, nil
}

func (s *Storage) GetIPThreatProfile(ip string) (*IPThreatProfile, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"src_ip": ip}}},
		{{Key: "$group", Value: bson.M{
			"_id": "$src_ip",
			"country_code": bson.M{"$first": "$geo.country_code"},
			"city": bson.M{"$first": "$geo.city"},
			"asn": bson.M{"$first": "$geo.asn"},
			"total_events": bson.M{"$sum": 1},
			"first_seen": bson.M{"$min": "$timestamp"},
			"last_seen": bson.M{"$max": "$timestamp"},
		}}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	if cursor.Next(ctx) {
		var res IPThreatProfile
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		res.IP = ip
		return &res, nil
	}
	return &IPThreatProfile{IP: ip}, nil
}

func (s *Storage) GetBotnetFingerprints(limit int) ([]models.BotnetFingerprint, error) {
	ctx := context.Background()
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{"sshversion": bson.M{"$ne": ""}}}},
		{{Key: "$group", Value: bson.M{
			"_id": "$sshversion",
			"count": bson.M{"$sum": 1},
			"first_seen": bson.M{"$min": "$timestamp"},
			"last_seen": bson.M{"$max": "$timestamp"},
		}}},
		{{Key: "$sort", Value: bson.M{"count": -1}}},
		{{Key: "$limit", Value: limit}},
	}
	cursor, err := s.db.Collection("logs").Aggregate(ctx, pipeline)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var results []models.BotnetFingerprint
	for cursor.Next(ctx) {
		var res struct {
			ID        string    `bson:"_id"`
			Count     int64     `bson:"count"`
			FirstSeen time.Time `bson:"first_seen"`
			LastSeen  time.Time `bson:"last_seen"`
		}
		if err := cursor.Decode(&res); err != nil {
			return nil, err
		}
		results = append(results, models.BotnetFingerprint{
			ClientVersion:  res.ID,
			BotnetCategory: "Unknown",
			SignatureType:  "Unknown",
			Count:          res.Count,
			FirstSeen:      res.FirstSeen,
			LastSeen:       res.LastSeen,
		})
	}
	return results, nil
}

func (s *Storage) GetSessionEvents(sessionID string) ([]*models.EnrichedEvent, error) {
	ctx := context.Background()
	opts := options.Find()
	cursor, err := s.db.Collection("logs").Find(ctx, bson.M{"session": sessionID}, opts)
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
