package store

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"sec_dash/backend/internal/ingest"
	"sec_dash/backend/internal/model"
)

// Mongo persists to MongoDB / Azure Cosmos DB (Mongo API).
type Mongo struct {
	client *mongo.Client
	db     *mongo.Database
}

func NewMongo(uri string) (*Mongo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("mongo connect: %w", err)
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, fmt.Errorf("mongo ping: %w", err)
	}
	m := &Mongo{client: client, db: client.Database("honeypot_db")}
	_, _ = m.db.Collection("logs").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "timestamp", Value: -1}}},
		{Keys: bson.D{{Key: "src_ip", Value: 1}}},
	})
	return m, nil
}

func (m *Mongo) Close() error { return m.client.Disconnect(context.Background()) }

// retry runs fn with backoff; Cosmos DB answers 429 (code 16500) when request units run out.
func retry(attempts int, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		time.Sleep(time.Duration(i+1) * 1500 * time.Millisecond)
	}
	return err
}

func (m *Mongo) Insert(evs []*model.Event) error {
	docs := make([]interface{}, len(evs))
	for i, e := range evs {
		docs[i] = ingest.ToStored(e)
	}
	return retry(4, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, err := m.db.Collection("logs").InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
		return err
	})
}

// Load reads the newest `limit` events in time-ordered pages so a throttled
// request only costs one retried page, not the whole load.
func (m *Mongo) Load(limit int) ([]*model.Event, error) {
	const page = 2000
	var out []*model.Event
	var before time.Time
	for len(out) < limit {
		n := page
		if limit-len(out) < n {
			n = limit - len(out)
		}
		filter := bson.M{}
		if !before.IsZero() {
			filter["timestamp"] = bson.M{"$lt": before}
		}
		var batch []*model.Event
		var oldest time.Time
		err := retry(5, func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cur, err := m.db.Collection("logs").Find(ctx, filter,
				options.Find().SetSort(bson.M{"timestamp": -1}).SetLimit(int64(n)))
			if err != nil {
				return err
			}
			defer cur.Close(ctx)
			batch, oldest = batch[:0], time.Time{}
			for cur.Next(ctx) {
				var s model.Stored
				if err := cur.Decode(&s); err != nil || s.EventID == "" {
					continue
				}
				batch = append(batch, ingest.FromStored(&s))
				if oldest.IsZero() || s.Time.Before(oldest) {
					oldest = s.Time
				}
			}
			return cur.Err()
		})
		if err != nil {
			return out, err
		}
		out = append(out, batch...)
		if len(batch) < n || oldest.IsZero() || oldest.Equal(before) {
			break
		}
		before = oldest
	}
	return out, nil
}

func (m *Mongo) UpdateGeo(ip string, g model.Geo) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := m.db.Collection("logs").UpdateMany(ctx, bson.M{"src_ip": ip}, bson.M{"$set": bson.M{"geo": g}})
	return err
}

func (m *Mongo) PutDoc(coll, key string, doc map[string]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	doc["_id"] = key
	_, err := m.db.Collection(coll).ReplaceOne(ctx, bson.M{"_id": key}, doc, options.Replace().SetUpsert(true))
	return err
}

func (m *Mongo) DelDoc(coll, key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := m.db.Collection(coll).DeleteMany(ctx, bson.M{"$or": bson.A{bson.M{"_id": key}, bson.M{"ip": key}}})
	return err
}

func (m *Mongo) ListDocs(coll string) ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cur, err := m.db.Collection(coll).Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var out []map[string]interface{}
	for cur.Next(ctx) {
		var d map[string]interface{}
		if err := cur.Decode(&d); err == nil {
			for k, v := range d {
				if dt, ok := v.(primitive.DateTime); ok {
					d[k] = dt.Time().UTC().Format(time.RFC3339)
				}
			}
			out = append(out, d)
		}
	}
	return out, cur.Err()
}
