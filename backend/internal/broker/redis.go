package broker

import (
	"context"
	"encoding/json"
	"log"

	"github.com/redis/go-redis/v9"
	"sec_dash/backend/internal/models"
)

const (
	EventChannel = "secdash_events"
	BanChannel   = "secdash_bans"
)

type RedisBroker struct {
	client *redis.Client
}

func NewRedisBroker(addr string) *RedisBroker {
	if addr == "" {
		addr = "localhost:6379"
	}
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	// Test connection
	if err := client.Ping(context.Background()).Err(); err != nil {
		log.Printf("[Redis] Warning: Failed to connect to Redis at %s: %v", addr, err)
	} else {
		log.Printf("[Redis] Connected successfully to %s", addr)
	}

	return &RedisBroker{
		client: client,
	}
}

// PublishEvent broadcasts a new enriched event to all connected backend nodes
func (b *RedisBroker) PublishEvent(ctx context.Context, ev *models.EnrichedEvent) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return b.client.Publish(ctx, EventChannel, data).Err()
}

// SubscribeEvents listens for events published by any backend node
func (b *RedisBroker) SubscribeEvents(ctx context.Context, onEvent func(*models.EnrichedEvent)) {
	sub := b.client.Subscribe(ctx, EventChannel)
	defer sub.Close()

	ch := sub.Channel()
	log.Printf("[Redis] Subscribed to %s", EventChannel)

	for msg := range ch {
		var ev models.EnrichedEvent
		if err := json.Unmarshal([]byte(msg.Payload), &ev); err == nil {
			onEvent(&ev)
		}
	}
}

// PublishBan broadcasts a ban command to all honeypot sensors
func (b *RedisBroker) PublishBan(ctx context.Context, ip string, duration int) error {
	payload := map[string]interface{}{
		"action":   "ban",
		"ip":       ip,
		"duration": duration, // seconds
	}
	data, _ := json.Marshal(payload)
	return b.client.Publish(ctx, BanChannel, data).Err()
}
