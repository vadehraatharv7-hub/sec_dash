package api

import (
	"context"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"sec_dash/backend/internal/models"
	"sec_dash/backend/internal/broker"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for the security dashboard
	},
}

// Hub maintains the set of active dashboard WebSocket clients and broadcasts events
type Hub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan *models.EnrichedEvent
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	lock       sync.Mutex
	broker     *broker.RedisBroker
}

func NewHub(b *broker.RedisBroker) *Hub {
	h := &Hub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan *models.EnrichedEvent, 1000),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		broker:     b,
	}

	// Subscribe to Redis events
	if b != nil {
		go b.SubscribeEvents(context.Background(), func(ev *models.EnrichedEvent) {
			// Forward Redis pub/sub event to the local broadcast channel
			select {
			case h.broadcast <- ev:
			default:
			}
		})
	}

	return h
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.lock.Lock()
			h.clients[client] = true
			h.lock.Unlock()
			log.Printf("[WS] Client connected. Total active clients: %d", len(h.clients))

		case client := <-h.unregister:
			h.lock.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
			}
			h.lock.Unlock()
			log.Printf("[WS] Client disconnected. Total active clients: %d", len(h.clients))

		case event := <-h.broadcast:
			h.lock.Lock()
			for client := range h.clients {
				err := client.WriteJSON(event)
				if err != nil {
					log.Printf("[WS] Write error: %v", err)
					client.Close()
					delete(h.clients, client)
				}
			}
			h.lock.Unlock()
		}
	}
}

// BroadcastEvent publishes an event to Redis (which then comes back via SubscribeEvents)
func (h *Hub) BroadcastEvent(event *models.EnrichedEvent) {
	if h.broker != nil {
		// Publish to Redis so all scaled backends get it
		_ = h.broker.PublishEvent(context.Background(), event)
	} else {
		// Fallback to local channel if no broker
		select {
		case h.broadcast <- event:
		default:
		}
	}
}

// HandleWebSocket upgrades incoming HTTP connections to WebSocket
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Upgrade error: %v", err)
		return
	}

	h.register <- conn

	// Send initial greeting
	_ = conn.WriteJSON(map[string]interface{}{
		"type":    "welcome",
		"message": "Connected to Cowrie Honeypot Realtime Stream",
	})

	// Keep-alive loop
	go func() {
		defer func() {
			h.unregister <- conn
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}
