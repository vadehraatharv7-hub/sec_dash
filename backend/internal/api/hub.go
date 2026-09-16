package api

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"sec_dash/backend/internal/models"
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
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan *models.EnrichedEvent, 1000),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
	}
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

// BroadcastEvent enqueues an event for distribution to all connected dashboard tabs
func (h *Hub) BroadcastEvent(event *models.EnrichedEvent) {
	select {
	case h.broadcast <- event:
	default:
		// Drop if buffer full to avoid blocking ingestion pipeline
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
