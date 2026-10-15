package server

import (
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"sec_dash/backend/internal/model"
)

var upgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// handleWS streams every new event to the browser as it is ingested.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ch := s.st.Subscribe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	defer func() {
		s.st.Unsubscribe(ch)
		conn.Close()
	}()
	_ = conn.WriteJSON(map[string]interface{}{"type": "hello", "ts": time.Now().UTC()})
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(map[string]interface{}{"type": "event", "event": viewOf(e)}); err != nil {
				return
			}
		case <-ping.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}

var _ = model.KindOther
