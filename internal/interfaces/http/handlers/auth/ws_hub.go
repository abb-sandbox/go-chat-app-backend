package handlers

import (
	"sync"
)

// Hub logic (Moved into methods for clarity)
type Hub struct {
	Clients map[string]*Client
	mu      sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{Clients: make(map[string]*Client)}
}

func (h *Hub) Register(id string, client *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Clients[id] = client
}

func (h *Hub) Unregister(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if client, ok := h.Clients[id]; ok {
		_ = client.conn.Close()
		close(client.sendChannel)
		delete(h.Clients, id)
	}
}
func (h *Hub) SendToUser(userID string, message []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if client, ok := h.Clients[userID]; ok {
		// Use a non-blocking send or a goroutine to prevent
		// one slow client from freezing the whole Hub
		select {
		case client.sendChannel <- message:
		default:
			// Channel full, handle accordingly (e.g., drop message or log)
		}
	}
}
