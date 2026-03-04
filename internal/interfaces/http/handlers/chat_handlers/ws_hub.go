package chat_handlers

import (
	"context"
	"encoding/json"
	"sync"
)

// Envelope Communication transport unit for ws pipe
type Envelope struct {
	ID      string `json:"id"`
	Event   string `json:"event"`
	Payload any    `json:"payload"`
}

// Hub logic (Moved into methods for clarity)
type Hub struct {
	Clients     map[string]*Client
	mu          sync.RWMutex
	JobQueue    chan *Envelope
	ChatService ChatService //// TODO: Need to implement
}

func NewHub(ctx context.Context, chatService ChatService) *Hub {
	return &Hub{Clients: make(map[string]*Client), JobQueue: make(chan *Envelope, 1024), ChatService: chatService}
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

func (h *Hub) Serve(userID string, client *Client) {
	h.Register(userID, client)
	defer h.Unregister(userID) // closes connection itself and removes from the hub

	// setting up write pipeline

	go client.writePump()

	// Keep-alive loop & Message Listener

	// blocking operation, but if we return from function ,
	// we will close the underlying tcp connection,
	// that will return an error in HandleMessage metod of client
websocket_serving_loop:
	for {
		var msg Envelope
		// This keeps the connection open and handles Koyeb timeouts
		err := client.conn.ReadJSON(&msg)
		if err != nil {
			break websocket_serving_loop
		}
		select {
		case h.JobQueue <- &msg:
			//Message sent to JobQueue
			ackMessage, _ := json.Marshal(Envelope{
				ID:      msg.ID,
				Event:   "envelope_status",
				Payload: "accepted",
			})
			client.sendChannel <- ackMessage
			////// !!!!!!!!!!!!!!!!! architectural trade-off !!!!!!!!!!!!!!!!!!!!!!!
			////      When to send the ack about the envelope ? When added to job queue or when the message successfully processed[*]
		default:
			// Immediate FAILURE ACK because the system is busy
			resp := Envelope{
				ID:    msg.ID, // Mirroring the ID back
				Event: "error",
				Payload: map[string]string{
					"code":    "SERVER_BUSY",
					"message": "Please try again in a few seconds",
				},
			}
			errMessage, _ := json.Marshal(resp)
			client.sendChannel <- errMessage
		}
	}
}
