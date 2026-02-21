package handlers

// import (
// 	"encoding/json"
// 	"net/http"
// 	"sync"

// 	"github.com/gin-gonic/gin"
// 	"github.com/gorilla/websocket"
// )

// type WSHandler struct {
// 	websocket.Upgrader
// }

// var upgrader = websocket.Upgrader{
// 	ReadBufferSize:  1024,
// 	WriteBufferSize: 1024,
// 	// Important for Koyeb/Production: Check the origin!
// 	CheckOrigin: func(r *http.Request) bool {
// 		return true
// 	},
// }

// type Envelope struct {
// 	Type    string          `json:"type"`    // e.g., "message_send"
// 	Payload json.RawMessage `json:"payload"` // Delayed decoding
// }

// // RegisterPublicRoutes registers routes that are publicly accessible (no auth required)
// func (h *WSHandler) RegisterWSRoutes(r *gin.RouterGroup) {
// 	ws := r.Group("/ws")
// 	ws.GET("/", h.handleWebSocket())
// }

// func (h WSHandler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
// 	conn, err := upgrader.Upgrade(w, r, nil)
// 	if err != nil {
// 		return
// 	}
// 	defer conn.Close()

// 	for {
// 		// Read message from browser
// 		var msg Envelope
// 		err := conn.ReadJSON(&msg)
// 		if err != nil {
// 			break
// 		}

// 		// Handle by Type
// 		switch msg.Type {
// 		case "ms":
// 			// Logic for sending a message
// 			conn.WriteJSON(Envelope{Type: "ms_st", Payload: []byte("delivered")})
// 		case "ping":
// 			conn.WriteJSON(Envelope{Type: "pong"})
// 		}
// 	}
// }

// type Hub struct {
// 	// Map of UserID -> WebSocket Connection
// 	Clients map[string]*websocket.Conn
// 	mu      sync.RWMutex
// }

// func NewHub() *Hub {
// 	return &Hub{
// 		Clients: make(map[string]*websocket.Conn),
// 	}
// }

// // 1. Add Connection
// func (h *Hub) Register(userID string, conn *websocket.Conn) {
// 	h.mu.Lock()
// 	defer h.mu.Unlock()
// 	h.Clients[userID] = conn
// }

// // 2. Remove Connection (Clean up)
// func (h *Hub) Unregister(userID string) {
// 	h.mu.Lock()
// 	defer h.mu.Unlock()
// 	if conn, ok := h.Clients[userID]; ok {
// 		conn.Close()
// 		delete(h.Clients, userID)
// 	}
// }

// // 3. Send Message (Basic Logic)
// func (h *Hub) SendToUser(receiverID string, msg interface{}) bool {
// 	h.mu.RLock()
// 	defer h.mu.RUnlock()

// 	if conn, ok := h.Clients[receiverID]; ok {
// 		err := conn.WriteJSON(msg)
// 		return err == nil
// 	}
// 	return false
// }
