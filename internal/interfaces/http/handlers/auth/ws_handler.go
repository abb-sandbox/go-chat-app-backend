package handlers

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// Request Models for Swagger
type SendMessageRequest struct {
	ReceiverID string `json:"receiver_id" example:"user_123"`
	Message    string `json:"message" example:"Hello from the backend!"`
}

type ActiveUsersResponse struct {
	ActiveUsers []string `json:"active_users" example:"user_1,user_2"`
}

type WSHandler struct {
	Hub      *Hub
	Upgrader websocket.Upgrader
}

func NewWSHandler() *WSHandler {
	return &WSHandler{
		Hub: NewHub(),
		Upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Adjust for production
			},
		},
	}
}

func (h *WSHandler) RegisterWSRoutes(rg *gin.RouterGroup, authMiddleware gin.HandlerFunc) {
	users := rg.Group("/users")
	users.Use(authMiddleware)
	{
		users.GET("/active", h.GetActiveUsers)
		users.POST("/send", h.TriggerSendMessage)
	}

	// WebSocket Upgrade endpoint
	rg.GET("/ws", authMiddleware, h.HandleWebSocket)
}

// HandleWebSocket godoc !!!!!!!!!!!!!!!!!! DO NOT TRUST OR USE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// @Summary      Upgrade to WebSocket
// @Description  Initiates a WebSocket connection. Requires user_id in query.
// @Tags         websocket
// @Param        user_id query string true "User ID"
// @Success      101 {string} string "Switching Protocols"
// @Router       /ws [get]
func (h *WSHandler) HandleWebSocket(c *gin.Context) {
	userID := c.Query("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	conn, err := h.Upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	h.Hub.Register(userID, conn)
	defer h.Hub.Unregister(userID)

	// Keep-alive loop & Message Listener
	for {
		// This keeps the connection open and handles Koyeb timeouts
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// GetActiveUsers godoc  !!!!!!!!!!!!!!!!!! DO NOT TRUST OR USE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// @Summary      List active users
// @Description  Returns an array of all currently connected User IDs.
// @Tags         users
// @Produce      json
// @Success      200 {object} ActiveUsersResponse
// @Router       /users/active [get]
func (h *WSHandler) GetActiveUsers(c *gin.Context) {
	h.Hub.mu.RLock()
	ids := make([]string, 0, len(h.Hub.Clients))
	for id := range h.Hub.Clients {
		ids = append(ids, id)
	}
	h.Hub.mu.RUnlock()

	c.JSON(http.StatusOK, ActiveUsersResponse{ActiveUsers: ids})
}

// TriggerSendMessage godoc !!!!!!!!!!!!!!!!!! DO NOT TRUST OR USE !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// @Summary      Send a message via WS
// @Description  Sends a push message to a specific user if they are connected via WebSocket.
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        request body SendMessageRequest true "Message Details"
// @Success      200 {object} map[string]bool "sent: true"
// @Router       /users/send [post]
func (h *WSHandler) TriggerSendMessage(c *gin.Context) {
	var req SendMessageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	success := h.Hub.SendToUser(req.ReceiverID, gin.H{
		"type":    "ms",
		"content": req.Message,
	})

	c.JSON(http.StatusOK, gin.H{"sent": success})
}

// Hub logic (Moved into methods for clarity)
type Hub struct {
	Clients map[string]*websocket.Conn
	mu      sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{Clients: make(map[string]*websocket.Conn)}
}

func (h *Hub) Register(id string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.Clients[id] = conn
}

func (h *Hub) Unregister(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if conn, ok := h.Clients[id]; ok {
		conn.Close()
		delete(h.Clients, id)
	}
}

func (h *Hub) SendToUser(id string, msg interface{}) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if conn, ok := h.Clients[id]; ok {
		return conn.WriteJSON(msg) == nil
	}
	return false
}
