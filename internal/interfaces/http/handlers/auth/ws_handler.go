package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/utils"
	usecases "github.com/AzimBB/go-chat-app-backend/internal/usecases/user_auth_service"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type Envelope struct {
	Event   string
	Payload any
}

type ActiveUsersResponse struct {
	ActiveUsers []string `json:"active_users" example:"user_1,user_2"`
}

type Client struct {
	conn        *websocket.Conn
	sendChannel chan []byte
	handler_ctx context.Context
}

func (c *Client) writePump() {
	defer c.conn.Close()
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	var err error

write_loop:
	for {
		select {
		case message, ok := <-c.sendChannel: // Other functions send data here
			// 1. Check if the channel was closed by another part of your code
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				break write_loop
			}

			err = c.conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				break write_loop
			}
		case <-ticker.C:
			err = c.conn.WriteMessage(websocket.PingMessage, nil)
			if err != nil {
				break write_loop
			}
		case <-c.handler_ctx.Done():
			_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			break write_loop
		}
	}
}

const (
	pingPeriod = 50 * time.Second // Send pings every 50s
	pongWait   = 60 * time.Second // Expect pongs/messages within 60s
)

func (c *Client) HandleMessage() error {
	var msg any
	// This keeps the connection open and handles Koyeb timeouts
	err := c.conn.ReadJSON(&msg)
	if err != nil {
		// Logger.Info or somethig
		return err
	}
	// TODO : handle the msg !!!!!!!!!!!!
	return nil
}

type WSHandler struct {
	Hub      *Hub
	Logger   usecases.Logger
	Upgrader websocket.Upgrader
	ctx      context.Context
}

func NewWSHandler(ctx context.Context) *WSHandler {
	return &WSHandler{
		Hub: NewHub(),
		Upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				return true // Adjust for production
			},
		},
		ctx: ctx,
	}
}

func (h *WSHandler) RegisterWSRoutes(rg *gin.RouterGroup, authMiddleware gin.HandlerFunc) {
	users := rg.Group("/users")
	users.Use(authMiddleware)
	{
		users.GET("/active", h.GetActiveUsers)
	}

	// WebSocket Upgrade endpoint
	rg.GET("/ws", authMiddleware, h.HandleWebSocket)
}

// HandleWebSocket
//
//	@Summary		Upgrade to WebSocket
//	@Descripti//	@Summary      Upgrade to WebSocket
//
//	@Description	Initiates a WebSocket connection. Requires user_id in query.
//	@Tags			websocket
//	@Param			user_id	query		string	true	"User ID"
//	@Success		101		{string}	string	"Switching Protocols"
//	@Router			/ws [get]
func (h *WSHandler) HandleWebSocket(c *gin.Context) {
	userID, ok := utils.GetFromContextAsString(c, userIDKey)
	if userID == "" || !ok {
		// Logger.Info or somethig
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id is required"})
		return
	}

	conn, err := h.Upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	// Inside HandleWebSocket after upgrade
	// setting  pong handler
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})
	// setting initial deadline
	err = conn.SetReadDeadline(time.Now().Add(pongWait))
	if err != nil {
		return
	}

	sendChannel := make(chan []byte, 256)

	client := Client{
		conn:        conn,
		handler_ctx: h.ctx,
		sendChannel: sendChannel,
	}

	h.Hub.Register(userID, &client)
	defer h.Hub.Unregister(userID) // closes connection itself and removes from the hub

	// setting up write pipeline

	go client.writePump()

	// Keep-alive loop & Message Listener

	// blocking operation, but if we return from function ,
	// we will close the underlying tcp connection,
	// that will return an error in HandleMessage metod of client
websocket_serving_loop:
	for {
		err := client.HandleMessage()
		if err != nil {
			h.Logger.Info("cannot read message")
			break websocket_serving_loop
		}
	}
}

// GetActiveUsers
//
//	@Summary		List active users
//	@Description	Returns an array of all currently connected User IDs.
//	@Tags			users
//	@Produce		json
//	@Success		200	{object}	ActiveUsersResponse
//	@Router			/users/active [get]
func (h *WSHandler) GetActiveUsers(c *gin.Context) {
	h.Hub.mu.RLock()
	ids := make([]string, 0, len(h.Hub.Clients))
	for id := range h.Hub.Clients {
		ids = append(ids, id)
	}
	h.Hub.mu.RUnlock()

	c.JSON(http.StatusOK, ActiveUsersResponse{ActiveUsers: ids})
}
