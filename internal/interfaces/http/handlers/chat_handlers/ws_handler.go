package chat_handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/utils"
	usecases "github.com/AzimBB/go-chat-app-backend/internal/usecases/user_auth_service"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type ActiveUsersResponse struct {
	ActiveUsers []string `json:"active_users" example:"user_1,user_2"`
}

type WSHandler struct {
	Hub      *Hub
	Logger   usecases.Logger
	Upgrader websocket.Upgrader
	ctx      context.Context
}

func NewWSHandler(ctx context.Context, chatService ChatService) *WSHandler {
	return &WSHandler{
		Hub: NewHub(ctx, chatService),
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
	userID, ok := utils.GetFromContextAsString(c, utils.UserIDKey)
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

	client := &Client{
		conn:        conn,
		handler_ctx: h.ctx,
		sendChannel: sendChannel,
	}

	// Starting to serve the client
	h.Hub.Serve(userID, client)
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
