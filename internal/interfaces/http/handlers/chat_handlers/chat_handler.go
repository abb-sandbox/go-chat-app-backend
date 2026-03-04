package chat_handlers

import (
	"context"
	"net/http"

	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	"github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/utils"
	usecases "github.com/AzimBB/go-chat-app-backend/internal/usecases/user_auth_service"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type ChatHandler struct {
	ChatService ChatService
	Hub         *Hub
	Logger      usecases.Logger
	Upgrader    websocket.Upgrader
	Ctx         context.Context
}

// -----------
// Create chat lodic for creation of new chat, if chat already exists returns response with old data
type CreateChatRequest struct {
	SenderID   string `json:"sender_id" binding:"required"`
	ReceiverID string `json:"receiver_id" binding:"required"`
}
type CreateChatResponse struct {
	ChatID   string `json:"chat_id" `
	ChatName string `json:"chat_name" `
}

// CreateChat Creating new chat or returning the existing chat
//
//	@Summary		Create or get a 1-to-1 chat
//	@Description	Initiates a new chat between two users or returns existing. If a 1-to-1 chat already exists between these users, it returns the existing chat details.
//	@Tags			chats
//	@Accept			json
//	@Produce		json
//	@Param			Authorization	header		string				true	"Insert 'Bearer <AccessToken>'"
//	@Param			request			body		CreateChatRequest	true	"Create Chat Request"
//	@Success		200				{object}	CreateChatResponse	"Successfully created or retrieved chat"
//	@Failure		400				{object}	utils.ErrorResponse	"Invalid request body or missing fields"
//	@Failure		500				{object}	utils.ErrorResponse	"Internal server error"
//	@Router			/api/v1/chats/create [post]
func (h *ChatHandler) CreateChat(c *gin.Context) {
	var req CreateChatRequest

	// 1. Bind and Validate Request

	if err := c.ShouldBindJSON(&req); err != nil {
		// Return structured, less verbose error
		h.Logger.Warn("Login bind failed", "error", err)
		c.JSON(http.StatusBadRequest, utils.ErrorResponse{Error: app_errors.ErrBadRequest.Error()})
		return
	}

	// 2. Mapping the DTO (Data Transfer Object or Model)
	createChatCommand := CreateChatCommand{
		SenderID:   req.SenderID,
		ReceiverID: req.ReceiverID,
	}

	// 3. Doing the business logic through service
	chat, err := h.ChatService.CreateChat(c.Request.Context(), createChatCommand)

	// 4. Filter for user errors
	if err != nil {
		h.Logger.Error(err, "ChatService.CreateChat : ", err.Error())
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse{Error: err.Error()})
		return
	}

	// 5. Returning success operation response
	c.JSON(http.StatusOK, CreateChatResponse{
		ChatID:   chat.ID,
		ChatName: chat.Name,
	})
}

// --------
