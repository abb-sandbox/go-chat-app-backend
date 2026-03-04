package chat_handlers

import (
	"net/http"

	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	"github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/utils"
	usecases "github.com/AzimBB/go-chat-app-backend/internal/usecases/user_auth_service"
	"github.com/gin-gonic/gin"
)

type ChatHandler struct {
	Logger      usecases.Logger
	ChatService ChatService
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
	createChatCommand := CreateChatCommand(req)

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
