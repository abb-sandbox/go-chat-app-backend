package chat_handlers

import (
	"context"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
)

type CreateChatCommand struct {
	SenderID   string
	ReceiverID string
}

// ChatService is the main service for handling all the chat ops
type ChatService interface {
	CreateChat(ctx context.Context, cmd CreateChatCommand) (chat entities.Chat, err error)
}
