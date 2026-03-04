package chat_service

import (
	"context"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	"github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/handlers/chat_handlers"
)

type ChatRepo interface {
	CreateOrReturnExistingChat(ctx context.Context, cmd chat_handlers.CreateChatCommand) (chat entities.Chat, err error)
}
