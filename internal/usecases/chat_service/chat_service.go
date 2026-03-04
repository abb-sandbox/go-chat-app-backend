package chat_service

import (
	"context"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	"github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/handlers/chat_handlers"
)

// This service is for handling all chat ops
type ChatService struct {
	ChatRepo ChatRepo
}

func (s *ChatService) CreateChat(ctx context.Context, cmd chat_handlers.CreateChatCommand) (chat entities.Chat, err error) {
	return s.ChatRepo.CreateOrReturnExistingChat(ctx, cmd)
}
