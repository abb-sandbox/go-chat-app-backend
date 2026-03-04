package chat_service

type ChatRepo interface {
	CreateOrReturnExistingChat(ctx, senderID, receiverID string)
}
