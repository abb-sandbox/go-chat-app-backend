package postgres

import (
	"context"
	"fmt"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	"github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/handlers/chat_handlers"
	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ChatRepo struct {
	Pool *pgxpool.Pool
}

func (p *ChatRepo) CreateOrReturnExistingChat(
	ctx context.Context,
	cmd chat_handlers.CreateChatCommand) (entities.Chat, error) {

	sb := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

	// Determine if this is a self-chat
	isSelfChat := cmd.SenderID == cmd.ReceiverID
	expectedCount := 2
	if isSelfChat {
		expectedCount = 1
	}

	// 1. Find existing chat
	// We use squirrel.Eq with a slice. If IDs are identical, Squirrel/Postgres
	// treats it as a single value in the IN clause.
	sql, args, err := sb.Select("chat_id").
		From("chat_members").
		Where(squirrel.Eq{"user_id": []string{cmd.SenderID, cmd.ReceiverID}}).
		GroupBy("chat_id").
		Having(fmt.Sprintf("COUNT(DISTINCT user_id) = %d", expectedCount)).
		Limit(1).
		ToSql()

	if err != nil {
		return entities.Chat{}, err
	}

	var chatID string
	err = p.Pool.QueryRow(ctx, sql, args...).Scan(&chatID)

	if err == nil {
		return p.getChatByID(ctx, chatID, cmd.SenderID)
	}

	if err != pgx.ErrNoRows {
		return entities.Chat{}, err
	}

	return p.createNewChat(ctx, cmd, isSelfChat)
}

func (p *ChatRepo) createNewChat(ctx context.Context, cmd chat_handlers.CreateChatCommand, isSelfChat bool) (entities.Chat, error) {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return entities.Chat{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var chatID string
	err = tx.QueryRow(ctx, "INSERT INTO chats (name) VALUES ($1) RETURNING id", "DM").Scan(&chatID)
	if err != nil {
		return entities.Chat{}, err
	}

	// Insert members
	im := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar).
		Insert("chat_members").Columns("chat_id", "user_id").
		Values(chatID, cmd.SenderID)

	// Only add the second row if it's NOT a self-chat
	if !isSelfChat {
		im = im.Values(chatID, cmd.ReceiverID)
	}

	sql, args, err := im.ToSql()
	if err != nil {
		return entities.Chat{}, err
	}

	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		return entities.Chat{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return entities.Chat{}, err
	}

	return p.getChatByID(ctx, chatID, cmd.SenderID)
}
func (p *ChatRepo) getChatByID(ctx context.Context, chatID, currentUserID string) (entities.Chat, error) {
	sb := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

	// Use COALESCE to prioritize the 'other' email, falling back to 'me' for self-chats.
	// We use aliases (me, me_u, other, other_u) to keep the joins clear.
	sql, args, err := sb.Select(
		"c.id",
		"COALESCE(other_u.email, me_u.email) as display_name",
	).
		From("chats c").
		// Join to find the current user's membership
		Join("chat_members me ON c.id = me.chat_id AND me.user_id = ?", currentUserID).
		// Join to get the current user's details (email fallback)
		Join("users me_u ON me.user_id = me_u.id").
		// Left Join to find if there is someone else in the chat
		LeftJoin("chat_members other ON c.id = other.chat_id AND other.user_id != ?", currentUserID).
		// Left Join to get that other person's details
		LeftJoin("users other_u ON other.user_id = other_u.id").
		Where(squirrel.Eq{"c.id": chatID}).
		Limit(1).
		ToSql()

	if err != nil {
		return entities.Chat{}, fmt.Errorf("failed to build getChatByID query: %w", err)
	}

	var chat entities.Chat
	err = p.Pool.QueryRow(ctx, sql, args...).Scan(&chat.ID, &chat.Name)
	if err != nil {
		return entities.Chat{}, fmt.Errorf("failed to execute getChatByID: %w", err)
	}

	return chat, nil
}
