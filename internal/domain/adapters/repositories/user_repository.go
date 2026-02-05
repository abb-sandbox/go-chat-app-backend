package repositories

import (
	"context"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entity"
)

// UserRepository responsible for CRUD operations including specific ones
type UserRepository interface {
	CheckEmailExistence(ctx context.Context, email string) error
	Create(ctx context.Context, user *entity.User) error
	CheckPassword(ctx context.Context, email, password string) error
	GetUserIDByEmail(ctx context.Context, email string) (userID string, err error)
}
