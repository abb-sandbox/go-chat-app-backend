package adapters

import (
	"context"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entity"
)

type Cache interface {
	SaveUserInCache(ctx context.Context, key string, user entity.User, duration time.Duration) error
	GetUserFromCache(ctx context.Context, key string) (user entity.User, err error)
	RemoveFromCacheByKey(ctx context.Context, link string) error
	SaveSession(ctx context.Context, session entity.Session) error
	// Get session by session ID (JTI)
	GetSessionByID(ctx context.Context, id string) (entity.Session, error)
	// Remove session by ID
	RemoveSessionByID(ctx context.Context, id string) error
}
