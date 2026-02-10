package usecases

import (
	"context"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
)

type Cache interface {
	SaveUserInCache(ctx context.Context, key string, user entities.User, duration time.Duration) error
	GetUserFromCache(ctx context.Context, key string) (user entities.User, err error)
	RemoveFromCacheByKey(ctx context.Context, link string) error
	SaveSession(ctx context.Context, session entities.Session) error
	// Get session by session ID (JTI)
	GetSessionByID(ctx context.Context, id string) (entities.Session, error)
	// Remove session by ID
	RemoveSessionByID(ctx context.Context, id string) error
}
