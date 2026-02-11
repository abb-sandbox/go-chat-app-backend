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

// UserRepository responsible for CRUD operations including specific ones
type UserRepository interface {
	CheckEmailExistence(ctx context.Context, email string) error
	Create(ctx context.Context, user *entities.User) error
	CheckPassword(ctx context.Context, email, password string) error
	GetUserIDByEmail(ctx context.Context, email string) (userID string, err error)
}

// MailingService interface for sending the activation link
type MailingService interface {
	SendActivationLink(ctx context.Context, email, activationCode string) error
}

type JWTService interface {
	GenerateActivationLink(ctx context.Context) (link string, err error)
	GenerateTokenPair(ctx context.Context, userID string) (accessToken, refreshToken string, err error)
	CreateSession(ctx context.Context, userID string, refreshToken, userAgent, ClientIP string) (entities.Session, error)
	// Validates a refresh token and returns its associated session ID and userID.
	ValidateRefreshToken(ctx context.Context, refreshToken string) (sessionID string, userID string, err error)
	// ValidateAccessToken validates an access token and returns the session ID and userIDs
	ValidateAccessToken(ctx context.Context, accessToken string) (sessionID string, userID string, err error)
}

type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})

	Error(err error, msg string, fields ...interface{})
}
