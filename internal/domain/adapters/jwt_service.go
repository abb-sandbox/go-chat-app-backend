package adapters

import (
	"context"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
)

type JWTService interface {
	GenerateActivationLink(ctx context.Context) (link string)
	GenerateTokenPair(ctx context.Context, userID string) (accessToken, refreshToken string, err error)
	CreateSession(ctx context.Context, userID string, refreshToken, userAgent, ClientIP string) (entities.Session, error)
	// Validates a refresh token and returns its associated session ID and userID.
	ValidateRefreshToken(ctx context.Context, refreshToken string) (sessionID string, userID string, err error)
	// ValidateAccessToken validates an access token and returns the session ID and userIDs
	ValidateAccessToken(ctx context.Context, accessToken string) (sessionID string, userID string, err error)
}
