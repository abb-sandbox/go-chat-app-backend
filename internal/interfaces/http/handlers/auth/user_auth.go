package handlers

import (
	"context"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
)

// UserAuthService is responsible for auth procedures of user
type UserAuthService interface {
	// ===Complete Registration logic ===

	// Register Initiating registration
	Register(ctx context.Context, user entities.User) error
	// ActivateUser Completing registration
	ActivateUser(ctx context.Context, link string) error
	// ==================================

	// ==== Authetication logic	=========

	// Login for generating JWT tokens and distributing
	Login(ctx context.Context, email, password, userAgent, ClientIP string) (AccessToken, RefreshToken string, err error)
	// Refreshing the token pair — require original request metadata
	Refresh(ctx context.Context, RefreshToken string, userAgent string, ClientIP string) (AccessToken, NewRefreshToken string, err error)
	// Logout by session ID (typically the JTI/JWT ID)
	Logout(ctx context.Context, sessionID string) error
	RevokeAccessBySession(ctx context.Context, sessionID string) error
	// ==================================
}
