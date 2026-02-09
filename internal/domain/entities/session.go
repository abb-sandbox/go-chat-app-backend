package entities

import "time"

type Session struct {
	// Unique identifier for this specific session. This is the Redis key.
	// It's usually the JTI (JWT ID) claim from the token payload.
	ID string `json:"session_id"`

	// Identifier of the user this session belongs to.
	UserID string `json:"user_id"`

	// To check the priorite while refreshing RefreshToken
	IsAdmin bool `json:"is_admin"`

	// The token string used for refreshing the session (the Refresh Token).
	RefreshToken string `json:"refresh_token"`

	// Time when the session (and the refresh token) expires.
	ExpiresAt time.Time `json:"expires_at"`

	// Optional: Metadata to track session health and revoke suspicious sessions.
	UserAgent string `json:"user_agent,omitempty"` // Browser/Device info
	ClientIP  string `json:"client_ip,omitempty"`  // IP address used for login
}
