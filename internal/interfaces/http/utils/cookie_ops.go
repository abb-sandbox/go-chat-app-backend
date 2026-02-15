package cookie_ops

import (
	"time"

	"github.com/gin-gonic/gin"
)

const (
	AccessTokenCookie  = "access_token"
	RefreshTokenCookie = "refresh_token"
)

// Helper method to set a secure HttpOnly cookie
// Note: This requires access to the expiration time from your service layer.
func SetAuthCookie(c *gin.Context, name string, value string, expires time.Duration) {
	// Determine the max age in seconds
	maxAge := int(expires.Seconds())

	c.SetCookie(
		name,
		value,
		maxAge,
		"/",  // Path: Cookie is accessible across the entire application
		"",   // Domain: Empty defaults to current host (secure)
		true, // Secure: Must be true in production (requires HTTPS)
		true, // HttpOnly: Prevents client-side JavaScript access (Anti-XSS)
	)
}

// Helper method to clear cookies by setting MaxAge to -1
func ClearAuthCookies(c *gin.Context) {
	// Clear Access Token
	c.SetCookie(
		AccessTokenCookie,
		"",
		-1, // MaxAge: -1 immediately deletes the cookie
		"/",
		"",
		true, // Secure flag must match the original setting
		true, // HttpOnly flag must match the original setting
	)

	// Clear Refresh Token
	c.SetCookie(
		RefreshTokenCookie,
		"",
		-1, // MaxAge: -1 immediately deletes the cookie
		"/",
		"",
		true,
		true,
	)
}
