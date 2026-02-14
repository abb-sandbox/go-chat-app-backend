package middleware

import (
	"net/http"
	"strings"
	"time"

	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	usecases "github.com/AzimBB/go-chat-app-backend/internal/usecases/user_auth_service"
	"github.com/gin-gonic/gin"
)

// Use simplified, idiomatic key names
type contextKey string

const (
	userIDKey    contextKey = "user_id"
	sessionIDKey contextKey = "session_id"
	// Cookie name constant
	AccessTokenCookie = "access_token"
)

// AuthMiddleware is a Gin-compatible middleware performing authentication checks.
func AuthMiddleware(jwtService usecases.JWTService, redis usecases.Cache, logger usecases.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := getToken(c)

		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized: Missing token."})
			return
		}

		sessionID, userID, err := jwtService.ValidateJWTToken(c.Request.Context(), token)
		if err != nil {
			logger.Info("JWT validation failed", "error", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized: Invalid token."})
			return
		}

		session, err := redis.GetSessionByID(c.Request.Context(), sessionID)
		if err != nil {
			logger.Info("Redis session lookup failed", "sessionID", sessionID, "error", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized: Session not found."})
			return
		}

		// Check session expiration
		if session.ExpiresAt.Before(time.Now()) {
			logger.Info("Session expired", "sessionID", sessionID)
			// OPTIONAL: Clear the expired cookie here for the client
			c.SetCookie(AccessTokenCookie, "", -1, "/", "", true, true)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized: Session expired."})
			return
		}

		// Check token user match (Stolen token check)
		if session.UserID != userID {
			logger.Error(app_errors.ErrRefreshTokenIsStolen, "sessionID", sessionID)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized: Token user mismatch."})
			return
		}

		// Populate Gin context
		c.Set(string(userIDKey), userID)
		c.Set(string(sessionIDKey), sessionID)
		c.Next()
	}
}

// getToken attempts to retrieve the access token from cookies, falling back to the Authorization header.
func getToken(c *gin.Context) string {
	// 1. Check for HttpOnly Cookie (Highest Priority)
	token, err := c.Cookie(AccessTokenCookie)
	if err == nil && token != "" {
		return token
	}

	// 2. Fallback to Authorization Header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

// --- Gin Helpers (Idiomatic Naming) ---

// GetUserID retrieves the user ID from the Gin context.
func GetUserID(c *gin.Context) (int, bool) {
	v, ok := c.Get(string(userIDKey))
	if !ok {
		return 0, false
	}
	id, ok := v.(int)
	return id, ok
}

// GetSessionID retrieves the session ID from the Gin context.
func GetSessionID(c *gin.Context) (string, bool) {
	v, ok := c.Get(string(sessionIDKey))
	if !ok {
		return "", false
	}
	sid, ok := v.(string)
	return sid, ok
}
