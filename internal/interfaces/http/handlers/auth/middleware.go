package handlers

import (
	"errors"
	"net/http"
	"strings"

	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	cookie_ops "github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/utils"
	"github.com/gin-gonic/gin"
)

// AuthMiddleware is a Gin-compatible middleware performing authentication checks.
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := getAccessToken(c)

		if accessToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrEmptyAuthCreds})
			return
		}
		currentIP := c.ClientIP()
		currentUserAgent := c.Request.UserAgent()

		sessionID, userID, err := h.JWTService.ValidateAccessToken(c.Request.Context(), accessToken, currentUserAgent, currentIP)
		if errors.Is(err, app_errors.ErrExpiredAccessToken) {
			h.Logger.Info("Access Token is expired", "sessionID", sessionID)
			cookie_ops.ClearAuthCookies(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrExpiredAccessToken})
		} else if errors.Is(err, app_errors.ErrInvalidJwtToken) {
			h.Logger.Info("Access Token is invalid", "accessToken", accessToken)
			cookie_ops.ClearAuthCookies(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrInvalidJwtToken})
		} else if errors.Is(err, app_errors.ErrAccessTokenStolen) {
			h.Logger.Info("Access Token is stolen", "currentIP", currentIP, "currentUserAgent", currentUserAgent)
			cookie_ops.ClearAuthCookies(c)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrAccessTokenStolen})
		} else if err != nil {
			h.Logger.Info("JWT validation failed", "error", err)
			cookie_ops.ClearAuthCookies(c)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": app_errors.ErrInternalServerError})
		} else {
			// Populate Gin context
			c.Set(string(userIDKey), userID)
			c.Set(string(sessionIDKey), sessionID)
			c.Next()
		}
		if err != nil {
			err = h.Service.RevokeAccessBySession(c.Request.Context(), sessionID)
			if err != nil {
				h.Logger.Info("Failed to delete sessionFrom cache failed", "error", err)
			}
		}

	}
}

// getAccessToken attempts to retrieve the access token from cookies, falling back to the Authorization header.
func getAccessToken(c *gin.Context) string {
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
