package handlers

import (
	"errors"
	"net/http"
	"strings"

	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	cookie_ops "github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddleware is a Gin-compatible middleware performing authentication checks.
//
//	@Summary		Auth middleware
//	@Description	For checking every auhtorized endpoint of users
//	@Tags			Auhtorization
//	@Param			Authorization	header		string			true	"Insert 'Bearer <AccessToken>'"
//	@Failure		401				{object}	ErrorResponse	"Possible "error" values : [EMPTY_AUTH_CREDS,EXPIRED_ACCESS_TOKEN,INVALID_JWT_TOKEN,ACCESS_TOKEN_STOLEN]"
//	@Failure		500				{object}	ErrorResponse	"Server failed to process . Possible "error" values : [INTERNAL_SERVER_ERROR]"
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := getAccessToken(c)

		if accessToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: app_errors.ErrEmptyAuthCreds.Error()})
			return
		}
		currentIP := c.ClientIP()
		currentUserAgent := c.Request.UserAgent()

		sessionID, userID, err := h.JWTService.ValidateAccessToken(c.Request.Context(), accessToken, currentUserAgent, currentIP)

		// Removing Auth cookies if error exists
		if err != nil {
			cookie_ops.ClearAuthCookies(c)
		}

		// Checking for errors
		if errors.Is(err, app_errors.ErrExpiredAccessToken) || errors.Is(err, jwt.ErrTokenExpired) {
			h.Logger.Info("Access Token is expired", "sessionID", sessionID)
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: app_errors.ErrExpiredAccessToken.Error()})
		} else if errors.Is(err, app_errors.ErrInvalidJwtToken) {
			h.Logger.Info("Access Token is invalid", "accessToken", accessToken)
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: app_errors.ErrInvalidJwtToken.Error()})
		} else if errors.Is(err, app_errors.ErrAccessTokenStolen) {
			h.Logger.Info("Access Token is stolen", "currentIP", currentIP, "currentUserAgent", currentUserAgent)
			c.AbortWithStatusJSON(http.StatusUnauthorized, ErrorResponse{Error: app_errors.ErrAccessTokenStolen.Error()})
		} else if err != nil {
			h.Logger.Info("JWT validation failed", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse{Error: app_errors.ErrInternalServerError.Error()})
		} else {
			// Populate Gin context
			c.Set(string(userIDKey), userID)
			c.Set(string(sessionIDKey), sessionID)
			c.Next()
		}

	}
}

// getAccessToken attempts to retrieve the access token from cookies, falling back to the Authorization header.
func getAccessToken(c *gin.Context) string {
	// 1. Check for HttpOnly Cookie (Highest Priority)
	token, err := c.Cookie(cookie_ops.AccessTokenCookie)
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

// getRefreshToken attempts to retrieve the access refresh from cookies, falling back to the Authorization header.
func getRefreshToken(c *gin.Context) string {
	// 1. Check for HttpOnly Cookie (Highest Priority)
	token, err := c.Cookie(cookie_ops.RefreshTokenCookie)
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
