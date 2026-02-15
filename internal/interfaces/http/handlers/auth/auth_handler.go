package handlers

import (
	"errors"
	"net/http"
	"strings"

	_ "github.com/AzimBB/go-chat-app-backend/docs"
	"github.com/AzimBB/go-chat-app-backend/internal/config"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	cookie_ops "github.com/AzimBB/go-chat-app-backend/internal/interfaces/http/utils"
	usecases "github.com/AzimBB/go-chat-app-backend/internal/usecases/user_auth_service"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	gs "github.com/swaggo/gin-swagger"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	Service UserAuthService
	Logger  usecases.Logger
	cfg     config.Config
}

func NewAuthHandler(s UserAuthService, l usecases.Logger, c config.Config) *AuthHandler {
	return &AuthHandler{Service: s, cfg: c}
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token" `
	RefreshToken string `json:"refresh_token" `
}

type registerRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// RegisterRoutes attaches endpoints
func (h *AuthHandler) RegisterRoutes(r *gin.RouterGroup, authMiddleware gin.HandlerFunc) {
	// Register public routes and protected routes so callers can opt-in to register them separately
	h.RegisterPublicRoutes(r)
	h.RegisterProtectedRoutes(r, authMiddleware)
}

// RouteModule provides a modular interface for registering route groups
type RouteModule interface {
	RegisterPublicRoutes(r *gin.RouterGroup)
	RegisterProtectedRoutes(r *gin.RouterGroup, authMiddleware gin.HandlerFunc)
}

// RegisterPublicRoutes registers routes that are publicly accessible (no auth required)
func (h *AuthHandler) RegisterPublicRoutes(r *gin.RouterGroup) {
	r.GET("/swagger/*any", gs.WrapHandler(swaggerFiles.Handler))
	auth := r.Group("/auth")
	auth.POST("/register", h.register)
	auth.POST("/login", h.login)
	auth.POST("/refresh", h.refresh)
	auth.GET("/activate/:link/", h.activate)
}

// RegisterProtectedRoutes registers routes that require authentication
func (h *AuthHandler) RegisterProtectedRoutes(r *gin.RouterGroup, authMiddleware gin.HandlerFunc) {
	auth := r.Group("/auth")
	auth.Use(authMiddleware)
	auth.POST("/logout", h.logout)
	auth.GET("/me", h.me)
}

// @Summary		Register a new user
// @Description	Creates a new user account with hashed password
// @Tags			Auth
// @Accept			json
// @Produce		json
// @Param			user	body		registerRequest		true	"Registration Info"
// @Success		201		{object}	map[string]string	"message: registered"
// @Failure		400		{object}	map[string]string	"error message"
// @Router			/auth/register [post]
func (h *AuthHandler) register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": app_errors.ErrBadRequest.Error()})
		return
	}

	user := entities.User{
		Email:        req.Email,
		PasswordHash: passwordHash,
	}

	if err := h.Service.Register(c.Request.Context(), user); err != nil {
		if errors.Is(err, app_errors.ErrUserAlreadyExists) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "registered"})
}

// @Summary		Activate user account
// @Description	Activates a user via email link and random 6-digit code
// @Tags			Auth
// @Param			link	path		string				true	"Activation Link UUID"
// @Param			code	path		string				true	"6-digit Verification Code"
// @Success		200		{object}	map[string]string	"message: success"
// @Failure		400		{object}	map[string]string	"error message"
// @Router			/auth/activate/{link}/{code} [post]
func (h *AuthHandler) activate(c *gin.Context) {
	link, ok := c.Params.Get("link")
	if link == "" || !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": app_errors.ErrBadRequest})
		return
	}

	if err := h.Service.ActivateUser(c.Request.Context(), link); err != nil {
		if errors.Is(err, app_errors.ErrUserAlreadyExists) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(verification_success))
}

//	@Summary		Login user
//	@Description	Authenticates user and sets HttpOnly cookies for Access and Refresh tokens
//	@Tags			Auth
//	@Accept			json
//	@Produce		json
//	@Param			login	body		loginRequest			true	"Login Credentials"
//	@Success		200		{object}	map[string]interface{}	"message: Login successful"
//	@Failure		401		{object}	map[string]string		"message: Invalid credentials"
//	@Router			/auth/login [post]
//
// Revised login method in AuthHandler
func (h *AuthHandler) login(c *gin.Context) {
	var req loginRequest

	// 1. Bind and Validate Request
	if err := c.ShouldBindJSON(&req); err != nil {
		// Return structured, less verbose error
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload or format."})
		h.Logger.Warn("Login bind failed", "error", err)
		return
	}

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	// 2. Call Service Layer
	// Service should return the tokens and their expiration durations (needed for cookies)
	accessToken, refreshToken, err := h.Service.Login(c.Request.Context(), req.Email, req.Password, ua, ip)

	if err != nil {
		// Log the error internally but return a generic Unauthorized to prevent enumeration attacks
		h.Logger.Info("Login failed attempt", "email", req.Email, "error", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials."})
		return
	}

	// 3. Set Secure HttpOnly Cookies
	// Store access token in a short-lived cookie
	cookie_ops.SetAuthCookie(c, cookie_ops.AccessTokenCookie, accessToken, h.cfg.JWT_SHORT)

	// Store refresh token in a long-lived cookie (Crucial for session persistence)
	cookie_ops.SetAuthCookie(c, cookie_ops.RefreshTokenCookie, refreshToken, h.cfg.JWT_LONG)

	// 4. Respond to Client
	// We only return a success message; tokens are in the cookie header
	c.JSON(http.StatusOK, AuthResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func (h *AuthHandler) refresh(c *gin.Context) {
	refreshToken, err := c.Cookie(cookie_ops.RefreshTokenCookie)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrEmptyAuthCreds})
		return
	}

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	newAccess, newRefresh, err := h.Service.Refresh(c.Request.Context(), refreshToken, ua, ip)
	if err != nil {
		h.Logger.Info("Token refresh failed", "error", err.Error())
		cookie_ops.ClearAuthCookies(c)
		c.JSON(http.StatusInternalServerError, gin.H{"error": app_errors.ErrInternalServerError})
		return
	}
	shortTTL := h.cfg.JWT_SHORT
	longTTL := h.cfg.JWT_LONG

	cookie_ops.SetAuthCookie(c, cookie_ops.AccessTokenCookie, newAccess, shortTTL)
	cookie_ops.SetAuthCookie(c, cookie_ops.RefreshTokenCookie, newRefresh, longTTL)
	c.JSON(http.StatusOK, AuthResponse{AccessToken: newAccess, RefreshToken: newRefresh})
}

func (h *AuthHandler) logout(c *gin.Context) {
	sid, ok := GetSessionID(c)

	if !ok {
		cookie_ops.ClearAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Session identifier missing."})
		return
	}

	if err := h.Service.Logout(c.Request.Context(), sid); err != nil {
		h.Logger.Error(errors.New("Logout service failed to delete session"), "session_id", sid, "error", err.Error())
		cookie_ops.ClearAuthCookies(c)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Logout failed internally, but client cookies cleared."})
		return
	}

	cookie_ops.ClearAuthCookies(c)

	c.Status(http.StatusNoContent)
}

// @Summary		Get current user info
// @Description	Returns the UID of the currently logged-in user from the session
// @Tags			Auth
// @Security		CookieAuth
// @Success		200	{object}	map[string]string	"user_id: string"
// @Failure		401	{object}	map[string]string	"error: unauthorized"
// @Router			/auth/me [get]
func (h *AuthHandler) me(c *gin.Context) {
	uid, ok := GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user_id": uid})
}

// @ Summary Endpoint for checing health
// @ Description Endpoint for checing health
// @ Success 200 {object} map[string]string "message: string"
// @ Router /health [get]
func Health(c *gin.Context) {
	c.JSON(200, gin.H{"message": "healthy and strong"})
}

// middlewares

// Use simplified, idiomatic key names
type contextKey string

const (
	userIDKey    contextKey = "user_id"
	sessionIDKey contextKey = "session_id"
	// Cookie name constant
	AccessTokenCookie = "access_token"
)

// AuthMiddleware is a Gin-compatible middleware performing authentication checks.
func (h *AuthHandler) AuthMiddleware(jwtService usecases.JWTService, redis usecases.Cache, logger usecases.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := getAccessToken(c)

		if accessToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrEmptyAuthCreds})
			return
		}
		currentIP := c.ClientIP()
		currentUserAgent := c.Request.UserAgent()

		sessionID, userID, err := jwtService.ValidateAccessToken(c.Request.Context(), accessToken, currentUserAgent, currentIP)
		if errors.Is(err, app_errors.ErrExpiredAccessToken) {
			logger.Info("Access Token is expired", "sessionID", sessionID)
			// OPTIONAL: Clear the expired cookie here for the client
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrExpiredAccessToken})
		} else if errors.Is(err, app_errors.ErrInvalidJwtToken) {
			logger.Info("Access Token is invalid", "accessToken", accessToken)
			// OPTIONAL: Clear the expired cookie here for the client
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrInvalidJwtToken})
		} else if errors.Is(err, app_errors.ErrAccessTokenStolen) {
			logger.Info("Access Token is stolen", "currentIP", currentIP, "currentUserAgent", currentUserAgent)
			// OPTIONAL: Clear the expired cookie here for the client
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": app_errors.ErrAccessTokenStolen})
		} else if err != nil {
			logger.Info("JWT validation failed", "error", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": app_errors.ErrInternalServerError})
		} else {
			// Populate Gin context
			c.Set(string(userIDKey), userID)
			c.Set(string(sessionIDKey), sessionID)
			c.Next()
		}

		c.SetCookie(AccessTokenCookie, "", -1, "/", "", true, true)
		err = h.Service.RevokeAccessBySession(c.Request.Context(), sessionID)
		if err != nil {
			logger.Info("Failed to delete sessionFrom cache failed", "error", err)
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
