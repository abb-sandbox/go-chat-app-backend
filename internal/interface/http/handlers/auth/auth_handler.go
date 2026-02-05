package handlers

import (
	"errors"
	"net/http"
	"time"

	_ "github.com/AzimBB/go-chat-app-backend/docs"
	"github.com/AzimBB/go-chat-app-backend/internal/config"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/adapters"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/entity"
	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/services"
	"github.com/AzimBB/go-chat-app-backend/internal/interface/http/middleware"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	gs "github.com/swaggo/gin-swagger"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	Service services.UserAuthService
	Logger  adapters.Logger
	cfg     config.Config
}

func NewAuthHandler(s services.UserAuthService, l adapters.Logger, c config.Config) *AuthHandler {
	return &AuthHandler{Service: s, Logger: l, cfg: c}
}

const (
	AccessTokenCookie  = "access_token"
	RefreshTokenCookie = "refresh_token"
)

type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type tokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

type registerRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// RegisterRoutes attaches endpoints
func (h *AuthHandler) RegisterRoutes(r *gin.RouterGroup, jwt adapters.JWTService, redis adapters.Cache) {
	// Register public routes and protected routes so callers can opt-in to register them separately
	h.RegisterPublicRoutes(r)
	h.RegisterProtectedRoutes(r, jwt, redis)
}

// RouteModule provides a modular interface for registering route groups
type RouteModule interface {
	RegisterPublicRoutes(r *gin.RouterGroup)
	RegisterProtectedRoutes(r *gin.RouterGroup, jwt adapters.JWTService, redis adapters.Cache)
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
func (h *AuthHandler) RegisterProtectedRoutes(r *gin.RouterGroup, jwt adapters.JWTService, redis adapters.Cache) {
	auth := r.Group("/auth")
	auth.Use(middleware.AuthMiddleware(jwt, redis, h.Logger))
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

	user := entity.User{
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
	access, refresh, err := h.Service.Login(c.Request.Context(), req.Email, req.Password, ua, ip)

	if err != nil {
		// Log the error internally but return a generic Unauthorized to prevent enumeration attacks
		h.Logger.Info("Login failed attempt", "email", req.Email, "error", err.Error())
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials."})
		return
	}

	// 3. Set Secure HttpOnly Cookies
	// Store access token in a short-lived cookie
	h.setAuthCookie(c, AccessTokenCookie, access, h.cfg.JWT_SHORT)

	// Store refresh token in a long-lived cookie (Crucial for session persistence)
	h.setAuthCookie(c, RefreshTokenCookie, refresh, h.cfg.JWT_LONG)

	// 4. Respond to Client
	// We only return a success message; tokens are in the cookie header
	c.JSON(http.StatusOK, gin.H{"message": "Login successful. Tokens set via cookie."})
}

// Helper method to set a secure HttpOnly cookie
// Note: This requires access to the expiration time from your service layer.
func (h *AuthHandler) setAuthCookie(c *gin.Context, name string, value string, expires time.Duration) {
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

func (h *AuthHandler) refresh(c *gin.Context) {
	refreshToken, err := c.Cookie(RefreshTokenCookie)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Refresh token cookie missing."})
		return
	}

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	access, newRefresh, err := h.Service.Refresh(c.Request.Context(), refreshToken, ua, ip)
	if err != nil {
		h.Logger.Info("Token refresh failed", "error", err.Error())
		c.SetCookie(AccessTokenCookie, "", -1, "/", "", true, true)
		c.SetCookie(RefreshTokenCookie, "", -1, "/", "", true, true)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Session invalid or expired. Please re-login."})
		return
	}
	shortTTL := h.cfg.JWT_SHORT
	longTTL := h.cfg.JWT_LONG

	h.setAuthCookie(c, AccessTokenCookie, access, shortTTL)
	h.setAuthCookie(c, RefreshTokenCookie, newRefresh, longTTL)
	c.JSON(http.StatusOK, gin.H{"message": "Tokens successfully refreshed."})
}

func (h *AuthHandler) logout(c *gin.Context) {
	sid, ok := middleware.GetSessionID(c)

	if !ok {
		h.clearAuthCookies(c)
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Session identifier missing."})
		return
	}

	if err := h.Service.Logout(c.Request.Context(), sid); err != nil {
		h.Logger.Error(errors.New("Logout service failed to delete session"), "session_id", sid, "error", err.Error())
		h.clearAuthCookies(c)
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Logout failed internally, but client cookies cleared."})
		return
	}

	h.clearAuthCookies(c)

	c.Status(http.StatusNoContent)
}

// Helper method to clear cookies by setting MaxAge to -1
func (h *AuthHandler) clearAuthCookies(c *gin.Context) {
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

// @Summary		Get current user info
// @Description	Returns the UID of the currently logged-in user from the session
// @Tags			Auth
// @Security		CookieAuth
// @Success		200	{object}	map[string]string	"user_id: string"
// @Failure		401	{object}	map[string]string	"error: unauthorized"
// @Router			/auth/me [get]
func (h *AuthHandler) me(c *gin.Context) {
	uid, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"user_id": uid})
}
