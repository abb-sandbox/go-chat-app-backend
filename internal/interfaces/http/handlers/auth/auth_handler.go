package handlers

import (
	"errors"
	"net/http"

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
	Service    UserAuthService
	Logger     usecases.Logger
	cfg        config.Config
	JWTService usecases.JWTService
}

func NewAuthHandler(s UserAuthService, l usecases.Logger, c config.Config, jwt usecases.JWTService) *AuthHandler {
	return &AuthHandler{Service: s, cfg: c, JWTService: jwt, Logger: l}
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email" example:"user@example.com"`
	Password string `json:"password" binding:"required" example:"P@ssword123"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token" `
	RefreshToken string `json:"refresh_token" `
}

type registerRequest struct {
	Email    string `json:"email" example:"user@example.com" binding:"required,email"`
	Password string `json:"password" example:"P@ssword123" binding:"required,min=8"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

const (
	userIDKey    = "user_id"
	sessionIDKey = "session_id"
)

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

// register method for starting the registration process
//
//	@Summary		Register
//	@Description	For initiating registration process with sending activation link
//	@Tags			Registration
//	@Accept			json
//	@Produce		json
//	@Param			payload	body	registerRequest	true	"User registration details"
//	@Success		201		"Activation link is successfully sent"
//	@Failure		400		{object}	ErrorResponse	"Request is invalid. Possible "error" values:[USER_ALREADY_EXISTS,"all	others	are	caused	by	the	request's	incorrectness"]"
//	@Failure		500		{object}	ErrorResponse	"Server failed to process. Possible "error" values : [INTERNAL_SERVER_ERROR]"
//	@Router			/api/v1/auth/register [post]
func (h *AuthHandler) register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: app_errors.ErrInternalServerError.Error()})
		return
	}

	user := entities.User{
		Email:        req.Email,
		PasswordHash: passwordHash,
	}

	if err := h.Service.Register(c.Request.Context(), user); err != nil {
		if errors.Is(err, app_errors.ErrUserAlreadyExists) {
			c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.Status(http.StatusCreated)
}

// activate activation of account after registration step
//
//	@Summary		Activate
//	@Description	Activation of account after registration step
//	@Tags			Registration
//	@Accept			plain
//	@Produce		html
//	@Param			link	path		string			true	"Generated link's end side edge"
//	@Success		201		{string}	string			"Returns the html page of success"
//	@Failure		400		{object}	ErrorResponse	"Could not get the link from url path. Possible "error" values : [BAD_REQUEST]"
//	@Failure		410		{object}	ErrorResponse	"Activation link is expired . Possible "error" values : [ACTIVATION_TIME_EXPIRED]"
//	@Failure		500		{object}	ErrorResponse	"Server failed to process . Possible "error" values : [INTERNAL_SERVER_ERROR]"
//	@Router			/api/v1/auth/activate/{link} [get]
func (h *AuthHandler) activate(c *gin.Context) {
	link, ok := c.Params.Get("link")
	if link == "" || !ok {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: app_errors.ErrBadRequest.Error()})
		return
	}

	if err := h.Service.ActivateUser(c.Request.Context(), link); err != nil {
		if errors.Is(err, app_errors.ErrActivationTimeExpired) {
			c.JSON(http.StatusGone, ErrorResponse{Error: err.Error()})
		}
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.Data(http.StatusCreated, "text/html; charset=utf-8", []byte(verification_success))
}

// @Summary		Login
// @Description	Basic Login operation with email and password
// @Tags			Authentication
// @Accept			json
// @Produce		json
// @Param			payload	body		loginRequest	true	"Provide your creds for creation new session on certain device"
// @Success		201		{object}	AuthResponse	"Session was successfully created"
// @Failure		400		{object}	ErrorResponse	"Possible "error" values: [EMPTY_AUTH_CREDS] "
// @Failure		401		{object}	ErrorResponse	"Possible "error" values: [INVALID_CREDS, "any	other	printable	errors"]"
// @Failure		500		{object}	ErrorResponse	"Server failed to process . Possible "error" values : [INTERNAL_SERVER_ERROR]"
// @Router			/api/v1/auth/login [post]
func (h *AuthHandler) login(c *gin.Context) {
	var req loginRequest

	// 1. Bind and Validate Request
	if err := c.ShouldBindJSON(&req); err != nil {
		// Return structured, less verbose error
		h.Logger.Warn("Login bind failed", "error", err)
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: app_errors.ErrEmptyAuthCreds.Error()})
		return
	}

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	// 2. Call Service Layer
	// Service should return the tokens and their expiration durations (needed for cookies)
	accessToken, refreshToken, err := h.Service.Login(c.Request.Context(), req.Email, req.Password, ua, ip)
	if errors.Is(err, app_errors.ErrInternalServerError) {
		h.Logger.Info("Login failed because of server", "email", req.Email, "error", err.Error())
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: app_errors.ErrInternalServerError.Error()})
		return
	} else if err != nil {
		// Log the error internally but return a generic Unauthorized to prevent enumeration attacks
		h.Logger.Info("Login failed attempt", "email", req.Email, "error", err.Error())
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: app_errors.ErrInvalidCreds.Error()})
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

// @Summary		refresh
// @Description	Get new pair of token
// @Tags			Authorization
// @Accept			plain
// @Produce		json
// @Param			Authorization	header		string			true	"Insert 'Bearer <RefreshToken>'"
// @Success		200				{object}	AuthResponse	"New refreshed token pair returned. So update them both"
// @Failure		401				{object}	ErrorResponse	"Possible "error" values: [INVALID_CREDS,"all	other	errors"]"
// @Failure		500				{object}	ErrorResponse	"Server failed to process . Possible "error" values : [INTERNAL_SERVER_ERROR]"
// @Router			/api/v1/auth/refresh [post]
func (h *AuthHandler) refresh(c *gin.Context) {
	refreshToken := getRefreshToken(c)
	if refreshToken == "" {
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: app_errors.ErrEmptyAuthCreds.Error()})
		return
	}

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	newAccess, newRefresh, err := h.Service.Refresh(c.Request.Context(), refreshToken, ua, ip)
	if errors.Is(err, app_errors.ErrInternalServerError) {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	} else if err != nil && !errors.Is(err, app_errors.ErrInternalServerError) {
		h.Logger.Info("Token refresh failed", "error", err.Error())
		cookie_ops.ClearAuthCookies(c)
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: err.Error()})
		return
	}
	shortTTL := h.cfg.JWT_SHORT
	longTTL := h.cfg.JWT_LONG

	cookie_ops.SetAuthCookie(c, cookie_ops.AccessTokenCookie, newAccess, shortTTL)
	cookie_ops.SetAuthCookie(c, cookie_ops.RefreshTokenCookie, newRefresh, longTTL)
	c.JSON(http.StatusOK, AuthResponse{AccessToken: newAccess, RefreshToken: newRefresh})
}

// @Summary		Log out
// @Description	Logging out by revoking session
// @Tags			Authorization
// @Accept			plain
// @Produce		plain
// @Param			Authorization	header	string	true	"Insert 'Bearer <AccessToken>'"
// @Success		204				"Logged out successfully"
// @Failure		401				{object}	ErrorResponse	"Possible "error" values: [EMPTY_AUTH_CREDS]"
// @Failure		500				{object}	ErrorResponse	"Server failed to process . Possible "error" values : [INTERNAL_SERVER_ERROR]"
// @Router			/api/v1/auth/logout [post]
func (h *AuthHandler) logout(c *gin.Context) {
	sid, ok := GetSessionID(c)

	if !ok {
		cookie_ops.ClearAuthCookies(c)
		c.JSON(http.StatusUnauthorized, ErrorResponse{Error: app_errors.ErrEmptyAuthCreds.Error()})
		return
	}

	if err := h.Service.Logout(c.Request.Context(), sid); err != nil {
		h.Logger.Error(errors.New("Logout service failed to delete session"), "session_id", sid, "error", err.Error())
		cookie_ops.ClearAuthCookies(c)
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: app_errors.ErrInternalServerError.Error()})
		return
	}

	cookie_ops.ClearAuthCookies(c)

	c.Status(http.StatusNoContent)
}

// @Summary		Checking authorization
// @Description	Endpoint for checking authorization
// @Tags			Profile
// @Accept			plain
// @Produce		json
// @Param			Authorization	header		string				true	"Insert 'Bearer <your_token>'"
// @Success		200				{object}	map[string]string	""user_id": some_user_id (int)"
// @Failure		500				{object}	ErrorResponse		"Possible "error" values: [INTERNAL_SERVER_ERROR]"
// @Router			/api/v1/auth/me [get]
func (h *AuthHandler) me(c *gin.Context) {
	user_id, ok := GetUserID(c)
	if !ok {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: app_errors.ErrInternalServerError.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user_id": user_id})
}

// Health
//
//	@Summary		Health
//	@Description	For container health checks (CI/CD)
//	@Tags			devops
//	@Accept			plain
//	@Produce		plain
//	@Success		200	{object}	map[string]string	"{"message": "healthy	and	strong"}s"
func Health(c *gin.Context) {
	c.JSON(200, gin.H{"message": "healthy and strong"})
}

// middlewares

// --- Gin Helpers (Idiomatic Naming) ---

// GetUserID retrieves the user ID from the Gin context.
func GetUserID(c *gin.Context) (string, bool) {
	v, ok := c.Get(string(userIDKey))
	if !ok {
		return "", false
	}
	id, ok := v.(string)
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
