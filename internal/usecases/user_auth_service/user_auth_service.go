package usecases

import (
	"context"
	"errors"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
)

type UserAuthServiceImpl struct {
	UserRepository       UserRepository
	JWTService           JWTService
	Cache                Cache
	MailingService       MailingService
	ActivationTimeExpiry time.Duration
	Logger               Logger
}

func AuthService(
	userRepository UserRepository,
	jwtService JWTService,
	redisCache Cache,
	mailingService MailingService) *UserAuthServiceImpl {
	return &UserAuthServiceImpl{
		UserRepository: userRepository,
		JWTService:     jwtService,
		Cache:          redisCache,
		MailingService: mailingService,
	}
}

func (s *UserAuthServiceImpl) Register(ctx context.Context, user entities.User) error {
	err := s.UserRepository.CheckEmailExistence(ctx, user.Email)
	if errors.Is(err, app_errors.ErrUserAlreadyExists) {
		s.Logger.Info(err.Error(), "email", user.Email)
		return err
	}
	if err != nil {
		s.Logger.Error(err, "In Register UseCase", "Method", "CheckEmailExistence")
		return app_errors.ErrInternalServerError
	}

	newLinkAsKey, err := s.JWTService.GenerateActivationLink(ctx)
	if err != nil {
		s.Logger.Error(err, "Method  JWTService.GenerateActivationLink", "user", user)
		return app_errors.ErrInternalServerError
	}

	err = s.Cache.SaveUserInCache(ctx, newLinkAsKey, user, s.ActivationTimeExpiry)
	if err != nil {
		s.Logger.Error(err, "Method on RedisCache", "user", user)
		return app_errors.ErrInternalServerError
	}

	err = s.MailingService.SendActivationLink(ctx, user.Email, newLinkAsKey)
	if err != nil {
		s.Logger.Error(err, "Method on MailingService", "user", user, "link", newLinkAsKey)
		return app_errors.ErrInternalServerError
	}

	return nil
}

func (s *UserAuthServiceImpl) ActivateUser(ctx context.Context, link string) error {
	user, err := s.Cache.GetUserFromCache(ctx, link)
	if errors.Is(err, app_errors.ErrActivationTimeExpired) {
		s.Logger.Info(err.Error(), "link", link)
		return err
	} else if err != nil {
		s.Logger.Error(err, "RedisCache.GetUserFromCache()", "link", link)
		return app_errors.ErrInternalServerError
	}
	err = s.UserRepository.Create(ctx, &user)
	if err != nil {
		s.Logger.Error(err, "UserRepository.Create()", "link", link, "user", user)
		return app_errors.ErrInternalServerError
	}
	err = s.Cache.RemoveFromCacheByKey(ctx, link)
	if err != nil {
		s.Logger.Error(err, "RedisCache.RemoveFromCacheByKey()", "link", link)
		return app_errors.ErrInternalServerError
	}
	return nil
}

func (s *UserAuthServiceImpl) Login(ctx context.Context, email, password, userAgent, ClientIP string) (string, string, error) {
	err := s.UserRepository.CheckPassword(ctx, email, password)
	if errors.Is(err, app_errors.InvalidCredentials) {
		s.Logger.Info(err.Error(), "email", email, "password", password)
		return "", "", err
	} else if err != nil {
		s.Logger.Error(err, "UserRepository.CheckPassword()", "email", email, "password", password)
		return "", "", app_errors.ErrInternalServerError
	}
	userID, err := s.UserRepository.GetUserIDByEmail(ctx, email)
	if err != nil {
		s.Logger.Error(err, "UserRepository.GetUserIDAndPriorityByEmail()", "email", email)
		return "", "", app_errors.ErrInternalServerError
	}
	accessToken, refreshToken, err := s.JWTService.GenerateTokenPair(ctx, userID)
	if err != nil {
		s.Logger.Error(err, "JWTService.GenerateTokenPair()", "userID", userID)
		return "", "", app_errors.ErrInternalServerError
	}
	session, err := s.JWTService.CreateSession(ctx, userID, refreshToken, userAgent, ClientIP)
	if err != nil {
		s.Logger.Error(err, "JWTService.CreateSession()", "userID", userID, "userAgent", userAgent, "ClientIP", ClientIP)
		return "", "", app_errors.ErrInternalServerError
	}
	err = s.Cache.SaveSession(ctx, session)
	if err != nil {
		s.Logger.Error(err, "RedisCache.SaveSession()", "session", session)
		return "", "", app_errors.ErrInternalServerError
	}
	return accessToken, refreshToken, err
}

func (s *UserAuthServiceImpl) Refresh(ctx context.Context, RefreshToken string, userAgent string, ClientIP string) (AccessToken, NewRefreshToken string, err error) {
	// Validate the refresh token first and extract the session ID and userID
	sessionID, userID, err := s.JWTService.ValidateJWTToken(ctx, RefreshToken)
	if err != nil {
		s.Logger.Error(err, "JWTService.ValidateRefreshToken()", "refreshToken", RefreshToken)
		return "", "", app_errors.ErrRefreshTokenStolen
	}

	// Fetch the session from Redis by session ID
	session, err := s.Cache.GetSessionByID(ctx, sessionID)
	if err != nil {
		s.Logger.Error(err, "RedisCache.GetSessionByID()", "sessionID", sessionID)
		return "", "", app_errors.ErrInternalServerError
	}

	// Check session expiry
	if session.ExpiresAt.Before(time.Now()) {
		s.Logger.Info(app_errors.ErrSessionTimeExpired.Error(), "sessionID", sessionID)
		return "", "", app_errors.ErrSessionTimeExpired
	}

	// Ensure token in session matches provided token
	if session.RefreshToken != RefreshToken {
		s.Logger.Error(app_errors.ErrRefreshTokenStolen, "Refresh token mismatch", "session.RefreshToken", session.RefreshToken, "RefreshToken", RefreshToken)
		return "", "", app_errors.ErrRefreshTokenStolen
	}

	// Confirm UserAgent and ClientIP are consistent with the stored session
	if session.UserAgent != userAgent || session.ClientIP != ClientIP {
		s.Logger.Error(app_errors.ErrRefreshTokenStolen, "UserAgent/ClientIP changed", "session.UserAgent", session.UserAgent, "userAgent", userAgent, "session.ClientIP", session.ClientIP, "ClientIP", ClientIP)
		return "", "", app_errors.ErrRefreshTokenStolen
	}

	// Generate a new token pair for the user
	accessToken, newRefreshToken, err := s.JWTService.GenerateTokenPair(ctx, userID)
	if err != nil {
		s.Logger.Error(err, "JWTService.GenerateTokenPair()", "userID", userID)
		return "", "", app_errors.ErrInternalServerError
	}

	// Create and save a new session for the new refresh token
	newSession, err := s.JWTService.CreateSession(ctx, userID, newRefreshToken, userAgent, ClientIP)
	if err != nil {
		s.Logger.Error(err, "JWTService.CreateSession()", "userID", userID)
		return "", "", app_errors.ErrInternalServerError
	}

	if err := s.Cache.SaveSession(ctx, newSession); err != nil {
		s.Logger.Error(err, "RedisCache.SaveSession()", "session", newSession)
		return "", "", app_errors.ErrInternalServerError
	}

	// Remove the old session (best-effort, but propagate error)
	if err := s.Cache.RemoveSessionByID(ctx, sessionID); err != nil {
		s.Logger.Error(err, "RedisCache.RemoveSessionByID()", "sessionID", sessionID)
		return "", "", app_errors.ErrInternalServerError
	}

	return accessToken, newRefreshToken, nil
}

func (s *UserAuthServiceImpl) Logout(ctx context.Context, sessionID string) error {
	err := s.Cache.RemoveSessionByID(ctx, sessionID)
	if err != nil {
		s.Logger.Error(err, "RedisCache.RemoveSessionByID()", "sessionID", sessionID)
		return app_errors.ErrInternalServerError
	}
	return nil
}
