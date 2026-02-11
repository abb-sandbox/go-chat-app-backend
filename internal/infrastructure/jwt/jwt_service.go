package jwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/config"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	"github.com/golang-jwt/jwt/v5"
)

type UserClaims struct {
	jwt.RegisteredClaims
}

type JWTService struct {
	secret   []byte
	shortTTL time.Duration
	longTTL  time.Duration
}

// New returns a configured JWTService implementation.
func New(cfg config.Config) *JWTService {
	return &JWTService{
		secret:   []byte(cfg.JWT_SECRET),
		shortTTL: cfg.JWT_SHORT,
		longTTL:  cfg.JWT_LONG,
	}
}

func (j *JWTService) GenerateActivationLink(ctx context.Context) (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("Error while utilizing GenerateActivationLink : %v ", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateTokenPair is FIXED: Uses the SAME Session ID (JTI) for both tokens.
func (j *JWTService) GenerateTokenPair(ctx context.Context, userID string) (string, string, error) {
	// 1. Generate the Session ID (JTI) once
	sessionID, err := newJTI()
	if err != nil {
		return "", "", err
	}

	// --- Access Token Claims ---
	claimsAcc := UserClaims{
		// 2. Use the shared Session ID (JTI)
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionID,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.shortTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsAcc)
	signedAcc, err := at.SignedString(j.secret)
	if err != nil {
		return "", "", err
	}

	// --- Refresh Token Claims ---
	claimsRef := jwt.RegisteredClaims{
		// 3. Use the SAME shared Session ID (JTI)
		ID:        sessionID,
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.longTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	rt := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRef)
	signedRef, err := rt.SignedString(j.secret)
	if err != nil {
		return "", "", err
	}

	return signedAcc, signedRef, nil
}

// CreateSession is CORRECT after fixing GenerateTokenPair.
func (j *JWTService) CreateSession(ctx context.Context, userID string, refreshToken, userAgent, clientIP string) (entities.Session, error) {
	// sessionID (JTI) is now unified.
	sessionID, parsedUserID, err := j.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return entities.Session{}, err
	}
	if parsedUserID != userID {
		return entities.Session{}, errors.New("mismatched userID in refresh token")
	}

	expiresAt := time.Now().Add(j.longTTL)
	session := entities.Session{
		ID:           sessionID, // Correctly using the unified JTI (sessionID)
		UserID:       userID,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		UserAgent:    userAgent,
		ClientIP:     clientIP,
	}
	return session, nil
}

func (j *JWTService) ValidateRefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.secret, nil
	})
	if err != nil {
		return "", "", err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return "", "", errors.New("invalid refresh token")
	}
	userID := claims.Subject

	return claims.ID, userID, nil
}

func (j *JWTService) ValidateAccessToken(ctx context.Context, accessToken string) (string, string, error) {
	token, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.secret, nil
	})
	if err != nil {
		return "", "", err
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return "", "", errors.New("invalid access token")
	}
	// REMOVED: fmt.Println(claims) is debug code and should not be in production.

	userID := claims.Subject

	return claims.ID, userID, nil
}

func newJTI() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("Error while creating new JTI")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
