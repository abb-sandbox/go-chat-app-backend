package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/AzimBB/go-chat-app-backend/internal/config"
	"github.com/AzimBB/go-chat-app-backend/internal/domain/entities"
	app_errors "github.com/AzimBB/go-chat-app-backend/internal/domain/errors"
	"github.com/golang-jwt/jwt/v5"
)

type UserClaims struct {
	UserAgent string
	IP        string
	jwt.RegisteredClaims
}

type JWTService struct {
	privateSecret *ecdsa.PrivateKey
	publicSecret  *ecdsa.PublicKey
	shortTTL      time.Duration
	longTTL       time.Duration
}

// New returns a configured JWTService implementation.
func New(cfg config.Config) *JWTService {
	derBytes, err := hex.DecodeString(cfg.JWT_SECRET)
	if err != nil {
		panic(err)
	}
	privkey, err := x509.ParseECPrivateKey(derBytes)

	return &JWTService{
		privateSecret: privkey,
		publicSecret:  &privkey.PublicKey,
		shortTTL:      cfg.JWT_SHORT,
		longTTL:       cfg.JWT_LONG,
	}
}

func (j *JWTService) GenerateActivationLink(ctx context.Context) (string, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("Error while utilizing GenerateActivationLink : %v ", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateTokenPair is FIXED: Uses the SAME Session ID (JTI) for both tokens.
func (j *JWTService) GenerateTokenPair(ctx context.Context, userID string, userAgent string, ip string) (string, string, error) {
	// 1. Generate the Session ID (JTI) once
	sessionID, err := newJTI()
	if err != nil {
		return "", "", err
	}

	// --- Access Token Claims ---
	claimsAcc := UserClaims{
		UserAgent: userAgent,
		IP:        ip,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        sessionID,
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.shortTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}}
	at := jwt.NewWithClaims(jwt.SigningMethodES256, claimsAcc)
	signedAcc, err := at.SignedString(j.privateSecret)
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
	rt := jwt.NewWithClaims(jwt.SigningMethodES256, claimsRef)
	signedRef, err := rt.SignedString(j.privateSecret)
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
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		UserAgent:    userAgent,
		ClientIP:     clientIP,
	}
	return session, nil
}

// ValidateAccessToken is for validating the access token only with math (because we use HYBRID Stateful JWT Auth)

func (j *JWTService) ValidateAccessToken(ctx context.Context, accessToken string, userAgent string, ip string) (string, string, error) {
	token, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.publicSecret, nil
	})
	if err != nil {
		return "", "", err
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return "", "", app_errors.ErrInvalidJwtToken
	} else if claims.ExpiresAt.Before(time.Now()) {
		return "", "", app_errors.ErrExpiredAccessToken
	} else if userAgent != claims.UserAgent {
		return "", "", app_errors.ErrAccessTokenStolen
	} else if ip != claims.IP {
		return "", "", app_errors.ErrAccessTokenStolen
	}

	return claims.ID, claims.Subject, err
}

func (j *JWTService) ValidateRefreshToken(ctx context.Context, refreshToken string) (string, string, error) {
	token, err := jwt.ParseWithClaims(refreshToken, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.publicSecret, nil
	})
	if err != nil {
		return "", "", err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return "", "", app_errors.ErrInvalidJwtToken
	} else if claims.ExpiresAt.Before(time.Now()) {
		return "", "", app_errors.ErrExpiredSession
	}

	return claims.ID, claims.Subject, err
}

func newJTI() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("Error while creating new JTI")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
