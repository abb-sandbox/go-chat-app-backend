package app_errors

import "errors"

var (
	EmailAlreadyExists = errors.New("EMAIL_ALREADY_EXISTS")
	InvalidCredentials = errors.New("INVALID_CREDENTIALS")
	LinkIsExpired      = errors.New("LINK_EXPIRED")
	InvalidCode        = errors.New("INVALID_CODE")
)

// AuthHandler errors
var (
	// Showing that user already exists
	ErrUserAlreadyExists     = errors.New("USER_ALREADY_EXISTS")
	ErrInternalServerError   = errors.New("INTERNAL_SERVER_ERROR")
	ErrActivationTimeExpired = errors.New("ACTIVATION_TIME_EXPIRED")
	ErrCacheMiss             = errors.New("CACHE_MISS")

	// JWTService errors
	ErrExpiredToken       = errors.New("EXPIRED_TOKEN")
	ErrExpiredAccessToken = errors.New("EXPIRED_ACCESS_TOKEN")
	ErrEmptyAuthCreds     = errors.New("EMPTY_AUTH_CREDS")
	ErrExpiredSession     = errors.New("EXPIRED_SESSION")
	// Occurs when a valid refresh token is used from a different user agent or IP
	ErrRefreshTokenStolen = errors.New("REFRESH_TOKEN_STOLEN")
	ErrAccessTokenStolen  = errors.New("ACCESS_TOKEN_STOLEN")
	ErrInvalidJwtToken    = errors.New("INVALID_JWT_TOKEN")
	// For http handlers
	ErrBadRequest   = errors.New("BAD_REQUEST")
	ErrUserNotFound = errors.New("USER_NOT_FOUND")

	// Policy errors
	ErrFilterQueryTooLong = errors.New("FILTER_QUERY_TOO_LONG")

	ErrOrganizationNotFound = errors.New("ORGANIZATION_NOT_FOUND")
	ErrWrongActivationCode  = errors.New("WRONG_ACTIVATION_CODE")
)
