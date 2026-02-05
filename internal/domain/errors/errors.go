package app_errors

import "errors"

var (
	EmailAlreadyExists = errors.New("email already exists")
	InvalidCredentials = errors.New("invalid credentials")
	LinkIsExpired      = errors.New("link is expired")
	InvalidCode        = errors.New("invalid code")
)

// AuthHandler errors
var (
	// Showing that user already exists
	ErrUserAlreadyExists     = errors.New("user already exists")
	ErrInternalServerError   = errors.New("internal server error")
	ErrActivationTimeExpired = errors.New("activation time is expired")
	// Occurs when a valid refresh token is used from a different user agent or IP
	ErrRefreshTokenIsStolen = errors.New("refresh token is stolen")
	// Session has already expired
	ErrSessionTimeExpired = errors.New("session time expired")
	// For http handlers
	ErrBadRequest   = errors.New("bad request")
	ErrUserNotFound = errors.New("user not found")

	// Policy errors
	ErrFilterQueryIsTooLong = errors.New("filter query is too long")

	ErrOrganizationNotFound = errors.New("organization not found")
	ErrWrongActivationCode  = errors.New("wrong activation code")
)
