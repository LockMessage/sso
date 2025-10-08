package domain

import "errors"

// Common domain errors returned by the SSO service.
// These errors provide standardized error handling across all service layers.

var (

	// ErrTokenExpired indicates that the provided JWT token has expired.
	// Clients should refresh their tokens or re-authenticate when this error occurs.
	ErrTokenExpired = errors.New("token expired")

	// ErrInvalidToken indicates that the provided JWT token is malformed or invalid.
	// This error suggests potential security issues and should be logged appropriately.
	ErrInvalidToken = errors.New("invalid token")

	// ErrUserNotFound indicates that a requested user does not exist in the system.
	// This error is returned by repository methods when querying for non-existent users.
	ErrUserNotFound = errors.New("user not found")

	// ErrUserExists indicates that a user with the same email already exists.
	// This error is returned during user registration when the email is already taken.
	ErrUserExists = errors.New("user already exists")

	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrWrongType           = errors.New("wrong token type")
	ErrAppNotFound         = errors.New("app not found")
	ErrWrongEmailFormat    = errors.New("wrong email format")
	ErrWrongPasswordFormat = errors.New("password should be more than 8 characters")
)
