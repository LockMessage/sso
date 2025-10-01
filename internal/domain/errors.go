package domain

import "errors"

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrWrongType           = errors.New("wrong token type")
	ErrTokenExpired        = errors.New("token expired")
	ErrInvalidToken        = errors.New("invalid token")
	ErrUserNotFound        = errors.New("user not found")
	ErrUserExists          = errors.New("user already exists")
	ErrAppNotFound         = errors.New("app not found")
	ErrWrongEmailFormat    = errors.New("wrong email format")
	ErrWrongPasswordFormat = errors.New("password should be more than 8 characters")
)
