package models

import (
	"errors"

	"github.com/LockMessage/sso/internal/domain/rules/validation"
)

type User struct {
	ID       int64
	Email    string
	PassHash []byte
}

func NewUser(id int64, email string, passHash []byte) (*User, error) {
	if !validation.ValidateEmail(email) {
		return nil, errors.New("invalid email")
	}
	return &User{ID: id, Email: email, PassHash: passHash}, nil
}
