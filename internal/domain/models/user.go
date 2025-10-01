package models

import (
	"time"
)

type User struct {
	ID        int64
	Email     string
	PassHash  []byte
	IsAdmin   bool
	CreatedAt time.Time
	UpdatedAt time.Time
}
