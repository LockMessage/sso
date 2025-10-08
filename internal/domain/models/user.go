package models

import (
	"time"
)

// User represents a user entity in the SSO system.
// A User contains authentication credentials and profile information
// required for the single sign-on process.
//
// The zero value for User is not useful and should not be used directly.
// Users should be created through the authentication service.
type User struct {
	// ID is the unique identifier for the user in the system.
	ID int64

	// Email is the user's email address used for authentication.
	// This field is required and must be unique across the system.
	Email string

	// PassHash contains the bcrypt hash of the user's password.
	// The original password is never stored in plain text.
	PassHash []byte

	// IsAdmin indicates whether the user has administrative privileges.
	// Admin users can access restricted endpoints and perform system operations.
	IsAdmin bool
	// CreatedAt is the timestamp when the user account was created.
	CreatedAt time.Time

	// UpdatedAt is the timestamp of the last user profile update.
	UpdatedAt time.Time
}
