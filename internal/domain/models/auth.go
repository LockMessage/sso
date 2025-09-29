package models

type RefreshTokenRequest struct {
	AppID        int32
	RefreshToken string
}

type LoginRequest struct {
	AppID    int32
	Email    string
	PassHash string
}

type RegisterRequest struct {
	AppID    int32
	Email    string
	Password string
}

type IsAdminRequest struct {
	UserID int64
}
