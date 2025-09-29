package jwt

import (
	"fmt"
	"time"

	"github.com/LockMessage/sso/internal/domain"
	"github.com/LockMessage/sso/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type CustomClaims struct {
	UID       int64  `json:"uid"`
	Email     string `json:"email"`
	TokenType string `json:"type"` // "access" or "refresh"
	AppID     int    `json:"app_id"`
	jwt.RegisteredClaims
}

func RenewAccessToken(oldRefresh string, user models.User, app models.App, TokenTTL time.Duration) (string, error) {
	parsed, err := jwt.ParseWithClaims(
		oldRefresh,
		&CustomClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodHS256 {
				return nil, domain.ErrInvalidToken
			}
			return []byte(app.Secret), nil
		},
	)
	if err != nil {
		return "", domain.ErrInvalidToken
	}

	claims, ok := parsed.Claims.(*CustomClaims)
	if !ok || !parsed.Valid {
		return "", domain.ErrInvalidToken
	}

	if claims.TokenType != "refresh" {
		return "", domain.ErrWrongType
	}

	if claims.ExpiresAt.Time.Before(time.Now().UTC()) {
		return "", domain.ErrTokenExpired
	}

	refresh, err := GenerateToken("access", user, app, TokenTTL)
	if err != nil {
		return "", err
	}

	return refresh, nil
}

func GenerateToken(tokenType string, user models.User, app models.App, tokenTTL time.Duration) (string, error) {
	claims := CustomClaims{
		UID:       user.ID,
		Email:     user.Email,
		TokenType: tokenType,
		AppID:     app.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			ID:        uuid.NewString(),
		},
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().UTC().Add(tokenTTL))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}
	return token, nil
}

func GenerateTokenPair(user models.User, app models.App, tokenTTL, refTokenTTL time.Duration) (access, refresh string, err error) {

	access, err = GenerateToken("access", user, app, tokenTTL)

	if err != nil {
		return "", "", err
	}
	refresh, err = GenerateToken("refresh", user, app, tokenTTL)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

func DecodeTokenWithVerification(tokenString, secretKey string) (jwt.MapClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token: %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}
