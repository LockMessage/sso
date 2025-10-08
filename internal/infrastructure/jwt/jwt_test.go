package jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/LockMessage/sso/internal/domain"
	"github.com/LockMessage/sso/internal/domain/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestGenerateTokenPair(t *testing.T) {
	user := models.User{ID: 42, Email: "user@example.com"}
	app := models.App{ID: 7, Secret: "supersecretkey"}
	a := New(15*time.Minute, 24*time.Hour)

	access, refresh, err := a.GenerateTokenPair(user, app)
	require.NoError(t, err)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)

	// Parse and verify access token claims
	parsedA, err := jwt.ParseWithClaims(access, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(app.Secret), nil
	})
	require.NoError(t, err)
	claimsA, ok := parsedA.Claims.(*CustomClaims)
	require.True(t, ok)
	require.Equal(t, int64(42), claimsA.UID)
	require.Equal(t, "access", claimsA.TokenType)
	require.Equal(t, 7, claimsA.AppID)
	require.True(t, parsedA.Valid)

	// Parse and verify refresh token claims
	parsedR, err := jwt.ParseWithClaims(refresh, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(app.Secret), nil
	})
	require.NoError(t, err)
	claimsR, ok := parsedR.Claims.(*CustomClaims)
	require.True(t, ok)
	require.Equal(t, "refresh", claimsR.TokenType)
	require.True(t, parsedR.Valid)
}

func TestDecodeTokenWithVerification_Success(t *testing.T) {
	// Create a simple MapClaims token
	a := New(0, 0)
	secret := "supersecretkey"
	claims := jwt.MapClaims{"foo": "bar", "exp": jwt.NewNumericDate(time.Now().Add(1 * time.Hour)).Unix()}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)

	decoded, err := a.DecodeTokenWithVerification(tokenString, secret)
	require.NoError(t, err)
	require.Equal(t, "bar", decoded["foo"])
}

func TestDecodeTokenWithVerification_Expired(t *testing.T) {
	a := New(1*time.Nanosecond, 1*time.Nanosecond)
	user := models.User{ID: 42, Email: "user@example.com"}
	app := models.App{ID: 7, Secret: "supersecretkey"}
	token, refresh, err := a.GenerateTokenPair(user, app)
	require.NoError(t, err)
	_, err = a.DecodeTokenWithVerification(token, app.Secret)
	assertEqualError(t, domain.ErrTokenExpired, err)

	_, err = a.DecodeTokenWithVerification(refresh, app.Secret)
	assertEqualError(t, domain.ErrTokenExpired, err)
}

func assertEqualError(t *testing.T, expected, actual error) {
	t.Helper()
	if !errors.Is(actual, expected) {
		t.Errorf("Expected %v, got %v", expected, actual)
	}
}
