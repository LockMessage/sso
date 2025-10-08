package jwt

import (
	"testing"
	"time"

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
