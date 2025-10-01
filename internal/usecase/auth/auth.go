package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/LockMessage/sso/internal/domain"
	"github.com/LockMessage/sso/internal/domain/models"
	"github.com/LockMessage/sso/internal/domain/rules/validation"
	"github.com/LockMessage/sso/internal/infrastructure/logger/sl"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	logger      *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	jwtAdapter  JwtAdapter
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uid int64, err error)
}

type UserProvider interface {
	FindByEmail(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int32) (models.App, error)
}

type JwtAdapter interface {
	RenewAccessToken(oldRefresh string, user models.User, app models.App) (string, error)
	GenerateTokenPair(user models.User, app models.App) (access, refresh string, err error)
	DecodeTokenWithVerification(tokenString, secretKey string) (map[string]any, error)
}

func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	jwtAdapter JwtAdapter,
) *Auth {

	return &Auth{
		logger:      log,
		usrSaver:    userSaver,
		usrProvider: userProvider,
		appProvider: appProvider,
		jwtAdapter:  jwtAdapter,
	}
}

func (a *Auth) RefreshToken(ctx context.Context, req models.RefreshTokenRequest) (string, error) {
	const op = "auth.RefreshToken"
	log := a.logger.With(
		slog.String("op", op),
	)
	log.Info("attempting to renew token")
	app, err := a.appProvider.App(ctx, req.AppID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	claims, err := a.jwtAdapter.DecodeTokenWithVerification(req.RefreshToken, app.Secret)
	if err != nil {
		a.logger.Error("failed to decode token", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, domain.ErrInvalidToken)
	}
	user, err := a.usrProvider.FindByEmail(ctx, claims["email"].(string))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			a.logger.Warn("user not found", sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		a.logger.Error("failed to get user", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	newToken, err := a.jwtAdapter.RenewAccessToken(req.RefreshToken, user, app)
	if err != nil {
		a.logger.Error("failed to renew token user", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return newToken, nil
}

func (a *Auth) Login(ctx context.Context, req models.LoginRequest) (string, string, error) {
	const op = "auth.Login"
	log := a.logger.With(
		slog.String("op", op),
	)
	log.Info("attempting to login user")
	user, err := a.usrProvider.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			a.logger.Warn("user not found", sl.Err(err))
			return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		a.logger.Error("failed to get user", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(req.PassHash)); err != nil {
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
	app, err := a.appProvider.App(ctx, req.AppID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user logged successfully")
	token, refToken, err := a.jwtAdapter.GenerateTokenPair(user, app)
	if err != nil {
		a.logger.Error("failed to generate token", sl.Err(err))
		return "", "", fmt.Errorf("%s: %w", op, err)
	}
	return token, refToken, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, req models.RegisterRequest) (int64, error) {
	const op = "auth.RegisterNewUser"
	log := a.logger.With(
		slog.String("op", op),
	)
	log.Info("registering user")
	if err := validation.ValidateEmail(req.Email); err != nil {
		return 0, fmt.Errorf("%s: %w", op, domain.ErrWrongEmailFormat)
	}
	if err := validation.ValidatePassword(req.Password); err != nil {
		return 0, fmt.Errorf("%s: %w", op, domain.ErrWrongPasswordFormat)
	}
	_, err := a.usrProvider.FindByEmail(ctx, req.Email)
	if !errors.Is(err, domain.ErrUserNotFound) {
		log.Error("err", err)
		return 0, fmt.Errorf("%s: %w", op, domain.ErrUserExists)
	}
	passHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	id, err := a.usrSaver.SaveUser(ctx, req.Email, passHash)
	if err != nil {
		log.Error("failed to save user", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user registered")
	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, req models.IsAdminRequest) (bool, error) {
	const op = "Auth.IsAdmin"

	log := a.logger.With(
		slog.String("op", op),
		slog.Int64("user_id", req.UserID),
	)

	log.Info("checking if user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, req.UserID)
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))

	return isAdmin, nil
}
