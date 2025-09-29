package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/LockMessage/sso/internal/domain"
	"github.com/LockMessage/sso/internal/domain/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "repository.postgres.SaveUser"

	var id int64
	err := s.db.QueryRow(ctx, "INSERT INTO users(email, pass_hash) VALUES ($1, $2) RETURNING id", email, passHash).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return 0, fmt.Errorf("%s: %w", op, domain.ErrUserExists, err)
		}
		return 0, fmt.Errorf("%s: %w", op, err)
	}
	return id, nil

}

func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "repository.postgres.User"
	var user models.User

	err := s.db.QueryRow(ctx, "SELECT id, email, pass_hash FROM users WHERE email = $1", email).Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %w", op, domain.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, nil
}

func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "repository.postgres.IsAdmin"

	var isAdmin bool

	err := s.db.QueryRow(ctx, "SELECT is_admin FROM users WHERE id = $1", userID).Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("%s: %w", op, domain.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	return isAdmin, nil
}
