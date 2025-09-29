package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/LockMessage/sso/internal/domain"
	"github.com/LockMessage/sso/internal/domain/models"
	"github.com/jackc/pgx/v5"
)

func (s *Storage) App(ctx context.Context, id int32) (models.App, error) {
	const op = "repository.postgres.App"

	var app models.App

	err := s.db.QueryRow(ctx, "SELECT id, name, secret FROM apps WHERE id = $1", id).Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %w", op, domain.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %w", op, err)
	}

	return app, nil
}
