package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/LockMessage/sso/internal/app"
	"github.com/LockMessage/sso/internal/config"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()
	log := setupLogger(cfg.Env)
	log.Info("Starting app",
		slog.String("env", cfg.Env),
		slog.Any("cfg", cfg),
		slog.Int("port", cfg.GRPC.Port),
	)
	application := app.New(log, cfg.GRPC.Port, cfg.StoragePath, cfg.TokenTTL, cfg.TokenRef)
	go application.MustRun()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	application.Stop()
	log.Info("application stopped")
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger
	switch env {
	case envLocal:
		log = slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}
	return log
}
