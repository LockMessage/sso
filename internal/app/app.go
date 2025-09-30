package app

import (
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/LockMessage/sso/internal/deliver/grpc/server"
	"github.com/LockMessage/sso/internal/infrastructure/jwt"
	"github.com/LockMessage/sso/internal/repository/postgres"
	"github.com/LockMessage/sso/internal/usecase/auth"
	"google.golang.org/grpc"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL, refTokenTTL time.Duration) *App {
	gRPCSever := grpc.NewServer()
	storage, err := postgres.New(storagePath)
	jwtAdapter := jwt.New(tokenTTL, refTokenTTL)
	if err != nil {
		panic(err)
	}
	authService := auth.New(log, storage, storage, storage, jwtAdapter)
	server.Register(gRPCSever, authService)
	return &App{log: log, gRPCServer: gRPCSever, port: grpcPort}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"
	log := a.log.With(slog.String("op", op),
		slog.Int("port", a.port),
	)
	log.Info("starting gRPC server")
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	log.Info("grpc server is running", slog.String("addr", l.Addr().String()))
	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.stop"
	a.log.With(slog.String("op", op)).Info("stopping gRPC server", slog.Int("port", a.port))
	a.gRPCServer.GracefulStop()
}
