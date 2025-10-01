package server

import (
	"context"
	"errors"

	ssov1 "github.com/LockMessage/protos/golang/sso"
	"github.com/LockMessage/sso/internal/domain"
	"github.com/LockMessage/sso/internal/domain/models"
	"github.com/LockMessage/sso/internal/usecase/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(ctx context.Context, req models.LoginRequest) (token string, refToken string, err error)
	RegisterNewUser(ctx context.Context, req models.RegisterRequest) (userID int64, err error)
	IsAdmin(ctx context.Context, req models.IsAdminRequest) (bool, error)
	RefreshToken(ctx context.Context, req models.RefreshTokenRequest) (string, error)
}

type serverAPI struct {
	ssov1.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

const emptyValue = 0

func (s *serverAPI) RefreshToken(ctx context.Context, req *ssov1.RefreshTokenRequest) (*ssov1.RefreshTokenResponse, error) {
	if req.GetAppId() == emptyValue {
		return nil, status.Errorf(codes.InvalidArgument, "app_id is required")
	}
	if req.GetRefreshToken() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token is required")
	}
	domainReq := models.RefreshTokenRequest{AppID: req.GetAppId(), RefreshToken: req.GetRefreshToken()}
	token, err := s.auth.RefreshToken(ctx, domainReq)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidToken) || errors.Is(err, domain.ErrTokenExpired) {
			return nil, status.Error(codes.InvalidArgument, "invalid or expired token")
		}
		if errors.Is(err, domain.ErrWrongType) {
			return nil, status.Error(codes.InvalidArgument, "token is not a refresh token")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.RefreshTokenResponse{AccessToken: token}, nil
}

func (s *serverAPI) Login(ctx context.Context, req *ssov1.LoginRequest) (*ssov1.LoginResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "password is required")
	}
	if req.GetAppId() == emptyValue {
		return nil, status.Errorf(codes.InvalidArgument, "app_id is required")
	}

	domainReq := models.LoginRequest{AppID: req.GetAppId(), Email: req.GetEmail(), PassHash: req.GetPassword()}
	token, refToken, err := s.auth.Login(ctx, domainReq)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid email or password")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &ssov1.LoginResponse{Token: token, RefreshToken: refToken}, nil
}

func (s *serverAPI) Register(ctx context.Context, req *ssov1.RegisterRequest) (*ssov1.RegisterResponse, error) {
	if req.GetEmail() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "password is required")
	}
	domainReq := models.RegisterRequest{Email: req.GetEmail(), Password: req.GetPassword()}
	userID, err := s.auth.RegisterNewUser(ctx, domainReq)
	if err != nil {
		if errors.Is(err, domain.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		if errors.Is(err, domain.ErrWrongEmailFormat) {
			return nil, status.Error(codes.InvalidArgument, "wrong email format")
		}
		if errors.Is(err, domain.ErrWrongPasswordFormat) {
			return nil, status.Error(codes.InvalidArgument, domain.ErrWrongPasswordFormat.Error())
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.RegisterResponse{UserId: userID}, nil
}
func (s *serverAPI) IsAdmin(ctx context.Context, req *ssov1.IsAdminRequest) (*ssov1.IsAdminResponse, error) {
	if req.GetUserId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	domainReq := models.IsAdminRequest{UserID: req.GetUserId()}
	isAdmin, err := s.auth.IsAdmin(ctx, domainReq)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &ssov1.IsAdminResponse{IsAdmin: isAdmin}, nil
}
