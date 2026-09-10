package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/zeal/auth/internal/model"
	"github.com/zeal/auth/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid_credentials")
	ErrEmailNotVerified   = errors.New("email_not_verified")
	ErrSocialAccountOnly  = errors.New("social_account_only")
	ErrEmailAlreadyExists = errors.New("email_already_exists")
	ErrInvalidEmail       = errors.New("invalid_email")
	ErrPasswordTooShort   = errors.New("password_too_short")
)

type AuthService struct {
	users *repository.UserRepository
}

func NewAuthService(users *repository.UserRepository) *AuthService {
	return &AuthService{users: users}
}

type SignupResult struct {
	User *model.User
}

func (s *AuthService) Signup(ctx context.Context, email, password string) (*SignupResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))

	if _, err := mail.ParseAddress(email); err != nil {
		return nil, ErrInvalidEmail
	}

	if len(password) < 8 {
		return nil, ErrPasswordTooShort
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	hashStr := string(hash)

	user, err := s.users.Create(ctx, email, hashStr)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicateEmail) {
			return nil, ErrEmailAlreadyExists
		}
		return nil, err
	}

	return &SignupResult{User: user}, nil
}

type LoginResult struct {
	User *model.User
}

func (s *AuthService) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	email = strings.TrimSpace(strings.ToLower(email))

	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.PasswordHash == nil {
		return nil, ErrSocialAccountOnly
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	return &LoginResult{User: user}, nil
}
