package model

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID            uuid.UUID
	Email         string
	PasswordHash  *string
	EmailVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	// spec 5 (000003)
	Role        string
	DisabledAt  *time.Time
	TOTPSecret  *string
	TOTPEnabled bool
}
