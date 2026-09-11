package model

import (
	"time"

	"github.com/google/uuid"
)

type FederatedIdentity struct {
	ID              uuid.UUID
	UserID          uuid.UUID
	Provider        string // "google", "github"
	ProviderUserID  string // IdP's sub claim
	EmailAtProvider *string
	CreatedAt       time.Time
}
