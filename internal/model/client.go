package model

import "time"

type Client struct {
	ID               string
	ClientSecretHash string
	Name             string
	Status           string
	CreatedAt        time.Time
}

type ClientRedirectURI struct {
	ID          string
	ClientID    string
	RedirectURI string
}
