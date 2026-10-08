package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"

	"github.com/zeal/auth/internal/model"
	"github.com/zeal/auth/internal/repository"
)

var (
	ErrInvalidState      = errors.New("invalid_state")
	ErrAccountLinkNeeded = errors.New("account_link_needed")
	ErrIdPError          = errors.New("idp_error")
	ErrInvalidLinkToken  = errors.New("invalid_link_token")
	ErrLinkEmailMismatch = errors.New("link_email_mismatch")
)

const stateTTL = 10 * time.Minute

type BrokerService struct {
	users      *repository.UserRepository
	federated  *repository.FederatedRepository
	rdb        *redis.Client
	google     *oauth2.Config
	github     *oauth2.Config
	httpClient *http.Client
	// Override URLs for testing
	googleUserInfoURL string
	githubUserURL     string
	githubEmailsURL   string
}

type BrokerDeps struct {
	Users      *repository.UserRepository
	Federated  *repository.FederatedRepository
	RDB        *redis.Client
	Google     *oauth2.Config
	GitHub     *oauth2.Config
	HTTPClient *http.Client
	// Override URLs for testing (empty = production URLs)
	GoogleUserInfoURL string
	GithubUserURL     string
	GithubEmailsURL   string
}

func NewBrokerService(deps BrokerDeps) *BrokerService {
	hc := deps.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &BrokerService{
		users:             deps.Users,
		federated:         deps.Federated,
		rdb:               deps.RDB,
		google:            deps.Google,
		github:            deps.GitHub,
		httpClient:        hc,
		googleUserInfoURL: deps.GoogleUserInfoURL,
		githubUserURL:     deps.GithubUserURL,
		githubEmailsURL:   deps.GithubEmailsURL,
	}
}

// BrokerResult signals the outcome of HandleCallback.
type BrokerResult struct {
	User               *model.User
	ReturnTo           string
	LinkRequired       bool
	LinkProvider       string
	LinkEmail          string
	LinkProviderUserID string
}

func (s *BrokerService) oauthConfig(provider string) (*oauth2.Config, error) {
	switch provider {
	case "google":
		return s.google, nil
	case "github":
		return s.github, nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (s *BrokerService) generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Initiate builds the authorize URL and stores the state → returnTo mapping.
func (s *BrokerService) Initiate(ctx context.Context, provider, returnTo string) (string, string, error) {
	cfg, err := s.oauthConfig(provider)
	if err != nil {
		return "", "", err
	}

	state, err := s.generateState()
	if err != nil {
		return "", "", err
	}

	if err := s.rdb.Set(ctx, "oauth:state:"+state, returnTo, stateTTL).Err(); err != nil {
		return "", "", fmt.Errorf("store state: %w", err)
	}

	authURL := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return authURL, state, nil
}

// HandleCallback exchanges the code, fetches the profile, and links or creates the user.
func (s *BrokerService) HandleCallback(ctx context.Context, provider, code, state string) (*BrokerResult, error) {
	// 1. Validate state (one-time use, CSRF protection)
	returnTo, err := s.rdb.Get(ctx, "oauth:state:"+state).Result()
	if err != nil {
		return nil, ErrInvalidState
	}
	s.rdb.Del(ctx, "oauth:state:"+state)

	cfg, err := s.oauthConfig(provider)
	if err != nil {
		return nil, err
	}

	// 2. Exchange code for token
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdPError, err)
	}

	// 3. Fetch profile from provider
	profile, err := s.fetchProfile(ctx, provider, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIdPError, err)
	}

	// 4. Lookup by (provider, providerUserID)
	existing, err := s.federated.FindByIdentity(ctx, provider, profile.ProviderUserID)
	if err == nil {
		// Found linked user — log in
		user, err := s.users.GetByID(ctx, existing.UserID)
		if err != nil {
			return nil, err
		}
		return &BrokerResult{User: user, ReturnTo: returnTo}, nil
	}
	if !errors.Is(err, repository.ErrFederatedIdentityNotFound) {
		return nil, err
	}

	// 5. Lookup by email
	_, err = s.users.GetByEmail(ctx, profile.Email)
	if err == nil {
		// Existing user, no link for this provider → link required
		return &BrokerResult{
			LinkRequired:       true,
			LinkProvider:       provider,
			LinkEmail:          profile.Email,
			LinkProviderUserID: profile.ProviderUserID,
			ReturnTo:           returnTo,
		}, nil
	}
	if !errors.Is(err, repository.ErrUserNotFound) {
		return nil, err
	}

	// 6. No matching user → create + link
	user, err := s.federated.CreateUserWithoutPassword(ctx, profile.Email)
	if err != nil {
		return nil, err
	}

	if err := s.federated.Link(ctx, user.ID, provider, profile.ProviderUserID, profile.Email); err != nil {
		return nil, err
	}

	return &BrokerResult{User: user, ReturnTo: returnTo}, nil
}

type pendingLink struct {
	Provider       string `json:"provider"`
	ProviderUserID string `json:"provider_user_id"`
	Email          string `json:"email"`
	ReturnTo       string `json:"return_to"`
}

// BeginLink stashes a not-yet-linked provider identity so the link-account
// form can complete it after password re-authentication.
func (s *BrokerService) BeginLink(ctx context.Context, provider, providerUserID, email, returnTo string) (string, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(pendingLink{
		Provider:       provider,
		ProviderUserID: providerUserID,
		Email:          email,
		ReturnTo:       returnTo,
	})
	if err != nil {
		return "", err
	}
	if err := s.rdb.Set(ctx, "oauth:pending:"+token, data, stateTTL).Err(); err != nil {
		return "", fmt.Errorf("store pending link: %w", err)
	}
	return token, nil
}

// CompleteLink verifies password-login identity matches the pending link,
// links the provider identity, and returns the original returnTo.
func (s *BrokerService) CompleteLink(ctx context.Context, token string, user *model.User) (string, error) {
	data, err := s.rdb.Get(ctx, "oauth:pending:"+token).Result()
	if err != nil {
		return "", ErrInvalidLinkToken
	}
	s.rdb.Del(ctx, "oauth:pending:"+token)

	var p pendingLink
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return "", ErrInvalidLinkToken
	}
	if !strings.EqualFold(user.Email, p.Email) {
		return "", ErrLinkEmailMismatch
	}
	if err := s.federated.Link(ctx, user.ID, p.Provider, p.ProviderUserID, p.Email); err != nil {
		return "", err
	}
	return p.ReturnTo, nil
}

// LinkIdentity links a provider identity to an existing user after authentication.
func (s *BrokerService) LinkIdentity(ctx context.Context, userID uuid.UUID, provider, providerUserID, email string) error {
	return s.federated.Link(ctx, userID, provider, providerUserID, email)
}

type normalizedProfile struct {
	Email          string
	ProviderUserID string
	Name           string
	EmailVerified  bool
}

func (s *BrokerService) fetchProfile(ctx context.Context, provider string, token *oauth2.Token) (*normalizedProfile, error) {
	switch provider {
	case "google":
		return s.fetchGoogleProfile(ctx, token)
	case "github":
		return s.fetchGitHubProfile(ctx, token)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (s *BrokerService) fetchGoogleProfile(ctx context.Context, token *oauth2.Token) (*normalizedProfile, error) {
	url := s.googleUserInfoURL
	if url == "" {
		url = "https://www.googleapis.com/oauth2/v2/userinfo"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google userinfo %d: %s", resp.StatusCode, body)
	}

	var data struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Name     string `json:"name"`
		Verified bool   `json:"verified_email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &normalizedProfile{
		Email:          strings.ToLower(data.Email),
		ProviderUserID: data.ID,
		Name:           data.Name,
		EmailVerified:  data.Verified,
	}, nil
}

func (s *BrokerService) fetchGitHubProfile(ctx context.Context, token *oauth2.Token) (*normalizedProfile, error) {
	// Fetch user
	userURL := s.githubUserURL
	if userURL == "" {
		userURL = "https://api.github.com/user"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github user %d: %s", resp.StatusCode, body)
	}

	var userData struct {
		ID    int    `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		return nil, err
	}

	// Fetch primary email
	emailsURL := s.githubEmailsURL
	if emailsURL == "" {
		emailsURL = "https://api.github.com/user/emails"
	}
	req, err = http.NewRequestWithContext(ctx, "GET", emailsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err = s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github emails %d: %s", resp.StatusCode, body)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return nil, err
	}

	var primaryEmail string
	var emailVerified bool
	for _, e := range emails {
		if e.Primary {
			primaryEmail = e.Email
			emailVerified = e.Verified
			break
		}
	}
	if primaryEmail == "" && len(emails) > 0 {
		primaryEmail = emails[0].Email
		emailVerified = emails[0].Verified
	}

	name := userData.Name
	if name == "" {
		name = userData.Login
	}

	providerUserID := fmt.Sprintf("%d", userData.ID)

	return &normalizedProfile{
		Email:          strings.ToLower(primaryEmail),
		ProviderUserID: providerUserID,
		Name:           name,
		EmailVerified:  emailVerified,
	}, nil
}
