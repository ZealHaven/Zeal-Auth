package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
)

// Ensure FositeStorage implements all required fosite storage interfaces.
var (
	_ fosite.Storage                     = (*FositeStorage)(nil)
	_ fosite.ClientManager               = (*FositeStorage)(nil)
	_ oauth2.CoreStorage                 = (*FositeStorage)(nil)
	_ oauth2.TokenRevocationStorage      = (*FositeStorage)(nil)
	_ pkce.PKCERequestStorage            = (*FositeStorage)(nil)
	_ openid.OpenIDConnectRequestStorage = (*FositeStorage)(nil)
)

// storedRequest is a serializable version of fosite.Request.
type storedRequest struct {
	ID                string                `json:"id"`
	RequestedAt       time.Time             `json:"requested_at"`
	Client            *fosite.DefaultClient `json:"client"`
	RequestedScope    []string              `json:"requested_scope"`
	GrantedScope      []string              `json:"granted_scope"`
	Form              map[string][]string   `json:"form"`
	SessionData       json.RawMessage       `json:"session_data"`
	RequestedAudience []string              `json:"requested_audience"`
	GrantedAudience   []string              `json:"granted_audience"`
	// Invalidated marks a single-use authorize code as redeemed. Kept (not
	// deleted) so fosite can revoke tokens issued from a replayed code.
	Invalidated bool `json:"invalidated,omitempty"`
}

func requestToStored(req fosite.Requester) *storedRequest {
	sr := &storedRequest{
		ID:                req.GetID(),
		RequestedAt:       req.GetRequestedAt(),
		RequestedScope:    []string(req.GetRequestedScopes()),
		GrantedScope:      []string(req.GetGrantedScopes()),
		RequestedAudience: []string(req.GetRequestedAudience()),
		GrantedAudience:   []string(req.GetGrantedAudience()),
	}

	form := req.GetRequestForm()
	sr.Form = make(map[string][]string, len(form))
	for k, v := range form {
		sr.Form[k] = v
	}

	if c := req.GetClient(); c != nil {
		sr.Client = &fosite.DefaultClient{
			ID:            c.GetID(),
			Secret:        c.GetHashedSecret(),
			RedirectURIs:  c.GetRedirectURIs(),
			GrantTypes:    []string(c.GetGrantTypes()),
			ResponseTypes: []string(c.GetResponseTypes()),
			Scopes:        []string(c.GetScopes()),
			Audience:      []string(c.GetAudience()),
			Public:        c.IsPublic(),
		}
	}

	return sr
}

func (sr *storedRequest) toRequest(session fosite.Session) *fosite.Request {
	req := &fosite.Request{
		ID:                sr.ID,
		RequestedAt:       sr.RequestedAt,
		Client:            sr.Client,
		RequestedScope:    fosite.Arguments(sr.RequestedScope),
		GrantedScope:      fosite.Arguments(sr.GrantedScope),
		Form:              make(map[string][]string),
		Session:           session,
		RequestedAudience: fosite.Arguments(sr.RequestedAudience),
		GrantedAudience:   fosite.Arguments(sr.GrantedAudience),
	}
	for k, v := range sr.Form {
		req.Form[k] = v
	}
	if session != nil && len(sr.SessionData) > 0 {
		_ = json.Unmarshal(sr.SessionData, session)
	}
	return req
}

// FositeStorage is a Postgres-backed fosite storage implementation.
type FositeStorage struct {
	db *pgxpool.Pool
}

func NewFositeStorage(db *pgxpool.Pool) *FositeStorage {
	return &FositeStorage{db: db}
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

func (s *FositeStorage) storeRequest(ctx context.Context, key string, req fosite.Requester) error {
	sr := requestToStored(req)
	if req.GetSession() != nil {
		data, err := json.Marshal(req.GetSession())
		if err != nil {
			return fmt.Errorf("marshal session: %w", err)
		}
		sr.SessionData = data
	}
	raw, err := json.Marshal(sr)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	_, err = s.db.Exec(ctx,
		`INSERT INTO auth.fosite_requests (key, data) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET data = $2`,
		key, raw,
	)
	return err
}

func (s *FositeStorage) getRequest(ctx context.Context, key string, session fosite.Session) (*fosite.Request, error) {
	var data []byte
	err := s.db.QueryRow(ctx,
		`SELECT data FROM auth.fosite_requests WHERE key = $1`, key,
	).Scan(&data)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	var sr storedRequest
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if sr.Client == nil {
		sr.Client = &fosite.DefaultClient{}
	}
	return sr.toRequest(session), nil
}

func (s *FositeStorage) deleteRequest(ctx context.Context, key string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM auth.fosite_requests WHERE key = $1`, key)
	return err
}

// ---- ClientManager ----

func (s *FositeStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var secretHash, name, status string
	var createdAt time.Time
	err := s.db.QueryRow(ctx,
		`SELECT client_secret_hash, name, status, created_at FROM auth.clients WHERE id = $1`, id,
	).Scan(&secretHash, &name, &status, &createdAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	if status == "disabled" {
		return nil, fosite.ErrNotFound
	}
	uris, err := s.getRedirectURIs(ctx, id)
	if err != nil {
		return nil, err
	}
	return &fosite.DefaultClient{
		ID:            id,
		Secret:        []byte(secretHash),
		RedirectURIs:  uris,
		GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "profile", "email"},
		Audience:      fosite.Arguments{id},
	}, nil
}

func (s *FositeStorage) getRedirectURIs(ctx context.Context, clientID string) ([]string, error) {
	rows, err := s.db.Query(ctx,
		`SELECT redirect_uri FROM auth.client_redirect_uris WHERE client_id = $1`, clientID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var uris []string
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			return nil, err
		}
		uris = append(uris, uri)
	}
	return uris, rows.Err()
}

func (s *FositeStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM auth.client_assertions WHERE jti = $1)`, jti,
	).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return fosite.ErrNotFound
	}
	return nil
}

func (s *FositeStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	_, err := s.db.Exec(ctx,
		`INSERT INTO auth.client_assertions (jti, expires_at) VALUES ($1, $2)
		 ON CONFLICT (jti) DO NOTHING`, jti, exp,
	)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `DELETE FROM auth.client_assertions WHERE expires_at < now()`)
	return err
}

// ---- RequestStorage ----

func (s *FositeStorage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return s.storeRequest(ctx, "authcode:"+hashToken(code), request)
}

func (s *FositeStorage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	key := "authcode:" + hashToken(code)
	var data []byte
	err := s.db.QueryRow(ctx, `SELECT data FROM auth.fosite_requests WHERE key = $1`, key).Scan(&data)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	var sr storedRequest
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if sr.Client == nil {
		sr.Client = &fosite.DefaultClient{}
	}
	req := sr.toRequest(session)
	if sr.Invalidated {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}
	return req, nil
}

func (s *FositeStorage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	key := "authcode:" + hashToken(code)
	var data []byte
	err := s.db.QueryRow(ctx, `SELECT data FROM auth.fosite_requests WHERE key = $1`, key).Scan(&data)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fosite.ErrNotFound
		}
		return err
	}
	var sr storedRequest
	if err := json.Unmarshal(data, &sr); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	sr.Invalidated = true
	raw, err := json.Marshal(&sr)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	_, err = s.db.Exec(ctx, `UPDATE auth.fosite_requests SET data = $2 WHERE key = $1`, key, raw)
	return err
}

func (s *FositeStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	key := "accesstoken:" + signature
	if err := s.storeRequest(ctx, key, request); err != nil {
		return err
	}
	var expiresAt sql.NullTime
	if sess := request.GetSession(); sess != nil {
		exp := sess.GetExpiresAt(fosite.AccessToken)
		if !exp.IsZero() {
			expiresAt = sql.NullTime{Time: exp, Valid: true}
		}
	}
	_, err := s.db.Exec(ctx,
		`INSERT INTO auth.access_tokens (signature, request_id, expires_at)
		 VALUES ($1, $2, $3) ON CONFLICT (signature) DO NOTHING`,
		signature, request.GetID(), expiresAt,
	)
	return err
}

func (s *FositeStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	var revokedAt sql.NullTime
	err := s.db.QueryRow(ctx,
		`SELECT revoked_at FROM auth.access_tokens WHERE signature = $1`, signature,
	).Scan(&revokedAt)
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if revokedAt.Valid {
		return nil, fosite.ErrNotFound
	}
	return s.getRequest(ctx, "accesstoken:"+signature, session)
}

func (s *FositeStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.deleteRequest(ctx, "accesstoken:"+signature)
}

func (s *FositeStorage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	return s.storeRequest(ctx, "refreshtoken:"+signature, request)
}

func (s *FositeStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	key := "refreshtoken:" + signature
	var data []byte
	err := s.db.QueryRow(ctx, `SELECT data FROM auth.fosite_requests WHERE key = $1`, key).Scan(&data)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	var sr storedRequest
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if sr.Client == nil {
		sr.Client = &fosite.DefaultClient{}
	}
	req := sr.toRequest(session)
	if sr.Invalidated {
		// Rotated away — fosite needs the request for reuse detection
		return req, fosite.ErrInactiveToken
	}
	return req, nil
}

func (s *FositeStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteRequest(ctx, "refreshtoken:"+signature)
}

// RotateRefreshToken marks the old refresh token as rotated. It stays
// retrievable so a replay returns ErrInactiveToken and triggers family revocation.
func (s *FositeStorage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	key := "refreshtoken:" + refreshTokenSignature
	var data []byte
	err := s.db.QueryRow(ctx, `SELECT data FROM auth.fosite_requests WHERE key = $1`, key).Scan(&data)
	if err != nil {
		if err == pgx.ErrNoRows {
			return fosite.ErrNotFound
		}
		return err
	}
	var sr storedRequest
	if err := json.Unmarshal(data, &sr); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	sr.Invalidated = true
	raw, err := json.Marshal(&sr)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	_, err = s.db.Exec(ctx, `UPDATE auth.fosite_requests SET data = $2 WHERE key = $1`, key, raw)
	return err
}

func (s *FositeStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, _ = s.db.Exec(ctx,
		`DELETE FROM auth.fosite_requests WHERE key LIKE 'refreshtoken:%'
		 AND data::jsonb->>'id' = $1`, requestID,
	)
	return nil
}

func (s *FositeStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, _ = s.db.Exec(ctx,
		`UPDATE auth.access_tokens SET revoked_at = now()
		 WHERE request_id = $1 AND revoked_at IS NULL`, requestID,
	)
	_, _ = s.db.Exec(ctx,
		`DELETE FROM auth.fosite_requests WHERE key LIKE 'accesstoken:%'
		 AND data::jsonb->>'id' = $1`, requestID,
	)
	return nil
}

// ---- PKCERequestStorage ----

func (s *FositeStorage) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.storeRequest(ctx, "pkce:"+signature, request)
}

func (s *FositeStorage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getRequest(ctx, "pkce:"+signature, session)
}

func (s *FositeStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.deleteRequest(ctx, "pkce:"+signature)
}

// ---- OpenIDConnectRequestStorage ----

func (s *FositeStorage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) error {
	return s.storeRequest(ctx, "oidcsession:"+hashToken(authorizeCode), request)
}

func (s *FositeStorage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, request fosite.Requester) (fosite.Requester, error) {
	// Hydrate into the caller's session — fosite needs it to issue the ID token
	return s.getRequest(ctx, "oidcsession:"+hashToken(authorizeCode), request.GetSession())
}

func (s *FositeStorage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.deleteRequest(ctx, "oidcsession:"+hashToken(authorizeCode))
}
