package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Webhook event names (spec 5.13).
const (
	EventUserCreated    = "user.created"
	EventUserDisabled   = "user.disabled"
	EventSessionRevoked = "session.revoked"
	EventClientCreated  = "client.created"
	EventClientDisabled = "client.disabled"
)

// WebhookService dispatches HMAC-signed events to registered endpoints
// (spec 5.13, AC-5-9). Deliveries are fire-and-forget on a short timeout so a
// slow or dead receiver never blocks the originating request. now is
// injectable for deterministic tests.
type WebhookService struct {
	pool   *pgxpool.Pool
	client *http.Client
	now    func() time.Time
}

func NewWebhookService(pool *pgxpool.Pool) *WebhookService {
	return &WebhookService{
		pool:   pool,
		client: &http.Client{Timeout: 5 * time.Second},
		now:    time.Now,
	}
}

// SetClock overrides the time source (tests only).
func (w *WebhookService) SetClock(now func() time.Time) { w.now = now }

// webhookRow mirrors auth.webhooks.
type webhookRow struct {
	ID     uuid.UUID
	URL    string
	Secret string
	Events []string
	Status string
}

func (w *WebhookService) matching(ctx context.Context, event string) ([]webhookRow, error) {
	rows, err := w.pool.Query(ctx,
		`SELECT id, url, secret, events, status FROM auth.webhooks WHERE status = 'active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []webhookRow
	for rows.Next() {
		var r webhookRow
		if err := rows.Scan(&r.ID, &r.URL, &r.Secret, &r.Events, &r.Status); err != nil {
			return nil, err
		}
		for _, e := range r.Events {
			if e == event || e == "*" {
				out = append(out, r)
				break
			}
		}
	}
	return out, rows.Err()
}

// Dispatch delivers event to all matching webhooks and returns after the
// deliveries settle. target is the affected resource id (user/client).
func (w *WebhookService) Dispatch(ctx context.Context, event, target string, payload map[string]any) {
	if w == nil || w.pool == nil {
		return
	}
	hooks, err := w.matching(ctx, event)
	if err != nil || len(hooks) == 0 {
		return
	}

	ts := w.now().UTC().Format(time.RFC3339Nano)
	body := map[string]any{
		"event":     event,
		"target":    target,
		"timestamp": ts,
		"data":      payload,
	}
	raw, _ := json.Marshal(body)

	for _, h := range hooks {
		go w.deliver(h, event, ts, raw)
	}
}

func (w *WebhookService) deliver(h webhookRow, event, ts string, raw []byte) {
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(raw))
	if err != nil {
		log.Printf("webhook %s: build request: %v", event, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Zeal-Event", event)
	req.Header.Set("X-Zeal-Timestamp", ts)
	req.Header.Set("X-Zeal-Signature", "sha256="+SignPayload(h.Secret, ts, raw))

	resp, err := w.client.Do(req)
	if err != nil {
		log.Printf("webhook %s → %s: %v", event, h.URL, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("webhook %s → %s: status %d", event, h.URL, resp.StatusCode)
	}
}

// SignPayload computes the HMAC-SHA256 hex signature over "<ts>.<body>",
// exported so receivers (and tests) can verify: sig = HMAC(secret, ts+"."+body).
func SignPayload(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature reports whether sig ("sha256=<hex>") matches the payload.
// Constant-time; used by the receiver-side test helper and documented for
// integrating products.
func VerifySignature(secret, ts string, body []byte, sig string) bool {
	sig = trimPrefix(sig, "sha256=")
	want := SignPayload(secret, ts, body)
	return hmac.Equal([]byte(sig), []byte(want))
}

func trimPrefix(s, p string) string {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}
