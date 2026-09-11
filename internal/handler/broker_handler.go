package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/zeal/auth/internal/service"
)

type BrokerHandler struct {
	broker *service.BrokerService
}

func NewBrokerHandler(broker *service.BrokerService) *BrokerHandler {
	return &BrokerHandler{broker: broker}
}

func (h *BrokerHandler) GoogleInitiate(w http.ResponseWriter, r *http.Request) {
	h.initiate(w, r, "google")
}

func (h *BrokerHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	h.callback(w, r, "google")
}

func (h *BrokerHandler) GitHubInitiate(w http.ResponseWriter, r *http.Request) {
	h.initiate(w, r, "github")
}

func (h *BrokerHandler) GitHubCallback(w http.ResponseWriter, r *http.Request) {
	h.callback(w, r, "github")
}

func (h *BrokerHandler) initiate(w http.ResponseWriter, r *http.Request, provider string) {
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	authURL, _, err := h.broker.Initiate(r.Context(), provider, returnTo)
	if err != nil {
		http.Error(w, "Failed to initiate OAuth", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (h *BrokerHandler) callback(w http.ResponseWriter, r *http.Request, provider string) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		http.Redirect(w, r, "/login?error=missing_params", http.StatusTemporaryRedirect)
		return
	}

	result, err := h.broker.HandleCallback(r.Context(), provider, code, state)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidState):
			http.Redirect(w, r, "/login?error=invalid_state", http.StatusTemporaryRedirect)
		case errors.Is(err, service.ErrIdPError):
			http.Redirect(w, r, "/login?error=idp_error", http.StatusTemporaryRedirect)
		default:
			http.Redirect(w, r, "/login?error=internal_error", http.StatusTemporaryRedirect)
		}
		return
	}

	if result.LinkRequired {
		http.Redirect(w, r, "/link-account?provider="+result.LinkProvider+"&email="+result.LinkEmail, http.StatusTemporaryRedirect)
		return
	}

	// Success: write JSON response for API callers, or set session cookie
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"message": "Login successful",
		"user_id": result.User.ID.String(),
	})
}
