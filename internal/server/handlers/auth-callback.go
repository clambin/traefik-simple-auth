package handlers

import (
	"github.com/clambin/traefik-simple-auth/internal/server/logging"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"log/slog"
	"net/http"
	"net/url"
)

type AuthCallbackHandler struct {
	Logger        *slog.Logger
	States        *state.Store[string]
	Domains       domains.Domains
	OAuthHandlers map[string]oauth.Handler
	Whitelist     whitelist.Whitelist
	Sessions      *sessions.Sessions
}

func (h *AuthCallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("request received", "request", logging.LoggedRequest{Request: r})

	// Look up the (random) state to find the final destination.
	encodedState := r.URL.Query().Get("state")
	redirectURL, ok := h.States.Get(encodedState)
	if !ok {
		h.Logger.Warn("invalid state. Dropping request ...")
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// we already validated the host vs the domain during the redirect.
	// since the state matches, we can trust the request to be valid.
	u, _ := url.Parse(redirectURL)
	domain, _ := h.Domains.Domain(u)

	// Use the "code" in the response to determine the user's email address.
	user, err := h.OAuthHandlers[domain].GetUserEmailAddress(r.FormValue("code"))
	if err != nil {
		h.Logger.Error("failed to log in", "err", err)
		http.Error(w, "oauth2 failed", http.StatusBadGateway)
		return
	}
	h.Logger.Debug("user authenticated", "user", user)

	// Check that the user's email address is in the whitelist.
	if !h.Whitelist.Match(user) {
		h.Logger.Warn("not a valid user. rejecting ...", "user", user)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	// GetUserEmailAddress successful. Add session cookie and redirect the user to the final destination.
	session := h.Sessions.Session(user)
	http.SetCookie(w, h.Sessions.Cookie(session, domain))

	h.Logger.Info("user logged in. redirecting ...", "user", user, "url", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}
