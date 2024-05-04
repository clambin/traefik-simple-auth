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

// The AuthCallbackHandler implements the oauth callback, initiated by ForwardAuthHandler's redirectToAuth method.
// It validates that the request came from us (by checking the state parameter), determines the user's email address,
// checks that that user is on the whitelist, creates a session Cookie for the user and redirects the user to the
// target that originally initiated the oauth flow.
func AuthCallbackHandler(
	domains domains.Domains,
	whitelist whitelist.Whitelist,
	oauthHandlers map[domains.Domain]oauth.Handler,
	states *state.States[string],
	sessions *sessions.Sessions,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", logging.Request(r))

		// Look up the (random) state to find the final destination.
		encodedState := r.URL.Query().Get("state")
		targetURL, ok := states.Get(encodedState)
		if !ok {
			logger.Warn("invalid state. Dropping request ...")
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		// we already validated the host vs the domain during the redirect.
		// since the state matches, we can trust the request to be valid.
		u, _ := url.Parse(targetURL)
		domain, _ := domains.Domain(u)

		// Use the "code" in the response to determine the user's email address.
		user, err := oauthHandlers[domain].GetUserEmailAddress(r.Context(), r.FormValue("code"))
		if err != nil {
			logger.Error("failed to log in", "err", err)
			http.Error(w, "oauth2 failed", http.StatusBadGateway)
			return
		}
		logger.Debug("user authenticated", "user", user)

		// Check that the user's email address is in the whitelist.
		if !whitelist.Match(user) {
			logger.Warn("not a valid user. rejecting ...", "user", user)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// GetUserEmailAddress successful. Add session cookie and redirect the user to the final destination.
		session := sessions.Session(user)
		http.SetCookie(w, sessions.Cookie(session, domain))

		logger.Info("user logged in. redirecting ...", "user", user, "url", targetURL)
		http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
	})
}
