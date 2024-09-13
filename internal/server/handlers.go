package server

import (
	"encoding/json"
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/server/logging"
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"net/url"
)

// The ForwardAuthHandler implements the authentication flow for traefik's forwardAuth middleware.  It checks that the request
// has a valid session (stored in a http.Cookie). If so, it returns http.StatusOK.   If not, it redirects the request
// to the configured oauth provider to log in.  After login, the request is routed to the AuthCallbackHandler, which
// forwards the request to the originally requested destination.
func ForwardAuthHandler(domains domains.Domains, oauthHandlers map[domains.Domain]oauth.Handler, states state.States, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", logging.Request(r))

		// check that the request is for one of the configured domains
		domain, ok := domains.Domain(r.URL)
		if !ok {
			logger.Warn("host doesn't match any configured domains", slog.String("host", r.URL.Host))
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// validate that the request has a valid session cookie
		session, err := getSession(r)
		if err == nil {
			logger.Debug("allowing valid request", slog.String("email", session.Key))
			w.Header().Set("X-Forwarded-User", session.Key)
			w.WriteHeader(http.StatusOK)
			return
		}

		// no valid session cookie found. redirect to oauth handler.
		logger.Warn("redirecting: no valid session found", slog.String("url", r.URL.String()), slog.String("email", session.Key), slog.Any("err", err))

		// To protect against CSRF attacks, we generate a random state and associate it with the final destination of the request.
		// authCallbackHandler uses the random state to retrieve the final destination, thereby validating that the request came from us.
		encodedState, err := states.Add(r.Context(), r.URL.String())
		if err != nil {
			logger.Warn("error adding state", slog.String("error", err.Error()))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Redirect the user to the oauth2 provider to select the account to authenticate the request.
		authCodeURL := oauthHandlers[domain].AuthCodeURL(encodedState, oauth2.SetAuthURLParam("prompt", "select_account"))
		logger.Debug("redirecting", slog.String("authCodeURL", authCodeURL))
		// TODO: possible clear the session cookie, so it's removed from the user's browser?
		http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
	})
}

// LogoutHandler logs out the user: it removes the session from the session store and sends an empty Cookie to the user.
// This means that the user's next request has an invalid cookie, triggering a new oauth flow.
func LogoutHandler(domains domains.Domains, sessionStore sessions.Sessions, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", logging.Request(r))

		// remove the cached cookie
		session, err := getSession(r)
		if err != nil {
			logger.Warn("rejecting: no valid session found", slog.String("url", r.URL.String()), slog.String("email", session.Key), slog.Any("err", err))
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// delete the session
		sessionStore.DeleteSession(session)

		// Write a blank session cookie to override the current valid one.
		domain, _ := domains.Domain(r.URL)
		http.SetCookie(w, sessionStore.Cookie(sessions.Session{}, string(domain)))

		http.Error(w, "You have been logged out", http.StatusUnauthorized)
		logger.Info("user has been logged out", "user", session.Key)
	})
}

// The AuthCallbackHandler implements the oauth callback, initiated by ForwardAuthHandler's redirectToAuth method.
// It validates that the request came from us (by checking the state parameter), determines the user's email address,
// checks that that user is on the whitelist, creates a session Cookie for the user and redirects the user to the
// target that originally initiated the oauth flow.
func AuthCallbackHandler(
	domains domains.Domains,
	whitelist whitelist.Whitelist,
	oauthHandlers map[domains.Domain]oauth.Handler,
	states state.States,
	sessions sessions.Sessions,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", logging.Request(r))

		// Look up the (random) state. This tells us that the request is valid and where to forward the request to.
		encodedState := r.URL.Query().Get("state")
		targetURL, err := states.Validate(r.Context(), encodedState)
		if err != nil {
			logger.Warn("rejecting login request: invalid state", "err", err)
			http.Error(w, "Invalid state", http.StatusUnauthorized)
			return
		}

		// We already validated the host vs. the domain during the redirect.
		// Since the state matches, we can trust the request to be valid.
		u, _ := url.Parse(targetURL)
		domain, _ := domains.Domain(u)

		// Use the "code" in the response to determine the user's email address.
		user, err := oauthHandlers[domain].GetUserEmailAddress(r.Context(), r.FormValue("code"))
		if err != nil {
			var oauthErr *oauth2.RetrieveError
			if errors.As(err, &oauthErr) {
				logger.Warn("rejecting login request: failed to retrieve code", "code", oauthErr.ErrorCode, "desc", oauthErr.ErrorDescription)
				http.Error(w, "Invalid code", http.StatusUnauthorized)
				return
			}
			logger.Error("rejecting login request: failed to log in", "err", err)
			http.Error(w, "oauth2 failed", http.StatusBadGateway)
			return
		}
		logger.Debug("user authenticated", "user", user)

		// Check that the user's email address is in the whitelist.
		if !whitelist.Match(user) {
			logger.Warn("rejecting login request: not a valid user", "user", user)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// GetUserEmailAddress successful. Create a session and redirect the user to the final destination.
		logger.Info("user logged in", "user", user, "url", targetURL)
		session := sessions.NewSession(user)
		http.SetCookie(w, sessions.Cookie(session, string(domain)))
		http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
	})
}

func HealthHandler(sessions sessions.Sessions, states state.States, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := states.Ping(r.Context()); err != nil {
			logger.Warn("cache ping failed", "err", err)
			http.Error(w, "state cache not healthy", http.StatusServiceUnavailable)
			return
		}

		stateCount, err := states.Count(r.Context())
		if err != nil {
			logger.Warn("error counting states", "err", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		health := struct {
			Sessions int `json:"sessions"`
			States   int `json:"states"`
		}{
			Sessions: sessions.Count(),
			States:   stateCount,
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(health)
	})
}
