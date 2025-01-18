package server

import (
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"github.com/clambin/traefik-simple-auth/internal/domain"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
)

// The ForwardAuthHandler implements the authentication flow for traefik's forwardAuth middleware.  It checks that the request
// has a valid cookie (stored in a http.Cookie). If so, it returns http.StatusOK.   If not, it redirects the request
// to the configured oauth provider to log in.  After login, the request is routed to the AuthCallbackHandler, which
// forwards the request to the originally requested destination.
func ForwardAuthHandler(domain domain.Domain, oauthHandler oauth.Handler, states state.States, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", (*request)(r))

		// check that the request is for one of the configured domains
		if !domain.Matches(r.URL) {
			logger.Warn("host doesn't match any configured domains", "host", r.URL.Host)
			http.Error(w, "Forbidden: invalid domain", http.StatusForbidden)
			return
		}

		// validate that the request has a valid JWT cookie
		email, err := getAuthenticatedUserEmail(r)
		if err == nil {
			logger.Debug("allowing valid request", "email", email)
			w.Header().Set("X-Forwarded-User", email)
			w.WriteHeader(http.StatusOK)
			return
		}

		// no valid JWT cookie found. redirect to oauth handler.
		logger.Warn("redirecting: no valid cookie found",
			"request", (*rejectedRequest)(r),
			"err", err,
		)

		// To protect against CSRF attacks, we generate a random state and associate it with the final destination of the request.
		// authCallbackHandler uses the random state to retrieve the final destination, thereby validating that the request came from us.
		encodedState, err := states.Add(r.Context(), r.URL.String())
		if err != nil {
			logger.Warn("error adding state", "err", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Redirect the user to the oauth2 provider to select the account to authenticate the request.
		authCodeURL := oauthHandler.AuthCodeURL(encodedState, oauth2.SetAuthURLParam("prompt", "select_account"))
		logger.Debug("redirecting", "authCodeURL", authCodeURL)
		// TODO: possible clear the cookie, so it's removed from the user's browser?
		http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
	})
}

// LogoutHandler logs out the user: it removes the cookie from the cookie store and sends an empty Cookie to the user.
// This means that the user's next request has an invalid cookie, triggering a new oauth flow.
func LogoutHandler(domain domain.Domain, authenticator *auth.Authenticator, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", (*request)(r))

		// validate that the request has a valid JWT cookie
		email, err := getAuthenticatedUserEmail(r)
		if err != nil {
			logger.Warn("rejecting: no valid cookie found",
				"request", (*request)(r),
				"err", err,
			)
			http.Error(w, "Invalid cookie", http.StatusUnauthorized)
			return
		}

		// Write a blank cookie to override/clear the current valid one.
		http.SetCookie(w, authenticator.Cookie("", 0, string(domain)))

		logger.Info("user has been logged out", "user", email)
		http.Error(w, "You have been logged out", http.StatusUnauthorized)
	})
}

// The AuthCallbackHandler implements the oauth callback, initiated by ForwardAuthHandler's redirectToAuth method.
// It validates that the request came from us (by checking the state parameter), determines the user's email address,
// checks that that user is on the whitelist, creates a JWT Cookie for the user and redirects the user to the
// target that originally initiated the oauth flow.
func AuthCallbackHandler(
	domain domain.Domain,
	whitelist whitelist.Whitelist,
	oauthHandler oauth.Handler,
	states state.States,
	authenticator *auth.Authenticator,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", (*request)(r))

		// Look up the (random) state. This tells us that the request is valid and where to forward the request to.
		encodedState := r.URL.Query().Get("state")
		targetURL, err := states.Validate(r.Context(), encodedState)
		if err != nil {
			logger.Warn("rejecting login request: invalid state",
				"request", (*request)(r),
				"err", err,
			)
			http.Error(w, "Invalid state", http.StatusUnauthorized)
			return
		}

		// We already validated the host vs. the domain during the redirect.
		// Since the state matches, we can trust the request to be valid.

		// Use the "code" in the response to determine the user's email address.
		user, err := oauthHandler.GetUserEmailAddress(r.Context(), r.FormValue("code"))
		if err != nil {
			var oauthErr *oauth2.RetrieveError
			if errors.As(err, &oauthErr) {
				logger.Warn("rejecting login request: failed to retrieve code",
					"code", oauthErr.ErrorCode,
					"desc", oauthErr.ErrorDescription,
				)
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

		// Valid user. Create a cookie and redirect the user to the final destination.
		logger.Info("user logged in", "user", user, "url", targetURL)
		c, _ := authenticator.CookieWithSignedToken(user, string(domain))
		logger.Debug("sending cookie to user", "user", user, "cookie", c)
		http.SetCookie(w, c)
		http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
	})
}

// The HealthHandler checks that traefik-simple-auth is able to service requests. This can be used in k8s (or other)
// as a livenessProbe.
//
// There's only one dependency: the external cache. If that is not available, we return http.StatusServiceUnavailable.
// Otherwise, we return http.StatusOK.
func HealthHandler(states state.States, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := states.Ping(r.Context()); err != nil {
			logger.Warn("cache ping failed", "err", err)
			http.Error(w, "state cache not healthy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}
