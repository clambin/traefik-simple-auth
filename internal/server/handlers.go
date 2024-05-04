package server

import (
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"net/url"
)

// The ForwardAuthHandler implements the authentication flow for traefik's forwardAuth middleware.  It checks that the request
// has a valid session (stored in a http.Cookie). If so, it returns http.StatusOK.   If not, it redirects the requesr
// to the configured oauth provider to log in.  After login, the request is routed to the AuthCallbackHandler, which
// forwards the request to the originally requested destination.
func ForwardAuthHandler(domains domains.Domains, oauthHandlers map[domains.Domain]oauth.Handler, states state.States[string], logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", slog.Any("request", loggedRequest(r)))

		// check that the request is for one of the configured domains
		domain, ok := domains.Domain(r.URL)
		if !ok {
			logger.Warn("host doesn't match any configured domains", slog.String("host", r.URL.Host))
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// validate that the request has a valid session cookie
		if sess, ok := GetSession(r); ok {
			logger.Debug("allowing valid request", slog.String("email", sess.Email))
			w.Header().Set("X-Forwarded-User", sess.Email)
			w.WriteHeader(http.StatusOK)
			return
		}

		// no valid session cookie found. redirect to oauth handler

		// To protect against CSRF attacks, we generate a random state and associate it with the final destination of the request.
		// authCallbackHandler uses the random state to retrieve the final destination, thereby validating that the request came from us.
		//
		// Note: since the state is kept in memory, this does limit traefik-simple-auth to a single instance, as in a multi-inatance setup,
		// the callback may be routed to a different instance than the one that generate the state.
		// However, considered traefik-simple-auth responds in less than 100 µs (i.e. 10,000 tps in a worst case scenario),
		// this doesn't present a real problem (yet).
		encodedState := states.Add(r.URL.String())

		// Redirect the user to the oauth2 provider to select the account to authenticate the request.
		authCodeURL := oauthHandlers[domain].AuthCodeURL(encodedState, oauth2.SetAuthURLParam("prompt", "select_account"))
		logger.Debug("redirecting ...", "authCodeURL", authCodeURL)
		http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
	})
}

// LogoutHandler logs out the user: it removes the session from the session store and sends an empty Cookie to the user.
// This means that the user's next request has an invalid cookie, triggering a new oauth flow.
func LogoutHandler(domains domains.Domains, sessionStore sessions.Sessions, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", loggedRequest(r))

		// remove the cached cookie
		session, ok := GetSession(r)
		if !ok {
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}

		// delete the session
		sessionStore.DeleteSession(session)

		// Write a blank session cookie to override the current valid one.
		domain, _ := domains.Domain(r.URL)
		http.SetCookie(w, sessionStore.Cookie(sessions.Session{}, domain))

		http.Error(w, "You have been logged out", http.StatusUnauthorized)
		logger.Info("user has been logged out", "user", session.Email)
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
	states state.States[string],
	sessions sessions.Sessions,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", loggedRequest(r))

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
