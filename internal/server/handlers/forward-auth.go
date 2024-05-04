package handlers

import (
	"github.com/clambin/traefik-simple-auth/internal/server/logging"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
)

// The ForwardAuthHandler implements the authentication flow for traefik's forwardAuth middleware.  It checks that the request
// has a valid session (stored in a http.Cookie). If so, it returns http.StatusOK.   If not, it redirects the requesr
// to the configured oauth provider to log in.  After login, the request is routed to the AuthCallbackHandler, which
// forwards the request to the originally requested destination.
func ForwardAuthHandler(domains domains.Domains, oauthHandlers map[domains.Domain]oauth.Handler, states *state.States[string], logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", slog.Any("request", logging.Request(r)))

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
