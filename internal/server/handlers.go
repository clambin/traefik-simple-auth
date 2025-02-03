package server

import (
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/server/oauth"
	"github.com/clambin/traefik-simple-auth/internal/server/state"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// forwardAuthHandler implements the authentication flow for traefik's forwardAuth middleware.
// If the request has a valid cookie (stored in an http.Cookie), it returns http.StatusOK. If not, it redirects the request
// to the OAuth2 provider to log in.  After login, the request is routed to the oAuth2CallbackHandler, which
// forwards the request to the originally requested destination.
func forwardAuthHandler(
	authorizer authorizer,
	oauthHandler oauth.Handler,
	states state.States,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", (*request)(r))

		// verify that the request is authorized
		user, err := authorizer.AuthorizeRequest(r)
		if err == nil {
			logger.Debug("allowing valid request", "user", user)
			w.Header().Set("X-Forwarded-User", user)
			w.WriteHeader(http.StatusOK)
			return
		}

		// If the request is not for an allowed user & domain, we return HTTP Forbidden
		if errors.Is(err, errInvalidUser) || errors.Is(err, errInvalidDomain) {
			logger.Warn("request rejected", "user", user, "host", r.URL.Host, "err", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		// Otherwise, we redirect to the OAuth2 provider so the user can log in
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

// logoutHandler logs out the user: it removes the cookie from the cookie store and sends an empty Cookie to the user.
// This means that the user's next request has an invalid cookie, triggering a new oauth flow.
func logoutHandler(
	authenticator *Authenticator,
	authorizer authorizer,
	logger *slog.Logger,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", (*request)(r))

		// verify that the request is authorized
		user, err := authorizer.AuthorizeRequest(r)
		if err == nil {
			// Write a blank cookie to override/clear the current valid one.
			http.SetCookie(w, authenticator.Cookie("", 0))
			logger.Info("user has been logged out", "user", user)
			http.Error(w, "You have been logged out", http.StatusUnauthorized)
			return
		}

		// if the request is not for an allowed user & domain, we return HTTP Forbidden
		statusCode := http.StatusUnauthorized
		if errors.Is(err, errInvalidUser) || errors.Is(err, errInvalidDomain) {
			statusCode = http.StatusForbidden
		}

		logger.Warn("request rejected", "user", user, "host", r.URL.Host, "err", err)
		http.Error(w, http.StatusText(statusCode), statusCode)
	})
}

// The oAuth2CallbackHandler implements the OAuth2 callback, initiated by forwardAuthHandler's redirectToAuth method.
// It validates that the request came from us (by checking the state parameter), determines the user's email address,
// checks that that user is on the whitelist, creates a JWT Cookie for the user and redirects the user to the
// target that originally initiated the oauth flow.
func oAuth2CallbackHandler(
	authenticator *Authenticator,
	authorizer authorizer,
	oauthHandler oauth.Handler,
	states state.States,
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

		// validate that this is an authorized request
		u, _ := url.Parse(targetURL)
		if err = authorizer.Authorize(user, u); err != nil {
			logger.Warn("rejecting login request: not a valid request", "user", user, "url", targetURL, "err", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		// Valid user. Create a cookie and redirect the user to the final destination.
		logger.Info("user logged in", "user", user, "url", targetURL)
		c, _ := authenticator.CookieWithSignedToken(user)
		logger.Debug("sending cookie to user", "user", user, "cookie", c)
		http.SetCookie(w, c)
		http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
	})
}

// The healthHandler checks that traefik-simple-auth is able to service requests. This can be used in k8s (or other)
// as a livenessProbe.
//
// There's only one dependency: the external cache. If that is not available, we return http.StatusServiceUnavailable.
// Otherwise, we return http.StatusOK.
func healthHandler(states state.States, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := states.Ping(r.Context()); err != nil {
			logger.Warn("cache ping failed", "err", err)
			http.Error(w, "state cache not healthy", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ slog.LogValuer = &request{}

type request http.Request

func (r *request) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("url", r.URL.String()),
	}
	for k := range r.Header {
		if strings.HasPrefix(k, "X-Forwarded-") {
			attrs = append(attrs, slog.String(k, r.Header.Get(k)))
		}
	}
	return slog.GroupValue(attrs...)
}

var _ slog.LogValuer = &rejectedRequest{}

type rejectedRequest http.Request

func (r *rejectedRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("user_agent", ((*http.Request)(r)).UserAgent()),
	)
}
