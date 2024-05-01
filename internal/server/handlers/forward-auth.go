package handlers

import (
	"github.com/clambin/traefik-simple-auth/internal/server/logging"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
)

// The ForwardAuthHandler handles all requests coming in from traefik's forwardAuth middleware
type ForwardAuthHandler struct {
	Logger        *slog.Logger
	Domains       domains.Domains
	States        *state.Store[string]
	Sessions      *sessions.Sessions
	OAuthHandlers map[domains.Domain]oauth.Handler
	OAUTHPath     string
}

func (h *ForwardAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case h.OAUTHPath + "/logout":
		h.logout(w, r)
	default:
		h.authenticate(w, r)
	}
}

// authenticate implements the authentication flow for traefik's forwardAuth middleware.  It checks that the request
// has a valid session (stored in a http.Cookie). If so, it returns http.StatusOK.   If not, it redirects the requesr
// to the configured oauth provider to log in.  After login, the request is routed to the AuthCallbackHandler, which
// forwards the request to the originally requested destination.
func (h *ForwardAuthHandler) authenticate(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("request received", "request", logging.LoggedRequest{Request: r})

	// check that the request is for one of the configured domains
	domain, ok := h.Domains.Domain(r.URL)
	if !ok {
		h.Logger.Warn("host doesn't match any configured domains", slog.String("host", r.URL.Host))
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	h.Logger.Debug("request has valid domain")

	// validate that the request has a valid session cookie
	sess, ok := GetSession(r)
	if !ok {
		h.redirectToAuth(w, r, domain)
		return
	}

	h.Logger.Debug("request has valid session")

	// all good. tell traefik to forward the request
	h.Logger.Debug("allowing valid request", slog.String("email", sess.Email))
	w.Header().Set("X-Forwarded-User", sess.Email)
	w.WriteHeader(http.StatusOK)
}

// redirectToAuth redirects the user to the configured oauth provider to log in
func (h *ForwardAuthHandler) redirectToAuth(w http.ResponseWriter, r *http.Request, domain domains.Domain) {
	// To protect against CSRF attacks, we generate a random state and associate it with the final destination of the request.
	// authCallbackHandler uses the random state to retrieve the final destination, thereby validating that the request came from us.
	encodedState := h.States.Add(r.URL.String())

	// Redirect user to oauth provider to select the account to be used to authenticate the request
	authCodeURL := h.OAuthHandlers[domain].AuthCodeURL(encodedState, oauth2.SetAuthURLParam("prompt", "select_account"))
	h.Logger.Debug("redirecting ...", "authCodeURL", authCodeURL)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

// logout logs out the user: it removes the session from the session store and sends an empty Cookie to the user.
// This means that the user's next request has an invalid cookie, triggering a new oauth flow.
func (h *ForwardAuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("request received", "request", logging.LoggedRequest{Request: r})

	// remove the cached cookie
	session, ok := GetSession(r)
	if !ok {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	// delete the session
	h.Sessions.DeleteSession(session)

	// Write a blank session cookie to override the current valid one.
	domain, _ := h.Domains.Domain(r.URL)
	http.SetCookie(w, h.Sessions.Cookie(sessions.Session{}, domain))

	http.Error(w, "You have been logged out", http.StatusUnauthorized)
	h.Logger.Info("user has been logged out", "user", session.Email)
}
