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

type ForwardAuthHandler struct {
	Logger        *slog.Logger
	Domains       domains.Domains
	States        *state.Store[string]
	Sessions      *sessions.Sessions
	OAuthHandlers map[domains.Domain]oauth.Handler
}

func (h *ForwardAuthHandler) Authenticate(w http.ResponseWriter, r *http.Request) {
	h.Logger.Debug("request received", "request", logging.LoggedRequest{Request: r})

	// check that the request is for one of the configured domains
	domain, ok := h.Domains.Domain(r.URL)
	if !ok {
		h.Logger.Warn("host doesn't match any configured domains", "host", r.URL.Host)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	// validate that the request has a valid session cookie
	sess, ok := GetSession(r)
	if !ok {
		h.redirectToAuth(w, r, domain)
		return
	}

	// all good. tell traefik to forward the request
	h.Logger.Debug("allowing valid request", "email", sess.Email)
	w.Header().Set("X-Forwarded-User", sess.Email)
	w.WriteHeader(http.StatusOK)
}

func (h *ForwardAuthHandler) redirectToAuth(w http.ResponseWriter, r *http.Request, domain domains.Domain) {
	// To protect against CSRF attacks, we generate a random state and associate it with the final destination of the request.
	// authCallbackHandler uses the random state to retrieve the final destination, thereby validating that the request came from us.
	encodedState := h.States.Add(r.URL.String())

	// Redirect user to oauth provider to select the account to be used to authenticate the request
	authCodeURL := h.OAuthHandlers[domain].AuthCodeURL(encodedState, oauth2.SetAuthURLParam("prompt", "select_account"))
	h.Logger.Debug("redirecting ...", "authCodeURL", authCodeURL)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func (h *ForwardAuthHandler) LogOut(w http.ResponseWriter, r *http.Request) {
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
