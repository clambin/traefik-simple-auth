package handlers

import (
	"github.com/clambin/traefik-simple-auth/internal/server/logging"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"log/slog"
	"net/http"
)

// LogoutHandler logs out the user: it removes the session from the session store and sends an empty Cookie to the user.
// This means that the user's next request has an invalid cookie, triggering a new oauth flow.
func LogoutHandler(domains domains.Domains, sessionStore *sessions.Sessions, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("request received", "request", logging.Request(r))

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
