package server

import (
	"context"
	"errors"
	"github.com/clambin/traefik-simple-auth/pkg/sessions"
	"log/slog"
	"net/http"
)

type ctxSessionKey string

var sessionKey ctxSessionKey = "sessionKey"

// sessionExtractor validates the session cookie from the request and, if valid, adds the session to the request's context.
func sessionExtractor(sessions sessions.Sessions, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if userSession, err := sessions.Validate(r); err == nil {
				r = withSession(r, userSession)
			} else if !errors.Is(err, http.ErrNoCookie) {
				logger.Warn("received invalid session cookie", "err", err)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// getSession returns the session from the request's context, if it exists.
func getSession(r *http.Request) (sessions.Session, bool) {
	userSession, ok := r.Context().Value(sessionKey).(sessions.Session)
	return userSession, ok
}

// withSession returns a request with the userSession added to its context
func withSession(r *http.Request, userSession sessions.Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, userSession))
}
