package extractor

import (
	"context"
	"errors"
	"github.com/clambin/traefik-simple-auth/pkg/sessions"
	"log/slog"
	"net/http"
)

type ctxSessionKey string

var sessionKey ctxSessionKey = "sessionKey"

// SessionExtractor validates the session cookie from the request and, if valid, adds the session to the request's context.
func SessionExtractor(sessions sessions.Sessions, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if userSession, err := sessions.Validate(r); err == nil {
				r = WithSession(r, userSession)
			} else if !errors.Is(err, http.ErrNoCookie) {
				logger.Warn("received invalid session cookie", "err", err)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetSession returns the session from the request's context, if it exists.
func GetSession(r *http.Request) (sessions.Session, bool) {
	userSession, ok := r.Context().Value(sessionKey).(sessions.Session)
	return userSession, ok
}

func WithSession(r *http.Request, userSession sessions.Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, userSession))
}
