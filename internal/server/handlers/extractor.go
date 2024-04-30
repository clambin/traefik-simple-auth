package handlers

import (
	"context"
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"log/slog"
	"net/http"
)

type ctxSessionKey string

var sessionKey ctxSessionKey = "sessionKey"

func SessionExtractor(sessions *sessions.Sessions, logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if userSession, err := sessions.Validate(r); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), sessionKey, userSession))
			} else if !errors.Is(err, http.ErrNoCookie) {
				logger.Warn("received invalid session cookie", "err", err)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func GetSession(r *http.Request) (sessions.Session, bool) {
	userSession, ok := r.Context().Value(sessionKey).(sessions.Session)
	return userSession, ok
}
