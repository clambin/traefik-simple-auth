package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"net/http"
)

type ctxSessionKey string

var sessionKey = ctxSessionKey("sessionKey")

type sessionInfo struct {
	err     error
	session sessions.Session
}

// sessionExtractor validates the session cookie from the request and, if valid, adds the session to the request's context.
func sessionExtractor(sessions sessions.Sessions) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var info sessionInfo
			info.session, info.err = sessions.Validate(r)
			next.ServeHTTP(w, withSession(r, info))
		})
	}
}

// withSession returns a request with the userSession added to its context.  If the session is missing/invalid, sessionInfo.err will indicate the reason.
func withSession(r *http.Request, info sessionInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, info))
}

// getSession returns the session from the request's context. If no valid cookie was found, err indicates the reason.
func getSession(r *http.Request) (sessions.Session, error) {
	info, ok := r.Context().Value(sessionKey).(sessionInfo)
	if !ok {
		// this should never happen
		info.err = http.ErrNoCookie
	}
	return info.session, info.err
}
