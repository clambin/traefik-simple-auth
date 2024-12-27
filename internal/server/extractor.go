package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/session"
	"net/http"
)

type ctxSessionKey string

var sessionKey = ctxSessionKey("sessionKey")

type sessionInfo struct {
	err   error
	email string
}

// sessionExtractor validates the JWT cookie from the request and adds the user's email & validation result to the request's context.
//
// Note: even if the JWT token is invalid, we pass the request to the next layer.  This allows us to record HTTP metrics using the user
// (from the JWT token). It's the responsibility of the application layer to check that the token is valid.
func sessionExtractor(sessions session.Sessions) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var info sessionInfo
			info.email, info.err = sessions.Validate(r)
			next.ServeHTTP(w, withSession(r, info))
		})
	}
}

// withSession returns a request with the userInfo added to its context.  If the cookie failed authentication, sessionInfo.err will indicate the reason.
func withSession(r *http.Request, info sessionInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, info))
}

// getSession returns the cookie from the request's context. If no valid cookie was found, err indicates the reason.
func getSession(r *http.Request) sessionInfo {
	info, ok := r.Context().Value(sessionKey).(sessionInfo)
	if !ok {
		// this should never happen
		info.err = http.ErrNoCookie
	}
	return info
}
