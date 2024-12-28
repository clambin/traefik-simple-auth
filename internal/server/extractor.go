package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"net/http"
)

type ctxAuthKey string

var authKey = ctxAuthKey("authKey")

type userInfo struct {
	err   error
	email string
}

// authExtractor validates the JWT cookie from the request and adds the user's email & validation result to the request's context.
//
// Note: even if the JWT token is invalid, we pass the request to the next layer.  This allows us to record HTTP metrics using the user
// (from the JWT token). It's the responsibility of the application layer to check that the token is valid.
func authExtractor(authenticator auth.Authenticator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var info userInfo
			info.email, info.err = authenticator.Validate(r)
			next.ServeHTTP(w, withUserInfo(r, info))
		})
	}
}

// withUserInfo returns a request with the userInfo added to its context.  If the cookie failed authentication, userInfo.err will indicate the reason.
func withUserInfo(r *http.Request, info userInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authKey, info))
}

// getUserInfo returns the cookie from the request's context. If no valid cookie was found, err indicates the reason.
func getUserInfo(r *http.Request) userInfo {
	info, ok := r.Context().Value(authKey).(userInfo)
	if !ok {
		// this should never happen
		info.err = http.ErrNoCookie
	}
	return info
}
