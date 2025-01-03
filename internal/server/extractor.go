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
			// Validate the JWT token in the cookie. If the cookie is invalid, userInfo.err will indicate the reason.
			var info userInfo
			info.email, info.err = authenticator.Validate(r)
			// Call the next handler with the auth info added to the request's context
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), authKey, info)))
		})
	}
}

// getUserInfo returns the token from the request's context. If no valid token was found, err indicates the reason.
func getUserInfo(r *http.Request) userInfo {
	info, ok := r.Context().Value(authKey).(userInfo)
	if !ok {
		// this should never happen
		info.err = http.ErrNoCookie
	}
	return info
}
