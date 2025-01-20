package server

import (
	"cmp"
	"context"
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"net/http"
	"strings"
)

type ctxAuthKey string

var authKey = ctxAuthKey("authKey")

type userInfo struct {
	err   error
	email string
}

// The authenticate middleware validates the JWT cookie from the request and adds the user's email & validation result to the request's context.
//
// Note: even if the JWT token is invalid, we pass the request to the next layer.  This allows us to record HTTP metrics using the user
// (from the JWT token). It's the responsibility of the application layer to check that the token is valid.
func authenticate(authenticator *auth.Authenticator) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Authenticate the JWT token in the cookie. If the cookie is invalid, userInfo.err will indicate the reason.
			var info userInfo
			info.email, info.err = authenticator.Authenticate(r)
			// Add the auth info to the request's context and call the next Handler.
			next.ServeHTTP(w, withUserInfo(r, info))
		})
	}
}

// withUserInfo returns a request with the token info in the request's context
func withUserInfo(r *http.Request, info userInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authKey, info))
}

// getUserInfo returns the token info from the request's context. If no valid token was found, err indicates the reason.
// If no token info is found in the request's context, err is http.ErrNoCookie.
func getUserInfo(r *http.Request) (string, error) {
	if info, ok := r.Context().Value(authKey).(userInfo); ok {
		return info.email, info.err
	}
	return "", http.ErrNoCookie
}

// The forwardAuthParser middleware takes a request passed by traefik's forwardAuth middleware and reconstructs the original request.
func forwardAuthParser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		restoreOriginalRequest(r)
		next.ServeHTTP(w, r)
	})
}

func restoreOriginalRequest(r *http.Request) {
	hdr := r.Header
	path := cmp.Or(hdr.Get("X-Forwarded-Uri"), "/")
	var rawQuery string
	if n := strings.Index(path, "?"); n > 0 {
		rawQuery = path[n+1:]
		path = path[:n]
	}

	r.Method = cmp.Or(hdr.Get("X-Forwarded-Method"), http.MethodGet)
	r.URL.Scheme = cmp.Or(hdr.Get("X-Forwarded-Proto"), "https")
	r.URL.Host = cmp.Or(hdr.Get("X-Forwarded-Host"), "")
	r.URL.Path = path
	r.URL.RawQuery = rawQuery
}
