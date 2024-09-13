package server

import (
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/oauth"
	"github.com/clambin/traefik-simple-auth/internal/sessions"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// newForwardAuthHandler returns a http.Handler that serves the auth request ("/") and the logout request ("/_oauth/logout)
func newForwardAuthHandler(
	domains domains.Domains,
	oauthHandlers map[domains.Domain]oauth.Handler,
	sessions sessions.Sessions,
	states state.States,
	metrics *Metrics,
	logger *slog.Logger,
) http.Handler {
	mux := http.NewServeMux()
	addForwardAuthRoutes(mux, domains, oauthHandlers, sessions, states, logger)
	return sessionExtractor(sessions)( // extract the session cookie and store it in the request context
		withMetrics(metrics)( // record request metrics
			traefikForwardAuthParser( // restore the original request
				mux, // handle forwardAuth or logout
			),
		),
	)
}

func addForwardAuthRoutes(
	mux *http.ServeMux,
	domains domains.Domains,
	oauthHandlers map[domains.Domain]oauth.Handler,
	sessions sessions.Sessions,
	states state.States,
	logger *slog.Logger,
) {
	mux.Handle("/", ForwardAuthHandler(domains, oauthHandlers, states, logger.With("handler", "forwardAuth")))
	mux.Handle(OAUTHPath+"/logout", LogoutHandler(domains, sessions, logger.With("handler", "logout")))
}

// traefikForwardAuthParser takes a request passed by traefik's forwardAuth middleware and reconstructs the original request.
func traefikForwardAuthParser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL = getOriginalTarget(r)
		next.ServeHTTP(w, r)
	})
}

func getOriginalTarget(r *http.Request) *url.URL {
	hdr := r.Header
	path := getHeaderValue(hdr, "X-Forwarded-Uri", "/")
	var rawQuery string
	if n := strings.Index(path, "?"); n > 0 {
		rawQuery = path[n+1:]
		path = path[:n]
	}

	return &url.URL{
		Scheme:   getHeaderValue(hdr, "X-Forwarded-Proto", "https"),
		Host:     getHeaderValue(hdr, "X-Forwarded-Host", ""),
		Path:     path,
		RawQuery: rawQuery,
	}
}

func getHeaderValue(h map[string][]string, key string, defaultValue string) string {
	val, ok := h[key]
	if !ok || len(val) == 0 {
		return defaultValue
	}
	return val[0]
}
