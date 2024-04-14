package server

import (
	"net/http"
	"net/url"
)

func traefikParser() func(next http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r.URL, _ = url.Parse(getOriginalTarget(r))
			next.ServeHTTP(w, r)
		}
	}
}

func getOriginalTarget(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		// TODO: why is this sometimes not set?
		proto = "https"
	}
	return proto + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
}
