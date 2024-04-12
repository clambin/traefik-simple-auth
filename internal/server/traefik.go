package server

import (
	"net/http"
)

func traefikParser() func(next http.Handler) http.HandlerFunc {
	return func(next http.Handler) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			r2, _ := http.NewRequest(r.Method, getOriginalTarget(r), nil)
			for _, c := range r.Cookies() {
				r2.AddCookie(c)
			}
			next.ServeHTTP(w, r2)
		}
	}
}

func getOriginalTarget(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		// TODO: why is this sometimes not set?
		proto = "https"
	}
	redirectURL := proto + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
	return redirectURL
}
