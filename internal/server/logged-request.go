package server

import (
	"log/slog"
	"net/http"
	"strings"
)

var _ slog.LogValuer = loggedRequest{}

type loggedRequest struct{ r *http.Request }

func (r loggedRequest) LogValue() slog.Value {
	cookies := make([]string, 0, 1)
	for _, c := range r.r.Cookies() {
		if c.Name == sessionCookieName {
			cookies = append(cookies, c.Name)
		}
	}
	return slog.GroupValue(
		slog.String("http", r.r.URL.String()),
		slog.String("cookies", strings.Join(cookies, ",")),
		slog.String("source", r.r.Header.Get("X-Forwarded-For")),
	)
}
