package server

import (
	"log/slog"
	"net/http"
)

var _ slog.LogValuer = loggedRequest{}

type loggedRequest struct{ r *http.Request }

func (r loggedRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("http", r.r.URL.String()),
		slog.String("source", r.r.Header.Get("X-Forwarded-For")),
	)
}
