package logging

import (
	"log/slog"
	"net/http"
)

var _ slog.LogValuer = LoggedRequest{}

type LoggedRequest struct{ Request *http.Request }

func (r LoggedRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("http", r.Request.URL.String()),
		slog.String("source", r.Request.Header.Get("X-Forwarded-For")),
	)
}
