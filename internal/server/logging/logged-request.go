package logging

import (
	"log/slog"
	"net/http"
)

var _ slog.LogValuer = LoggedRequest{}

type LoggedRequest struct{ request *http.Request }

func Request(r *http.Request) LoggedRequest {
	return LoggedRequest{request: r}
}

func (r LoggedRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("http", r.request.URL.String()),
		slog.String("source", r.request.Header.Get("X-Forwarded-For")),
	)
}
