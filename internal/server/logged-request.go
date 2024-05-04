package server

import (
	"log/slog"
	"net/http"
)

var _ slog.LogValuer = request{}

type request struct{ request *http.Request }

func loggedRequest(r *http.Request) slog.LogValuer {
	return request{request: r}
}

func (r request) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("http", r.request.URL.String()),
		slog.String("source", r.request.Header.Get("X-Forwarded-For")),
	)
}
