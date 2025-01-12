package server

import (
	"log/slog"
	"net/http"
	"strings"
)

var _ slog.LogValuer = &request{}

type request http.Request

func (r *request) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("url", r.URL.String()),
	}
	for k := range r.Header {
		if strings.HasPrefix(k, "X-Forwarded-") {
			attrs = append(attrs, slog.String(k, r.Header.Get(k)))
		}
	}
	return slog.GroupValue(attrs...)
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var _ slog.LogValuer = &rejectedRequest{}

type rejectedRequest http.Request

func (r *rejectedRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("user_agent", ((*http.Request)(r)).UserAgent()),
	)
}
