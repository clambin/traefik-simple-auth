package logging

import (
	"log/slog"
	"net/http"
	"strings"
)

var _ slog.LogValuer = &Request{}

type Request http.Request

func (r *Request) LogValue() slog.Value {
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

var _ slog.LogValuer = &RejectedRequest{}

type RejectedRequest http.Request

func (r *RejectedRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("method", r.Method),
		slog.String("url", r.URL.String()),
		slog.String("user-agent", ((*http.Request)(r)).UserAgent()),
	)
}
