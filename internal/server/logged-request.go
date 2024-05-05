package server

import (
	"log/slog"
	"net/http"
	"strings"
)

var _ slog.LogValuer = request{}

type request struct{ request *http.Request }

func loggedRequest(r *http.Request) slog.LogValuer {
	return request{request: r}
}

func (r request) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.String("url", r.request.URL.String()),
	}
	for k := range r.request.Header {
		if strings.HasPrefix(k, "X-Forwarded-") {
			attrs = append(attrs, slog.String(k, r.request.Header.Get(k)))
		}
	}
	return slog.GroupValue(attrs...)
}
