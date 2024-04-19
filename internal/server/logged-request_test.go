package server

import (
	"bytes"
	"github.com/clambin/go-common/testutils"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/http"
	"testing"
)

func Test_loggedRequest(t *testing.T) {
	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo/bar")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "foo"})
	r.Header.Add("X-Forwarded-For", "127.0.0.1:0")

	var out bytes.Buffer
	l := testutils.NewJSONLogger(&out, slog.LevelInfo)
	l.Info("request", "r", loggedRequest{r: r})

	want := `{"level":"INFO","msg":"request","r":{"http":"https://traefik/","sessions":"_traefik_simple_auth","source":"127.0.0.1:0"}}
`
	assert.Equal(t, want, out.String())
}
