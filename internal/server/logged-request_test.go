package server

import (
	"bytes"
	"github.com/clambin/go-common/testutils"
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

	want := `{"level":"INFO","msg":"request","r":{"http":"https://traefik/","traefik":"https://example.com/foo/bar","cookies":"_simple_auth","source":"127.0.0.1:0"}}
`
	if got := out.String(); got != want {
		t.Errorf("got %q, want %q string", got, want)
	}
}
