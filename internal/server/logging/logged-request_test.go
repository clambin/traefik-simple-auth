package logging

import (
	"bytes"
	logtest "github.com/clambin/go-common/testutils"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/http"
	"testing"
)

func Test_loggedRequest(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Header.Add("X-Forwarded-For", "127.0.0.1:0")

	var out bytes.Buffer
	l := logtest.NewJSONLogger(&out, slog.LevelInfo)
	l.Info("request", "r", Request(r))

	want := `{"level":"INFO","msg":"request","r":{"http":"https://example.com/","source":"127.0.0.1:0"}}
`
	assert.Equal(t, want, out.String())
}
