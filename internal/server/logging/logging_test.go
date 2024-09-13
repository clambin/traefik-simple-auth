package logging

import (
	"bytes"
	logtest "github.com/clambin/go-common/testutils"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/http"
	"testing"
)

func TestRequest_LogValue(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Header.Add("X-Forwarded-For", "127.0.0.1:0")

	var out bytes.Buffer
	l := logtest.NewJSONLogger(&out, slog.LevelInfo)
	l.Info("request", "r", (*Request)(r))

	want := `{"level":"INFO","msg":"request","r":{"url":"https://example.com/","X-Forwarded-For":"127.0.0.1:0"}}
`
	assert.Equal(t, want, out.String())
}

func BenchmarkRequest_LogValue(b *testing.B) {
	r, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Header.Add("X-Forwarded-For", "127.0.0.1:0")
	var out bytes.Buffer
	l := logtest.NewTextLogger(&out, slog.LevelInfo)
	b.ResetTimer()
	for range b.N {
		l.Info("request", "r", (*Request)(r))
		out.Reset()
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func TestRejectedRequest_LogValue(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Header.Add("User-Agent", "foo")
	var out bytes.Buffer
	l := logtest.NewTextLogger(&out, slog.LevelInfo)
	l.Info("request", "r", (*RejectedRequest)(r))
	assert.Equal(t, `level=INFO msg=request r.method=GET r.url=https://example.com/ r.user-agent=foo
`, out.String())
}

func BenchmarkRejectedRequest_LogValue(b *testing.B) {
	r, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	r.Header.Add("User-Agent", "foo")
	var out bytes.Buffer
	l := logtest.NewTextLogger(&out, slog.LevelInfo)
	b.ResetTimer()
	for range b.N {
		l.Info("request", "r", (*RejectedRequest)(r))
		out.Reset()
	}
}
