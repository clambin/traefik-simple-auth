package server

import (
	"github.com/clambin/traefik-simple-auth/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionExtractor(t *testing.T) {
	a := auth.New("_auth", []byte("secret"), time.Hour)
	extractor := authenticate(a)
	validCookie, _ := a.CookieWithSignedToken("foo@example.com", "example.com")

	tests := []struct {
		name      string
		cookie    *http.Cookie
		wantErr   require.ErrorAssertionFunc
		wantEmail string
	}{
		{
			name:    "no cookie",
			cookie:  nil,
			wantErr: require.Error,
		},
		{
			name:    "bad cookie",
			cookie:  a.Cookie("invalid-token", time.Hour, "example.com"),
			wantErr: require.Error,
		},
		{
			name:      "valid cookie",
			cookie:    validCookie,
			wantErr:   require.NoError,
			wantEmail: "foo@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie)
			}
			w := httptest.NewRecorder()

			h := extractor(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Helper()
				email, err := getUserInfo(r)
				tt.wantErr(t, err)
				if err != nil {
					return
				}
				assert.Equal(t, tt.wantEmail, email)
			}))
			h.ServeHTTP(w, r)
		})
	}
}

func Test_getOriginalTarget(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantMethod string
		wantAddr   string
	}{
		{
			name: "with scheme",
			headers: http.Header{
				"X-Forwarded-Proto":  []string{"http"},
				"X-Forwarded-Host":   []string{"example.com"},
				"X-Forwarded-Uri":    []string{"/foo"},
				"X-Forwarded-Method": []string{http.MethodPost},
			},
			wantMethod: http.MethodPost,
			wantAddr:   "http://example.com/foo",
		},
		{
			name: "with parameters",
			headers: http.Header{
				"X-Forwarded-Proto":  []string{"http"},
				"X-Forwarded-Host":   []string{"example.com"},
				"X-Forwarded-Uri":    []string{"/foo?arg1=foo&arg2=bar"},
				"X-Forwarded-Method": []string{http.MethodPost},
			},
			wantMethod: http.MethodPost,
			wantAddr:   "http://example.com/foo?arg1=foo&arg2=bar",
		},
		{
			name: "default scheme is https",
			headers: http.Header{
				"X-Forwarded-Host":   []string{"example.com"},
				"X-Forwarded-Uri":    []string{"/foo"},
				"X-Forwarded-Method": []string{http.MethodPost},
			},
			wantMethod: http.MethodPost,
			wantAddr:   "https://example.com/foo",
		},
		{
			name: "ports are ignored",
			headers: http.Header{
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Host":   []string{"example.com"},
				"X-Forwarded-Port":   []string{"443"},
				"X-Forwarded-Method": []string{http.MethodPost},
			},
			wantMethod: http.MethodPost,
			wantAddr:   "https://example.com/",
		},
		{
			name: "default method is GET",
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
				"X-Forwarded-Host":  []string{"example.com"},
				"X-Forwarded-Uri":   []string{"/foo"},
			},
			wantMethod: http.MethodGet,
			wantAddr:   "http://example.com/foo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header = tt.headers
			restoreOriginalRequest(r)
			assert.Equal(t, tt.wantMethod, r.Method)
			assert.Equal(t, tt.wantAddr, r.URL.String())
		})
	}
}

// current:
// Benchmark_restoreOriginalRequest-16      8409932               141.6 ns/op             0 B/op          0 allocs/op
func Benchmark_restoreOriginalRequest(b *testing.B) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header = http.Header{
		"X-Forwarded-Method": []string{http.MethodPost},
		"X-Forwarded-Proto":  []string{"https"},
		"X-Forwarded-Host":   []string{"example.com"},
		"X-Forwarded-Uri":    []string{"/foo?arg1=bar"},
	}

	b.ResetTimer()
	for range b.N {
		restoreOriginalRequest(r)
		if r.Method != http.MethodPost {
			b.Fatal("unexpected method", r.Method)
		}
		// target.String() is too slow for this benchmark
		if r.URL.Scheme != "https" || r.URL.Host != "example.com" || r.URL.Path != "/foo" || r.URL.RawQuery != "arg1=bar" {
			b.Fatal("unexpected target", r.URL.String())
		}
	}
}
