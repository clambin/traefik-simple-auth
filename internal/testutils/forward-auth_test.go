package testutils_test

import (
	"net/http"
	"testing"

	"github.com/clambin/traefik-simple-auth/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestForwardAuthRequest(t *testing.T) {
	tests := []struct {
		name   string
		method string
		addr   string
		panics bool
		want   http.Header
	}{
		{
			name:   "without path",
			method: http.MethodPost,
			addr:   "https://example.com",
			want: http.Header{
				"User-Agent":         []string{"unit-test"},
				"X-Forwarded-Host":   []string{"example.com"},
				"X-Forwarded-Method": []string{"POST"},
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Uri":    []string{"/"},
			},
		},
		{
			name:   "with path",
			method: http.MethodPost,
			addr:   "https://example.com/foobar",
			want: http.Header{
				"User-Agent":         []string{"unit-test"},
				"X-Forwarded-Host":   []string{"example.com"},
				"X-Forwarded-Method": []string{"POST"},
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Uri":    []string{"/foobar"},
			},
		},
		{
			name:   "with query",
			method: http.MethodPost,
			addr:   "https://example.com/foobar?q=a",
			want: http.Header{
				"User-Agent":         []string{"unit-test"},
				"X-Forwarded-Host":   []string{"example.com"},
				"X-Forwarded-Method": []string{"POST"},
				"X-Forwarded-Proto":  []string{"https"},
				"X-Forwarded-Uri":    []string{"/foobar?q=a"},
			},
		},
		{
			name:   "panics if address has no scheme",
			method: http.MethodPost,
			addr:   "example.com",
			panics: true,
		},
		{
			name:   "panics if address is invalid",
			method: http.MethodPost,
			addr:   "\n",
			panics: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.panics {
				assert.Panics(t, func() { _ = testutils.ForwardAuthRequest(tt.method, tt.addr) })
				return
			}

			req := testutils.ForwardAuthRequest(tt.method, tt.addr)
			assert.Equal(t, http.MethodGet, req.Method)
			assert.Equal(t, "https://traefik/", req.URL.String())
			assert.Equal(t, tt.want, req.Header)
		})
	}
}
