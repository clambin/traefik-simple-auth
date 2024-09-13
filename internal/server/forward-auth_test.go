package server

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
			method, addr := getOriginalTarget(r)
			assert.Equal(t, tt.wantMethod, method)
			assert.Equal(t, tt.wantAddr, addr.String())
		})
	}
}
