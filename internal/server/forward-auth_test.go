package server

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_getOriginalTarget(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
	}{
		{
			name: "with scheme",
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
				"X-Forwarded-Host":  []string{"example.com"},
				"X-Forwarded-Uri":   []string{"/foo"},
			},
			want: "http://example.com/foo",
		},
		{
			name: "with parameters",
			headers: http.Header{
				"X-Forwarded-Proto": []string{"http"},
				"X-Forwarded-Host":  []string{"example.com"},
				"X-Forwarded-Uri":   []string{"/foo?arg1=foo&arg2=bar"},
			},
			want: "http://example.com/foo?arg1=foo&arg2=bar",
		},
		{
			name: "default scheme is https",
			headers: http.Header{
				"X-Forwarded-Host": []string{"example.com"},
				"X-Forwarded-Uri":  []string{"/foo"},
			},
			want: "https://example.com/foo",
		},
		{
			name: "ports are ignored",
			headers: http.Header{
				"X-Forwarded-Proto": []string{"https"},
				"X-Forwarded-Host":  []string{"example.com"},
				"X-Forwarded-Port":  []string{"443"},
			},
			want: "https://example.com/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header = tt.headers
			assert.Equal(t, tt.want, getOriginalTarget(r).String())
		})
	}
}
