package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	target, err := url.Parse("http://" + ln.Addr().(*net.TCPAddr).String())
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-User") == "" {
			http.Error(w, "no user", http.StatusUnauthorized)
		}
	})
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	require.Equal(t, http.StatusUnauthorized, resp.Code)

	go func() {
		require.ErrorIs(t, http.Serve(ln, h), http.ErrServerClosed)
	}()

	req, _ = http.NewRequest(http.MethodGet, "/", nil)
	resp = httptest.NewRecorder()
	forwardAuthHandler(target, "user").ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
}
