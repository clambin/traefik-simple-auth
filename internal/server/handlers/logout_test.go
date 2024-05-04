package handlers

import (
	"context"
	"github.com/clambin/traefik-simple-auth/internal/server/sessions"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestServer_LogoutHandler(t *testing.T) {
	sessionStore := sessions.New("_auth", []byte("secret"), time.Hour)
	h := LogoutHandler(
		domains.Domains{".example.com"},
		sessionStore,
		slog.Default(),
	)

	t.Run("logging out clears the session cookie", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "https://example.com/_oauth/logout", nil)
		session := sessionStore.Session("foo@example.com")
		r = r.WithContext(context.WithValue(r.Context(), sessionKey, session))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "You have been logged out\n", w.Body.String())
		assert.Equal(t, "_auth=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))

	})

	t.Run("must be logged in to log out", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "https://example.com/_oauth/logout", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		require.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, "Invalid session\n", w.Body.String())
	})
}
