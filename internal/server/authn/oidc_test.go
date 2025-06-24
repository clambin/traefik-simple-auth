package authn

import (
	"testing"

	"github.com/clambin/traefik-simple-auth/internal/testutils"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCHandler_GetUserEmailAddress(t *testing.T) {
	s, err := mockoidc.Run()
	require.NoError(t, err)

	cfg := s.Config()
	ctx := t.Context()
	l := testutils.DiscardLogger

	t.Run("invalid issuer url", func(t *testing.T) {
		_, err = NewOIDCHandler(ctx, "", cfg.ClientID, cfg.ClientSecret, "https://auth.example.com", l)
		assert.Error(t, err)
	})

	t.Run("valid issuer url", func(t *testing.T) {
		h, err := NewOIDCHandler(ctx, s.Issuer(), cfg.ClientID, cfg.ClientSecret, "https://auth.example.com", l)
		require.NoError(t, err)

		_, err = h.GetUserEmailAddress(ctx, "invalid")
		assert.Error(t, err)

		u := mockoidc.MockUser{
			Email:         "foo@example.com",
			EmailVerified: true,
		}
		session, err := s.SessionStore.NewSession("oidc profile email", "", &u, "", "")
		require.NoError(t, err)

		email, err := h.GetUserEmailAddress(ctx, session.SessionID)
		require.NoError(t, err)
		assert.Equal(t, "foo@example.com", email)
	})

	t.Run("failed to access Auth server", func(t *testing.T) {
		assert.NoError(t, s.Shutdown())

		_, err = NewOIDCHandler(ctx, s.Issuer(), cfg.ClientID, cfg.ClientSecret, "https://auth.example.com", l)
		assert.Error(t, err)
	})
}
