package oauth

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"log/slog"
	"testing"

	"github.com/oauth2-proxy/mockoidc"
)

func TestOIDCHandler_GetUserEmailAddress(t *testing.T) {
	s, err := mockoidc.Run()
	require.NoError(t, err)

	cfg := s.Config()

	ctx := context.Background()

	l := slog.Default()

	_, err = NewOIDCHandler(ctx, "", cfg.ClientID, cfg.ClientSecret, "https://auth.example.com", l)
	assert.Error(t, err)

	h, err := NewOIDCHandler(ctx, s.Issuer(), cfg.ClientID, cfg.ClientSecret, "https://auth.example.com", l)
	require.NoError(t, err)

	_, err = h.GetUserEmailAddress(ctx, "invalid")
	assert.Error(t, err)

	u := mockoidc.MockUser{
		Email:         "foo@example.com",
		EmailVerified: true,
	}
	session, err := s.SessionStore.NewSession("oidc profile email", "1234567890", &u, "12345", "")
	require.NoError(t, err)

	email, err := h.GetUserEmailAddress(ctx, session.SessionID)
	require.NoError(t, err)
	assert.Equal(t, email, "foo@example.com")

	assert.NoError(t, s.Shutdown())

	_, err = NewOIDCHandler(ctx, s.Issuer(), cfg.ClientID, cfg.ClientSecret, "https://auth.example.com", l)
	assert.Error(t, err)

}
