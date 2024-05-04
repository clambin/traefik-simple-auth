package testutils

import (
	"context"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"golang.org/x/oauth2"
)

var _ oauth.Handler = FakeOauthHandler{}

type FakeOauthHandler struct {
	Email string
	Err   error
}

func (f FakeOauthHandler) AuthCodeURL(_ string, _ ...oauth2.AuthCodeOption) string {
	// not needed to test authCallbackHandler()
	panic("implement me")
}

func (f FakeOauthHandler) GetUserEmailAddress(_ context.Context, _ string) (string, error) {
	return f.Email, f.Err
}
