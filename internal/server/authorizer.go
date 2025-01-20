package server

import (
	"errors"
	"github.com/clambin/traefik-simple-auth/internal/domain"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"net/http"
	"net/url"
)

var (
	errInvalidUser   = errors.New("invalid user")
	errInvalidDomain = errors.New("invalid domain")
)

type authorizer struct {
	whitelist.Whitelist
	domain.Domain
}

func (a authorizer) AuthorizeRequest(r *http.Request) (string, error) {
	user, err := getUserInfo(r)
	if err != nil {
		return "", err
	}
	return user, a.Authorize(user, r.URL)
}

func (a authorizer) Authorize(user string, u *url.URL) error {
	if !a.Whitelist.Match(user) {
		return errInvalidUser
	}
	if !a.Domain.Matches(u) {
		return errInvalidDomain
	}
	return nil
}
