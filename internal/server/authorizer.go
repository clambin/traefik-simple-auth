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
	reqUser, err := getAuthenticatedUserEmail(r)
	if err != nil {
		return "", err
	}
	return reqUser, a.Authorize(reqUser, r.URL)
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
