package server

import (
	"net/url"
	"strings"
)

type Domains []string

func (d Domains) getDomain(u *url.URL) (string, bool) {
	for _, _d := range d {
		if isValidSubdomain(_d, u.Host) {
			return _d, true
		}
	}
	return "", false
}

func isValidSubdomain(domain, input string) bool {
	if domain == "" {
		return false
	}
	if domain[0] != '.' {
		domain = "." + domain
	}
	if "."+input == domain {
		return true
	}
	return strings.HasSuffix(input, domain)
}
