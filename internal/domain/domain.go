// Package domains provides a means of testing if the host in a URL is part of a list of domains.
package domain

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type Domain string

func New(domain string) (Domain, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}
	if domain[0] != '.' {
		domain = "." + domain
	}
	if _, port, _ := net.SplitHostPort(domain); port != "" {
		return "", fmt.Errorf("domain cannot contain port")
	}
	if _, err := url.Parse("https://www" + domain); err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	return Domain(domain), nil
}

func (d Domain) Matches(u *url.URL) bool {
	host := strings.ToLower(u.Host)
	if n := strings.LastIndexByte(host, ':'); n != -1 {
		host = host[:n]
	}
	if Domain(host) == d[1:] {
		return true
	}
	return strings.HasSuffix(host, string(d))
}
