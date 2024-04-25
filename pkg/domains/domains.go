package domains

import (
	"net/url"
	"strings"
)

// Domains validates if the host in a URL is part of a list of subdomains.
type Domains []string

// Domain returns the domain that the host in the URL is part of. Returns false if the URL is not part of any domain.
func (d Domains) Domain(u *url.URL) (string, bool) {
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
