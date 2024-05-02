package domains

import (
	"fmt"
	"net/url"
	"strings"
)

type Domain string

// Domains validates if the host in a URL is part of a list of domains.
type Domains []Domain

// New builds a new Domains group from the provided entries. If an entry is not a valid domain, an error is returned.
func New(entries []string) (Domains, error) {
	var results Domains
	for _, domain := range entries {
		if domain == "" {
			return nil, fmt.Errorf("domain cannot be empty")
		}
		if domain[0] != '.' {
			domain = "." + domain
		}
		if _, err := url.Parse("https://www" + domain); err != nil {
			return nil, fmt.Errorf("invalid domain %q: %w", domain, err)
		}
		results = append(results, Domain(strings.ToLower(domain)))
	}
	return results, nil
}

// Domain returns the domain that the host in the URL is part of. Returns false if the URL is not part of any domain.
func (d Domains) Domain(u *url.URL) (Domain, bool) {
	host := strings.ToLower(u.Host)
	for _, domain := range d {
		if isValidSubdomain(domain, host) {
			return domain, true
		}
	}
	return "", false
}

func isValidSubdomain(domain Domain, input string) bool {
	if Domain(input) == domain[1:] {
		return true
	}
	return strings.HasSuffix(input, string(domain))
}
