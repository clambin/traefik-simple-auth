package domains

import (
	"fmt"
	"net/url"
	"strings"
)

type Domain string

// Domains validates if the host in a URL is part of a list of domains.
type Domains []Domain

func GetDomains(entries []string) (Domains, error) {
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
		results = append(results, Domain(domain))
	}
	return results, nil
}

// Domain returns the domain that the host in the URL is part of. Returns false if the URL is not part of any domain.
func (d Domains) Domain(u *url.URL) (Domain, bool) {
	for _, domain := range d {
		if isValidSubdomain(domain, u.Host) {
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
