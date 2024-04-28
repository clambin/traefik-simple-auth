package domains

import (
	"fmt"
	"net/url"
	"strings"
)

// Domains validates if the host in a URL is part of a list of subdomains.
type Domains []string

func GetDomains(entries []string) (Domains, error) {
	var results Domains
	for _, domain := range entries {
		if domain != "" {
			if domain[0] != '.' {
				domain = "." + domain
			}
			if _, err := url.Parse("https://www" + domain); err != nil {
				return nil, fmt.Errorf("invalid domain %q: %w", domain, err)
			}
			results = append(results, domain)
		}
	}
	return results, nil
}

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
