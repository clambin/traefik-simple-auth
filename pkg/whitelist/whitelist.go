// Package whitelist maintains a list of whitelisted email addresses. It is used by traefik-simple-auth to validate that
// requests for an authenticated user should be allowed.
package whitelist

import (
	"fmt"
	"net/mail"
	"strings"
)

type Whitelist map[string]struct{}

// New creates a new Whitelist for the provided email addresses.
func New(emails []string) (Whitelist, error) {
	list := make(map[string]struct{}, len(emails))
	for _, email := range emails {
		email = strings.TrimSpace(email)
		if email != "" {
			if _, err := mail.ParseAddress(email); err != nil {
				return nil, fmt.Errorf("invalid email address %q: %w", email, err)
			}
			list[strings.ToLower(email)] = struct{}{}
		}
	}
	return list, nil
}

// Match returns true if the email address is on the whitelist, or if the whitelist is empty.
func (w Whitelist) Match(email string) bool {
	if len(w) == 0 {
		return true
	}
	_, ok := w[strings.ToLower(email)]
	return ok
}

func (w Whitelist) list() []string {
	list := make([]string, 0, len(w))
	for email := range w {
		list = append(list, email)
	}
	return list
}
