package whitelist

import "strings"

type Whitelist map[string]struct{}

// New creates a new Whitelist for the provided email addresses
func New(emails []string) Whitelist {
	list := make(map[string]struct{}, len(emails))
	for _, email := range emails {
		list[strings.ToLower(email)] = struct{}{}
	}
	return list
}

// Contains returns true if the email address is on the whitelist
func (w Whitelist) Contains(email string) bool {
	_, ok := w[strings.ToLower(email)]
	return ok
}

// Match returns true if the email address is on the whitelist, or if the whitelist is empty
func (w Whitelist) Match(email string) bool {
	if len(w) == 0 {
		return true
	}
	return w.Contains(email)
}

func (w Whitelist) list() []string {
	list := make([]string, 0, len(w))
	for email := range w {
		list = append(list, email)
	}
	return list
}
