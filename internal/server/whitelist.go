package server

import "strings"

type whitelist map[string]struct{}

func newWhitelist(emails []string) whitelist {
	list := make(map[string]struct{})
	for _, email := range emails {
		list[strings.ToLower(email)] = struct{}{}
	}
	return list
}

func (w whitelist) contains(email string) bool {
	_, ok := w[strings.ToLower(email)]
	return ok
}

func (w whitelist) list() []string {
	list := make([]string, 0, len(w))
	for email := range w {
		list = append(list, email)
	}
	return list
}
