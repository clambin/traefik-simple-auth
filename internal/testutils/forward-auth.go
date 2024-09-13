package testutils

import (
	"fmt"
	"net/http"
	"net/url"
)

func ForwardAuthRequest(method, target string) *http.Request {
	addr, err := url.Parse(target)
	if err != nil {
		panic(fmt.Sprintf("invalid url %q: %s", target, err.Error()))
	}
	if addr.Scheme != "http" && addr.Scheme != "https" {
		panic(fmt.Sprintf("invalid url scheme %q, expected http or https", addr.Scheme))
	}
	path := addr.Path
	if path == "" {
		path = "/"
	}
	if len(addr.Query()) > 0 {
		path += "?" + addr.Query().Encode()
	}
	req, _ := http.NewRequest(http.MethodGet, "https://traefik/", nil)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Proto", addr.Scheme)
	req.Header.Set("X-Forwarded-Host", addr.Host)
	req.Header.Set("X-Forwarded-Uri", path)
	req.Header.Set("User-Agent", "unit-test")
	return req
}
