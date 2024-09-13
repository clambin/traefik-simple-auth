package testutils

import (
	"net/http"
)

func ForwardAuthRequest(method, host, uri string) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "https://traefik/", nil)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	req.Header.Set("User-Agent", "unit-test")
	return req
}
