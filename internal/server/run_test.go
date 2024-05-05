package server

import (
	"context"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)

	go func() {
		<-ctx.Done()
		require.NoError(t, oidcServer.Shutdown())
	}()
	cfg := Configuration{
		Debug:             false,
		Addr:              ":8081",
		PromAddr:          ":9091",
		SessionCookieName: "_auth",
		Expiration:        time.Hour,
		Secret:            []byte("secret"),
		Provider:          "oidc",
		OIDCIssuerURL:     oidcServer.Issuer(),
		Domains:           domains.Domains{".example.com"},
		Whitelist:         whitelist.Whitelist{"jane.doe@example.com": struct{}{}},
		ClientID:          oidcServer.ClientID,
		ClientSecret:      oidcServer.ClientSecret,
		AuthPrefix:        "auth",
	}
	go func() {
		err := Run(ctx, cfg, os.Stderr, "dev")
		require.NoError(t, err)
	}()

	assert.Eventually(t, func() bool {
		resp, err := http.Get("http://localhost:8081/health")
		return err == nil && resp.StatusCode == http.StatusOK
	}, time.Second, 10*time.Millisecond)

	c := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     http.DefaultTransport,
	}

	// not logged in. server responds with a redirect, pointing to the oauth provider
	req := makeForwardAuthRequest(http.MethodGet, "www.example.com", "/")
	req.URL, _ = url.Parse("http://localhost:8081/")
	resp, err := c.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	target := resp.Header.Get("Location")

	// call the oauth provider. this will redirect us to the authCallback flow
	req, _ = http.NewRequest(http.MethodGet, target, nil)
	resp, err = c.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	oauthURL, _ := url.Parse(resp.Header.Get("Location"))

	// call the authCallback flow. RawQuery contains the code & state. this will redirect us back to the forwardAuth
	// flow and gives us a session cookie.
	req, _ = http.NewRequest(http.MethodGet, "http://localhost:8081"+oauthURL.Path+"?"+oauthURL.RawQuery, nil)
	resp, err = c.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode)
	var cookie *http.Cookie
	for _, cookie = range resp.Cookies() {
		if cookie.Name == cfg.SessionCookieName {
			break
		}
	}
	require.NotNil(t, cookie)

	// try again, now with the session cookie. this time, we are authenticated.
	req = makeForwardAuthRequest(http.MethodGet, "www.example.com", "/")
	req.URL, _ = url.Parse("http://localhost:8081/")
	req.AddCookie(cookie)
	resp, err = c.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// health now gives us 1 session and 1 (used) state
	resp, err = http.Get("http://localhost:8081/health")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "{\"sessions\":1,\"states\":0}\n", string(body))

	cancel()

	// wait for shutdown
	assert.Eventually(t, func() bool {
		_, err := http.Get("http://localhost:8081/health")
		return err != nil
	}, time.Second, 10*time.Millisecond)
}
