package cmd

import (
	"context"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/internal/server/testutils"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/prometheus/client_golang/prometheus"
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
	cfg := server.Configuration{
		Debug:             true,
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
		err := Run(ctx, cfg, prometheus.NewRegistry(), os.Stderr, "dev")
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
	code, location, err := doForwardAuth(&c, "http://localhost:8081/", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, code)
	assert.NotEmpty(t, location)

	// call the oauth provider. this will redirect us to the authCallback flow
	code, location, _, err = doDirect(&c, location, cfg.SessionCookieName)
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, code)
	assert.NotEmpty(t, location)
	oauthURL, err := url.Parse(location)
	require.NoError(t, err)

	// call the authCallback flow. RawQuery contains the code & state. this will redirect us back to the forwardAuth
	// flow and gives us a session cookie.
	var cookie *http.Cookie
	code, _, cookie, err = doDirect(&c, "http://localhost:8081"+oauthURL.Path+"?"+oauthURL.RawQuery, cfg.SessionCookieName)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, code)
	require.NotNil(t, cookie)

	// try again, now with the session cookie. this time, we are authenticated.
	code, _, err = doForwardAuth(&c, "http://localhost:8081/", cookie)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)

	// health now gives us 1 session and 1 (used) state
	resp, err := http.Get("http://localhost:8081/health")
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.Equal(t, "{\"sessions\":1,\"states\":0}\n", string(body))

	cancel()

	// wait for shutdown
	assert.Eventually(t, func() bool {
		_, err = http.Get("http://localhost:8081/health")
		return err != nil
	}, time.Second, 10*time.Millisecond)
}

func TestRun_Fail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)

	go func() {
		<-ctx.Done()
		require.NoError(t, oidcServer.Shutdown())
	}()
	cfg := server.Configuration{
		Debug:             true,
		Addr:              ":-1",
		PromAddr:          ":-1",
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
	assert.Error(t, Run(ctx, cfg, prometheus.NewRegistry(), os.Stderr, "dev"))
}

func doForwardAuth(c *http.Client, target string, cookie *http.Cookie) (int, string, error) {
	req := testutils.ForwardAuthRequest(http.MethodGet, "www.example.com", "/")
	var err error
	if req.URL, err = url.Parse(target); err != nil {
		return 0, "", fmt.Errorf("url: %w", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	_ = resp.Body.Close()
	var redirectURL string
	if resp.StatusCode == http.StatusTemporaryRedirect {
		redirectURL = resp.Header.Get("Location")
	}

	return resp.StatusCode, redirectURL, nil
}

func doDirect(c *http.Client, target string, sessionCookieName string) (int, string, *http.Cookie, error) {
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	_ = resp.Body.Close()
	var redirectURL string
	if resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusFound {
		redirectURL = resp.Header.Get("Location")
	}
	var cookie *http.Cookie
	for _, cookie = range resp.Cookies() {
		if cookie.Name == sessionCookieName {
			break
		}
	}
	return resp.StatusCode, redirectURL, cookie, nil
}
