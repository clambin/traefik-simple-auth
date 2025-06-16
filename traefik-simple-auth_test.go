package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/clambin/traefik-simple-auth/internal/testutils"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	oidcServer, err := mockoidc.Run()
	require.NoError(t, err)

	var g errgroup.Group
	g.Go(func() error {
		<-ctx.Done()
		return oidcServer.Shutdown()
	})

	cfg := server.DefaultConfiguration
	cfg.Secret = []byte("secret")
	cfg.Provider = "oidc"
	cfg.IssuerURL = oidcServer.Issuer()
	cfg.ClientID = oidcServer.ClientID
	cfg.ClientSecret = oidcServer.ClientSecret
	cfg.Domain = ".example.com"
	cfg.Whitelist = server.Whitelist{"jane.doe@example.com": struct{}{}}

	//l := testutils.DiscardLogger
	l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	g.Go(func() error {
		return run(ctx, cfg, prometheus.NewRegistry(), l)
	})

	assert.Eventually(t, func() bool {
		resp, err := http.Get("http://localhost:8080/health")
		if err == nil {
			_ = resp.Body.Close()
		}
		return err == nil && resp.StatusCode == http.StatusOK
	}, time.Second, 10*time.Millisecond)

	c := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     http.DefaultTransport,
	}

	// no cookie provided. server responds with a redirect, pointing to the oauth provider
	code, location, err := doForwardAuth(&c, "http://localhost:8080/", nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, code)
	assert.NotEmpty(t, location)

	// call the oauth provider. this will redirect us to the authCallback flow
	code, location, _, err = doDirect(&c, location, cfg.CookieName)
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, code)
	assert.NotEmpty(t, location)
	oauthURL, err := url.Parse(location)
	require.NoError(t, err)

	// call the authCallback flow. RawQuery contains the code & state. this will redirect us back to the forwardAuth
	// flow and gives us a session cookie.
	var cookie *http.Cookie
	code, _, cookie, err = doDirect(&c, "http://localhost:8080"+oauthURL.Path+"?"+oauthURL.RawQuery, cfg.CookieName)
	require.NoError(t, err)
	assert.Equal(t, http.StatusTemporaryRedirect, code)
	require.NotNil(t, cookie)
	assert.Equal(t, cfg.CookieName, cookie.Name)

	// try again, now with the session cookie. this time, we are authenticated.
	code, _, err = doForwardAuth(&c, "http://localhost:8080/", cookie)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, code)

	cancel()
	assert.NoError(t, g.Wait())
}

/*
	func TestRun_Fail(t *testing.T) {
		oidcServer, err := mockoidc.Run()
		require.NoError(t, err)
		t.Cleanup(func() { _ = oidcServer.Shutdown() })

		cfg := server.Configuration{
			Debug:             true,
			Addr:              ":-1",
			PromAddr:          ":-1",
			SessionCookieName: "_auth",
			Secret:            []byte("secret"),
			Provider:          "oidc",
			OIDCIssuerURL:     oidcServer.Issuer(),
			Domain:            server.Domain(".example.com"),
			Whitelist:         server.Whitelist{"jane.doe@example.com": struct{}{}},
			ClientID:          oidcServer.ClientID,
			ClientSecret:      oidcServer.ClientSecret,
			AuthPrefix:        "auth",
			StateConfiguration: authn.Configuration{
				TTL:       time.Hour,
				CacheType: "memory",
			},
		}
		assert.Error(t, run(t.Context(), cfg, prometheus.NewRegistry(), "dev", testutils.DiscardLogger))
	}
*/
func doForwardAuth(c *http.Client, target string, cookie *http.Cookie) (int, string, error) {
	req := testutils.ForwardAuthRequest(http.MethodGet, "https://www.example.com/")
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
