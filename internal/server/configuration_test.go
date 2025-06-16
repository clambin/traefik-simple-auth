package server

import (
	"flag"
	"testing"
	"time"

	"codeberg.org/clambin/go-common/flagger"
	"github.com/clambin/traefik-simple-auth/internal/server/csrf"
	"github.com/stretchr/testify/assert"
)

func TestGetConfiguration(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Configuration
		err  assert.ErrorAssertionFunc
	}{
		{
			name: "invalid whitelist",
			args: []string{"-users", "bar"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "invalid secret",
			args: []string{"-users", "foo@example.com", "-secret", "invalid-secret"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "invalid domain",
			args: []string{"-users", "foo@example.com", "-secret", "12345678"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "missing clientID",
			args: []string{"-users", "foo@example.com", "-secret", "12345678", "-domain", ".example.com"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "missing clientSecret",
			args: []string{"-users", "foo@example.com", "-secret", "12345678", "-domain", ".example.com", "-oidc.client-id", "12345678"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "valid",
			args: []string{"-users", "foo@example.com", "-secret=12345678", "-domain=example.com", "-oidc.client-id=12345678", "-oidc.client-secret=12345678"},
			want: Configuration{
				Log:       flagger.DefaultLog,
				Prom:      flagger.DefaultProm,
				Session:   Session{CookieName: "_traefik_simple_auth", Expiration: 30 * 24 * time.Hour},
				Whitelist: Whitelist{"foo@example.com": struct{}{}},
				Addr:      ":8080",
				PProfAddr: "",
				Secret:    []uint8{0xd7, 0x6d, 0xf8, 0xe7, 0xae, 0xfc},
				Domain:    ".example.com",
				CSRF: csrf.Configuration{
					TTL:   10 * time.Minute,
					Redis: csrf.RedisConfiguration{Addr: "", Username: "", Password: "", Namespace: "github.com/clambin/traefik-simple-auth/state"},
				},
				OIDC: OIDC{Provider: "google", IssuerURL: "https://accounts.google.com", ClientID: "12345678", ClientSecret: "12345678", AuthPrefix: "auth"},
			},
			err: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := GetConfiguration(flag.NewFlagSet("test", flag.ContinueOnError), tt.args...)
			tt.err(t, err)
			assert.Equal(t, tt.want, cfg)
		})
	}
}
