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
			name: "valid",
			args: []string{"-users=foo@example.com", "-session.secret=c2VjcmV0", "-domain=example.com", "-auth.client-id=12345678", "-auth.client-secret=12345678"},
			want: Configuration{
				Log:  flagger.DefaultLog,
				Prom: flagger.DefaultProm,
				Session: Session{
					CookieName: "_traefik_simple_auth",
					Secret:     []byte("secret"),
					Expiration: 30 * 24 * time.Hour,
				},
				Whitelist: Whitelist{"foo@example.com": struct{}{}},
				Addr:      ":8080",
				PProfAddr: "",
				Domain:    ".example.com",
				CSRFConfiguration: csrf.Configuration{
					TTL:   10 * time.Minute,
					Redis: csrf.RedisConfiguration{Addr: "", Username: "", Password: "", Namespace: "github.com/clambin/traefik-simple-auth/state"},
				},
				Auth: Auth{Provider: "google", IssuerURL: "https://accounts.google.com", ClientID: "12345678", ClientSecret: "12345678", AuthPrefix: "auth"},
			},
			err: assert.NoError,
		},
		{
			name: "invalid whitelist",
			args: []string{"-users=invalid-user", "-session.secret=12345678", "-domain=example.com", "-auth.client-id=12345678", "-auth.client-secret=12345678"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "invalid secret",
			args: []string{"-users=foo@example.com", "-session.secret=invalid-secret", "-domain=example.com", "-auth.client-id=12345678", "-auth.client-secret=12345678"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "invalid domain",
			args: []string{"-users=foo@example.com", "-session.secret=12345678", "-auth.client-id=12345678", "-auth.client-secret=12345678"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "missing clientID",
			args: []string{"-users=foo@example.com", "-session.secret=12345678", "-domain=example.com", "-auth.client-secret=12345678"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "missing clientSecret",
			args: []string{"-users=foo@example.com", "-session.secret=session.12345678", "-domain=example.com", "-auth.client-id=12345678"},
			want: Configuration{},
			err:  assert.Error,
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
