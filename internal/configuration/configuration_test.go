package configuration

import (
	"bytes"
	"github.com/clambin/traefik-simple-auth/internal/domains"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGetConfiguration(t *testing.T) {
	type args struct {
		domainsString string
		users         string
		secret        string
		clientID      string
		clientSecret  string
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
		want    Configuration
	}{
		{
			name:    "empty",
			wantErr: assert.Error,
		},
		{
			name: "invalid domains",
			args: args{
				domainsString: " ",
			},
			wantErr: assert.Error,
		},
		{
			name: "invalid whitelist",
			args: args{
				domainsString: "example.com",
				users:         "9",
			},
			wantErr: assert.Error,
		},
		{
			name: "missing secret",
			args: args{
				domainsString: "example.com",
				users:         "foo@example.com",
			},
			wantErr: assert.Error,
		},
		{
			name: "invalid secret",
			args: args{
				domainsString: "example.com",
				users:         "foo@example.com",
				secret:        "secret",
			},
			wantErr: assert.Error,
		},
		{
			name: "missing clientID",
			args: args{
				domainsString: "example.com",
				users:         "foo@example.com",
				secret:        "c2VjcmV0Cg==",
			},
			wantErr: assert.Error,
		},
		{
			name: "missing clientSecret",
			args: args{
				domainsString: "example.com",
				users:         "foo@example.com",
				secret:        "c2VjcmV0Cg==",
				clientID:      "123456789",
			},
			wantErr: assert.Error,
		},
		{
			name: "valid",
			args: args{
				domainsString: "example.com",
				users:         "foo@example.com",
				secret:        "c2VjcmV0Cg==",
				clientID:      "123456789",
				clientSecret:  "1234567890",
			},
			wantErr: assert.NoError,
			want: Configuration{
				Debug:             false,
				Addr:              ":8080",
				PromAddr:          ":9090",
				SessionCookieName: "_traefik_simple_auth",
				SessionExpiration: 30 * 24 * time.Hour,
				StateConfiguration: state.Configuration{
					CacheType: "memory",
					Namespace: "github.com/clambin/traefik-simple-auth/state",
					TTL:       10 * time.Minute,
				},
				Secret:        []byte("secret\n"),
				Provider:      "google",
				OIDCIssuerURL: "https://accounts.google.com",
				Domains:       domains.Domains{".example.com"},
				Whitelist:     whitelist.Whitelist{"foo@example.com": struct{}{}},
				ClientID:      "123456789",
				ClientSecret:  "1234567890",
				AuthPrefix:    "auth"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*domainsString = tt.args.domainsString
			*users = tt.args.users
			*secret = tt.args.secret
			*clientId = tt.args.clientID
			*clientSecret = tt.args.clientSecret

			cfg, err := GetConfiguration()
			tt.wantErr(t, err)
			if err == nil {
				assert.Equal(t, tt.want, cfg)
			}
		})
	}
}

func TestConfiguration_Logger(t *testing.T) {
	var cfg Configuration
	var out bytes.Buffer

	l := cfg.Logger(&out)
	l.Debug("debug message")
	assert.Empty(t, out.String())

	cfg.Debug = true
	l = cfg.Logger(&out)
	l.Debug("debug message")
	assert.Contains(t, out.String(), `"msg":"debug message"`)
}
