package configuration

import (
	"bytes"
	"flag"
	"github.com/clambin/traefik-simple-auth/internal/state"
	"github.com/clambin/traefik-simple-auth/internal/whitelist"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

/*
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
				Domain:        domain.Domain(".example.com"),
				Whitelist:     whitelist.Whitelist{"foo@example.com": struct{}{}},
				ClientID:      "123456789",
				ClientSecret:  "1234567890",
				AuthPrefix:    "auth"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*domainString = tt.args.domainsString
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
*/

func TestGetConfiguration(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Configuration
		err  assert.ErrorAssertionFunc
	}{
		{
			name: "invalid whitelist",
			args: []string{"test", "-users", "bar"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "invalid secret",
			args: []string{"test", "-users", "foo@example.com", "-secret", "invalid-secret"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "invalid domain",
			args: []string{"test", "-users", "foo@example.com", "-secret", "12345678"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "missing clientID",
			args: []string{"test", "-users", "foo@example.com", "-secret", "12345678", "-domain", ".example.com"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "missing clientSecret",
			args: []string{"test", "-users", "foo@example.com", "-secret", "12345678", "-domain", ".example.com", "-client-id", "12345678"},
			want: Configuration{},
			err:  assert.Error,
		},
		{
			name: "valid",
			args: []string{"test", "-users", "foo@example.com", "-secret", "12345678", "-domain", ".example.com", "-client-id", "12345678", "-client-secret", "12345678"},
			want: Configuration{
				Whitelist:         whitelist.Whitelist{"foo@example.com": struct{}{}},
				Addr:              ":8080",
				PromAddr:          ":9090",
				SessionCookieName: "_traefik_simple_auth",
				Provider:          "google",
				OIDCIssuerURL:     "https://accounts.google.com",
				ClientID:          "12345678",
				ClientSecret:      "12345678",
				AuthPrefix:        "auth",
				Secret:            []uint8{0xd7, 0x6d, 0xf8, 0xe7, 0xae, 0xfc},
				Domain:            ".example.com",
				StateConfiguration: state.Configuration{
					CacheType: "memory",
					Namespace: "github.com/clambin/traefik-simple-auth/state",
					MemcachedConfiguration: state.MemcachedConfiguration{
						Addr: "",
					},
					RedisConfiguration: state.RedisConfiguration{
						Addr:     "",
						Username: "",
						Password: "",
						Database: 0,
					},
					TTL: 10 * time.Minute,
				},
				SessionExpiration: 30 * 24 * time.Hour,
				Debug:             false,
			},
			err: assert.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
			os.Args = tt.args

			cfg, err := GetConfiguration()
			tt.err(t, err)
			assert.Equal(t, tt.want, cfg)
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
