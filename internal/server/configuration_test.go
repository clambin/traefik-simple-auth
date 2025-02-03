package server

import (
	"bytes"
	"flag"
	"github.com/clambin/traefik-simple-auth/internal/server/state"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
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
				Whitelist:         Whitelist{"foo@example.com": struct{}{}},
				Addr:              ":8080",
				PromAddr:          ":9090",
				PProfAddr:         "",
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
		{
			name: "with pprof",
			args: []string{"test", "-pprof", ":6000", "-users", "foo@example.com", "-secret", "12345678", "-domain", ".example.com", "-client-id", "12345678", "-client-secret", "12345678"},
			want: Configuration{
				Whitelist:         Whitelist{"foo@example.com": struct{}{}},
				Addr:              ":8080",
				PromAddr:          ":9090",
				PProfAddr:         ":6000",
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
