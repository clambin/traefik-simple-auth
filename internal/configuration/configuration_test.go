package configuration

import (
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
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
				Expiry:            30 * 24 * time.Hour,
				Secret:            []byte("secret\n"),
				Provider:          "google",
				Domains:           domains.Domains{".example.com"},
				Whitelist:         whitelist.Whitelist{"foo@example.com": struct{}{}},
				ClientID:          "123456789",
				ClientSecret:      "1234567890",
				AuthPrefix:        "auth"},
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
	/*
		*domainsString = "example.com"
		_, err = GetConfiguration()
		assert.Error(t, err)

		*secret = "not-a-valid-secret"
		_, err = GetConfiguration()
		assert.Error(t, err)

		*secret = hex.EncodeToString([]byte("secret"))
		_, err = GetConfiguration()
		assert.Error(t, err)

		*clientId = "clientId"
		_, err = GetConfiguration()
		assert.Error(t, err)

		*clientSecret = "clientSecret"
		_, err = GetConfiguration()
		assert.Error(t, err)

		*users = "foo@example.com"
		cfg, err := GetConfiguration()
		assert.NoError(t, err)

		assert.Equal(t, Configuration{
			Addr:              ":8080",
			PromAddr:          ":9090",
			SessionCookieName: "_traefik_simple_auth",
			Expiry:            720 * time.Hour,
			Secret:            []byte{0xef, 0x7e, 0xb9, 0xeb, 0x7e, 0xf6, 0xeb, 0x9e, 0xf8},
			Provider:          "google",
			Domains:           []string{".example.com"},
			Whitelist:         map[string]struct{}{"foo@example.com": {}},
			ClientID:          "clientId",
			ClientSecret:      "clientSecret",
			AuthPrefix:        "auth",
		}, cfg)
	*/
}
