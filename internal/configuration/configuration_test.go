package configuration

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGetConfiguration(t *testing.T) {
	_, err := GetConfiguration()
	assert.Error(t, err)

	*domains = "example.com"
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
		Users:             []string{"foo@example.com"},
		ClientID:          "clientId",
		ClientSecret:      "clientSecret",
		AuthPrefix:        "auth",
	}, cfg)

}
