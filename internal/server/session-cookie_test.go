package server

import (
	"github.com/clambin/go-common/cache"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

func Test_sessionCookie_codec(t *testing.T) {
	c := sessionCookie{
		Expiry: time.Date(2024, time.April, 14, 0, 0, 0, 0, time.Local),
	}
	secret := []byte("secret")
	encoded := c.encode(secret)

	tests := []struct {
		name    string
		input   string
		wantErr assert.ErrorAssertionFunc
		want    sessionCookie
	}{
		{
			name:    "valid",
			input:   encoded,
			wantErr: assert.NoError,
			want:    c,
		},
		{
			name:    "mac mismatch",
			input:   "0000" + encoded[4:],
			wantErr: assert.Error,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: assert.Error,
		},
		{
			name:    "mac too short",
			input:   encoded[:10],
			wantErr: assert.Error,
		},
		{
			name:    "mac invalid",
			input:   "zzzz" + encoded[4:],
			wantErr: assert.Error,
		},
		{
			name:    "ts too short",
			input:   encoded[:70],
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var c2 sessionCookie
			err := c2.decode(secret, tt.input)
			tt.wantErr(t, err)

			if err == nil {
				assert.Equal(t, tt.want, c2)
			}
		})
	}
}

func Benchmark_sessionCookie_decode(b *testing.B) {
	c := sessionCookie{}
	secret := []byte("secret")
	encoded := c.encode(secret)

	b.ResetTimer()
	for range b.N {
		if err := c.decode(secret, encoded); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSessionCookieHandler_getSessionCookie(t *testing.T) {
	secret := []byte("secret")
	sc := sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)}
	goodCookie := sc.encode(secret)
	sc.Expiry = time.Now().Add(-time.Hour)

	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{
			name:    "valid",
			value:   goodCookie,
			wantErr: nil,
		},
		{
			name:    "invalid cookie",
			value:   "0000" + goodCookie[4:],
			wantErr: errCookieInvalidMAC,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := sessionCookieHandler{
				SecureCookie: true,
				Secret:       secret,
				sessions:     cache.New[string, sessionCookie](time.Hour, time.Minute),
			}

			_, err := handler.getSessionCookie(&http.Cookie{Value: tt.value})
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
