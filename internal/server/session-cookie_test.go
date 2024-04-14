package server

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionCookie_codec(t *testing.T) {
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

func BenchmarkSessionCookie_decode(b *testing.B) {
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

func TestSessionCookieParser_SaveCookie(t *testing.T) {
	p := sessionCookieHandler{
		SecureCookie: false,
		Secret:       []byte("secret"),
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour), Domain: ".example.com"}
		p.SaveCookie(w, c)
	}))
	defer s.Close()

	resp, err := http.Get(s.URL)
	require.NoErrorf(t, err, "failed to get session cookie from %s", s.URL)

	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			found = true
			assert.Equalf(t, "example.com", c.Domain, "unexpected domain in session cookie")
			break
		}
	}
	require.Truef(t, found, "session cookie %s not found", s.URL)
}

func TestSessionCookieParser_GetCookie(t *testing.T) {
	p := sessionCookieHandler{
		SecureCookie: false,
		Secret:       []byte("secret"),
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Helper()
		c, err := p.GetCookie(r)
		require.NoError(t, err)
		if !assert.Equal(t, "foo@example.com", c.Email) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}))
	defer s.Close()

	w := httptest.NewRecorder()
	p.SaveCookie(w, sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour), Domain: ".example.com"})
	rawCookie := strings.TrimPrefix(strings.Split(w.Header().Get("Set-Cookie"), ";")[0], sessionCookieName+"=")

	req, _ := http.NewRequest(http.MethodGet, s.URL, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: rawCookie})

	_, err := http.DefaultClient.Do(req)
	assert.NoError(t, err)
}

func TestSessionCookieParser_GetCookie_Validation(t *testing.T) {
	secret := []byte("secret")
	sc := sessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)}
	goodCookie := sc.encode(secret)
	sc.Expiry = time.Now().Add(-time.Hour)
	expiredCookie := sc.encode(secret)

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
			name:    "expired cookie",
			value:   expiredCookie,
			wantErr: errCookieExpired,
		},
		{
			name:    "invalid cookie",
			value:   "0000" + goodCookie[4:],
			wantErr: errCookieInvalidMAC,
		},
		{
			name:    "no cookie",
			wantErr: http.ErrNoCookie,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := sessionCookieHandler{
				SecureCookie: true,
				Secret:       secret,
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.value != "" {
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tt.value})
			}

			_, err := p.GetCookie(r)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
