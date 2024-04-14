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
	tests := []struct {
		name    string
		value   string
		wantErr error
	}{
		{
			name:    "no cookie",
			wantErr: http.ErrNoCookie,
		},
		{
			name:    "invalid cookie",
			value:   "foo@example.com|1234",
			wantErr: errCookieInvalidStructure,
		},
		{
			name:    "invalid mac",
			value:   "foo@example.com|123456789|mac",
			wantErr: errCookieInvalidMAC,
		},
		{
			name:    "invalid timestamp",
			value:   "foo@example.com|abcd|2nXfiuQLTAhWCnSRymk2ynqnja6knT7DAlCu9fQsLpw=",
			wantErr: errCookieInvalidStructure,
		},
		{
			name:    "expired cookie",
			value:   "foo@example.com|123456789|cbaZTEq2adeyQ1Slwhhhv-SOwObTB-4me_4CA_EG6Ew=",
			wantErr: errCookieExpired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := sessionCookieHandler{
				SecureCookie: true,
				Secret:       []byte("secret"),
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
