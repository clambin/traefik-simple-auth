package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionCookieParser_SaveCookie(t *testing.T) {
	p := SessionCookieHandler{
		SecureCookie: false,
		Secret:       []byte("secret"),
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := SessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour), Domain: ".example.com"}
		p.SaveCookie(w, c)
	}))
	defer s.Close()

	resp, err := http.Get(s.URL)
	if err != nil {
		t.Fatalf("Failed to get session cookie from %s: %v", s.URL, err)
	}
	var found bool
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			if got := c.Domain; got != "example.com" {
				t.Errorf("got cookie domain %v, want %v", got, "example.com")
			}
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Session cookie %s not found", sessionCookieName)
	}
}

func TestSessionCookieParser_GetCookie(t *testing.T) {
	p := SessionCookieHandler{
		SecureCookie: false,
		Secret:       []byte("secret"),
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Helper()
		c, err := p.GetCookie(r)
		if err != nil {
			t.Fatalf("Failed to get cookie: %v", err)
		}
		if c.Email != "foo@example.com" {
			t.Errorf("got cookie email %v, want %v", c.Email, "foo@example.com")
		}
	}))
	defer s.Close()

	w := httptest.NewRecorder()
	p.SaveCookie(w, SessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour), Domain: ".example.com"})
	rawCookie := strings.TrimPrefix(strings.Split(w.Header().Get("Set-Cookie"), ";")[0], sessionCookieName+"=")

	req, _ := http.NewRequest(http.MethodGet, s.URL, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: rawCookie})

	_, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("Failed to send session cookie: %v", err)
	}
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
			p := SessionCookieHandler{
				SecureCookie: true,
				Secret:       []byte("secret"),
			}

			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.value != "" {
				r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tt.value})
			}

			_, err := p.GetCookie(r)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetCookie() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
