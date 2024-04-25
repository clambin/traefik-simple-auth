package session

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessions_Validate(t *testing.T) {
	secret := []byte("secret")
	tests := []struct {
		name      string
		cookie    *http.Cookie
		wantErr   assert.ErrorAssertionFunc
		wantEmail string
	}{
		{
			name:      "valid cookie",
			cookie:    &http.Cookie{Name: "_name", Value: NewSession("foo@example.com", time.Hour, secret).encode()},
			wantErr:   assert.NoError,
			wantEmail: "foo@example.com",
		},
		{
			name:      "valid cookie (cached)",
			cookie:    &http.Cookie{Name: "_name", Value: NewSession("foo@example.com", time.Hour, secret).encode()},
			wantErr:   assert.NoError,
			wantEmail: "foo@example.com",
		},
		{
			name:    "missing cookie",
			cookie:  nil,
			wantErr: assert.Error,
		},
		{
			name:    "expired cookie",
			cookie:  &http.Cookie{Name: "_name", Value: NewSession("foo@example.com", -time.Hour, secret).encode()},
			wantErr: assert.Error,
		},
		{
			name:    "invalid cookie",
			cookie:  &http.Cookie{Name: "_name", Value: "bad-data"},
			wantErr: assert.Error,
		},
	}

	s := New("_name", secret, time.Hour)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.cookie != nil {
				r.AddCookie(tt.cookie)
			}
			session, err := s.Validate(r)
			tt.wantErr(t, err)
			if err == nil {
				assert.NoError(t, session.validate(secret))
				assert.Equal(t, tt.wantEmail, session.Email)
			}
		})
	}
}

func BenchmarkSessions_Validate(b *testing.B) {
	secret := []byte("secret")
	s := New("_name", secret, time.Hour)
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{
		Name:  "_name",
		Value: NewSession("foo@example.com", time.Hour, secret).encode(),
	})

	for range b.N {
		if _, err := s.Validate(r); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSessions_DeleteSession(t *testing.T) {
	secret := []byte("secret")
	s := New("_name", secret, time.Hour)

	session := s.MakeSession("foo@example.com")
	assert.NoError(t, session.validate(secret))
	assert.Equal(t, 1, s.cache.Len())

	s.DeleteSession(session)
	assert.Equal(t, 0, s.cache.Len())
}

func TestSessions_Cookie(t *testing.T) {
	sessions := New("_name", []byte("secret"), time.Hour)
	s := Session{Email: "foo@example.com", expiration: time.Date(2024, time.April, 24, 0, 0, 0, 0, time.UTC), mac: []byte("1234")}
	w := httptest.NewRecorder()
	http.SetCookie(w, sessions.Cookie(s, "example.com"))
	assert.Equal(t, "_name=313233340000000066284b80foo@example.com; Path=/; Domain=example.com; Expires=Wed, 24 Apr 2024 00:00:00 GMT; HttpOnly; Secure", w.Header().Get("Set-Cookie"))

	w = httptest.NewRecorder()
	http.SetCookie(w, sessions.Cookie(Session{}, "example.com"))
	assert.Equal(t, "_name=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))

}
