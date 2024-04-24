package session

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSession_newSessionFromCookie(t *testing.T) {
	secret := []byte("secret")
	s := NewSession("foo@example.com", time.Hour, secret)

	c := &http.Cookie{Value: s.Encode()}

	s2, err := newSessionFromCookie(c)
	require.NoError(t, err)
	assert.Equal(t, s.Encode(), s2.Encode())

	tests := []struct {
		name            string
		value           string
		wantNewErr      assert.ErrorAssertionFunc
		wantValidateErr assert.ErrorAssertionFunc
	}{
		{
			name:            "valid cookie",
			value:           NewSession("foo@example.com", time.Hour, secret).Encode(),
			wantNewErr:      assert.NoError,
			wantValidateErr: assert.NoError,
		},
		{
			name:            "expired cookie",
			value:           NewSession("foo@example.com", -time.Hour, secret).Encode(),
			wantNewErr:      assert.NoError,
			wantValidateErr: assert.Error,
		},
		{
			name:            "mac mismatch",
			value:           "0000" + NewSession("foo@example.com", time.Hour, secret).Encode()[4:],
			wantNewErr:      assert.NoError,
			wantValidateErr: assert.Error,
		},
		{
			name:            "invalid cookie",
			value:           "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantNewErr:      assert.Error,
			wantValidateErr: assert.Error,
		},
		{
			name:            "empty cookie",
			value:           "",
			wantNewErr:      assert.Error,
			wantValidateErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s, err := newSessionFromCookie(&http.Cookie{Value: tt.value})
			tt.wantNewErr(t, err)
			tt.wantValidateErr(t, s.validate(secret))
		})
	}
}

func TestSession_WriteCookie(t *testing.T) {
	s := Session{Email: "foo@example.com", expiration: time.Date(2024, time.April, 24, 0, 0, 0, 0, time.UTC), mac: []byte("1234")}
	w := httptest.NewRecorder()
	s.WriteCookie(w, "_name", "example.com")
	assert.Equal(t, "_name=313233340000000066284b80foo@example.com; Path=/; Domain=example.com; Expires=Wed, 24 Apr 2024 00:00:00 GMT; HttpOnly; Secure", w.Header().Get("Set-Cookie"))

	w = httptest.NewRecorder()
	Session{}.WriteCookie(w, "_name", "example.com")
	assert.Equal(t, "_name=; Path=/; Domain=example.com; HttpOnly; Secure", w.Header().Get("Set-Cookie"))
}
