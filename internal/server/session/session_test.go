package session

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func TestSession_newSessionFromCookie(t *testing.T) {
	secret := []byte("secret")
	s := NewSession("foo@example.com", time.Hour, secret)

	c := &http.Cookie{Value: s.encode()}

	s2, err := newSessionFromCookie(c)
	require.NoError(t, err)
	assert.Equal(t, s.encode(), s2.encode())

	tests := []struct {
		name            string
		value           string
		wantNewErr      assert.ErrorAssertionFunc
		wantValidateErr assert.ErrorAssertionFunc
	}{
		{
			name:            "valid cookie",
			value:           NewSession("foo@example.com", time.Hour, secret).encode(),
			wantNewErr:      assert.NoError,
			wantValidateErr: assert.NoError,
		},
		{
			name:            "expired cookie",
			value:           NewSession("foo@example.com", -time.Hour, secret).encode(),
			wantNewErr:      assert.NoError,
			wantValidateErr: assert.Error,
		},
		{
			name:            "mac mismatch",
			value:           "0000" + NewSession("foo@example.com", time.Hour, secret).encode()[4:],
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
