package sessions

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
	"time"
)

func TestSession_newSessionFromCookie(t *testing.T) {
	secret := []byte("secret")
	tests := []struct {
		name          string
		value         string
		wantCookieErr error
	}{
		{
			name:          "valid cookie",
			value:         newSession("foo@example.com", time.Hour, secret).encode(),
			wantCookieErr: nil,
		},
		{
			name:          "invalid cookie",
			value:         "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			wantCookieErr: ErrInvalidCookie,
		},
		{
			name:          "empty cookie",
			value:         "",
			wantCookieErr: http.ErrNoCookie,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, err := sessionFromCookie(&http.Cookie{Value: tt.value})
			assert.ErrorIs(t, err, tt.wantCookieErr)
			if err == nil {
				assert.NoError(t, s.validate(secret))
			}
		})
	}
}

func TestSession_validate(t *testing.T) {
	secret := []byte("secret")
	validSession := newSession("foo@example.com", time.Hour, secret)
	tests := []struct {
		name    string
		session Session
		wantErr error
	}{
		{
			name:    "valid",
			session: validSession,
			wantErr: nil,
		},
		{
			name:    "expired session",
			session: newSession("foo@example.com", -time.Hour, secret),
			wantErr: ErrSessionExpired,
		},
		{
			name: "invalid mac",
			session: Session{
				Email:      validSession.Email,
				expiration: validSession.expiration,
				mac:        append([]byte("0000"), validSession.mac[4:]...),
			},
			wantErr: ErrInvalidMAC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.ErrorIs(t, tt.session.validate(secret), tt.wantErr)
		})
	}
}
