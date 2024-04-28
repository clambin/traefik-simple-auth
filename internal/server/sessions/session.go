package sessions

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

var (
	ErrInvalidCookie  = errors.New("cookie contains invalid session")
	ErrInvalidMAC     = errors.New("invalid MAC")
	ErrSessionExpired = errors.New("session expired")
)

type Session struct {
	Email      string
	expiration time.Time
	mac        []byte
}

func newSession(email string, expiration time.Duration, secret []byte) Session {
	expiry := time.Now().Add(expiration)
	return Session{
		Email:      email,
		expiration: expiry,
		mac:        calculateMAC(secret, []byte(email), binary.BigEndian.AppendUint64(nil, uint64(expiry.Unix()))),
	}
}
func sessionFromCookie(c *http.Cookie) (Session, error) {
	const macSize = 32                   // 256 bits
	const timeSize = 8                   // 64 bits
	const encodedMACSize = 2 * macSize   // 2 * 256 bits
	const encodedTimeSize = 2 * timeSize // 2 * 64 bits

	value := c.Value
	if value == "" {
		return Session{}, http.ErrNoCookie
	}

	if len(value) < encodedMACSize+encodedTimeSize {
		return Session{}, ErrInvalidCookie
	}

	bin, err := hex.DecodeString(value[:encodedMACSize+encodedTimeSize])
	if err != nil {
		return Session{}, ErrInvalidCookie
	}

	value = value[encodedMACSize+encodedTimeSize:]
	mac := bin[:macSize]

	return Session{Email: value, expiration: time.Unix(int64(binary.BigEndian.Uint64(bin[macSize:])), 0), mac: mac}, nil
}

func (s Session) encode() string {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(s.expiration.Unix()))
	return hex.EncodeToString(s.mac) + hex.EncodeToString(ts) + s.Email
}

func (s Session) validate(secret []byte) error {
	mac := calculateMAC(secret, []byte(s.Email), binary.BigEndian.AppendUint64(nil, uint64(s.expiration.Unix())))
	if !bytes.Equal(s.mac, mac) {
		return ErrInvalidMAC
	}
	if s.expired() {
		return ErrSessionExpired
	}
	return nil
}

func (s Session) expired() bool {
	return s.expiration.Before(time.Now())
}

func calculateMAC(secret []byte, parts ...[]byte) []byte {
	hash := hmac.New(sha256.New, secret)
	for _, part := range parts {
		hash.Write(part)
	}
	return hash.Sum(nil)
}
