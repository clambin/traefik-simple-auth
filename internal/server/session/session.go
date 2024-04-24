package session

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

type Session struct {
	Email      string
	expiration time.Time
	mac        []byte
}

func NewSession(email string, expiration time.Duration, secret []byte) Session {
	expiry := time.Now().Add(expiration)
	return Session{
		Email:      email,
		expiration: expiry,
		mac:        calculateMAC(secret, []byte(email), binary.BigEndian.AppendUint64(nil, uint64(expiry.Unix()))),
	}
}
func newSessionFromCookie(c *http.Cookie) (Session, error) {
	const macSize = 32                   // 256 bits
	const timeSize = 8                   // 64 bits
	const encodedMACSize = 2 * macSize   // 2 * 256 bits
	const encodedTimeSize = 2 * timeSize // 2 * 64 bits

	value := c.Value
	if len(value) < encodedMACSize+encodedTimeSize {
		return Session{}, errors.New("invalid structure")
	}

	bin, err := hex.DecodeString(value[:encodedMACSize+encodedTimeSize])
	if err != nil {
		return Session{}, errors.New("invalid structure")
	}

	value = value[encodedMACSize+encodedTimeSize:]

	mac := bin[:macSize]

	return Session{Email: value, expiration: time.Unix(int64(binary.BigEndian.Uint64(bin[macSize:])), 0), mac: mac}, nil
}

func (s Session) WriteCookie(w http.ResponseWriter, cookieName string, domain string) {
	var value string
	var expiration time.Time

	if s.Email != "" {
		value = s.Encode()
		expiration = s.expiration
	}

	c := http.Cookie{
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		Expires:  expiration,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, &c)
}

func (s Session) Encode() string {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(s.expiration.Unix()))
	return hex.EncodeToString(s.mac) + hex.EncodeToString(ts) + s.Email
}

func (s Session) validate(secret []byte) error {
	if s.expiration.Before(time.Now()) {
		return errors.New("session expired")
	}
	mac := calculateMAC(secret, []byte(s.Email), binary.BigEndian.AppendUint64(nil, uint64(s.expiration.Unix())))
	if !bytes.Equal(s.mac, mac) {
		return errors.New("invalid mac")
	}
	return nil
}

func calculateMAC(secret []byte, parts ...[]byte) []byte {
	hash := hmac.New(sha256.New, secret)
	for _, part := range parts {
		hash.Write(part)
	}
	return hash.Sum(nil)
}
