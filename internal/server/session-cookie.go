package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"
)

const sessionCookieName = "_traefik_simple_auth"

var (
	errCookieExpired          = errors.New("expired cookie")
	errCookieInvalidMAC       = errors.New("cookie has invalid MAC")
	errCookieInvalidStructure = errors.New("cookie has invalid structure")
)

type sessionCookie struct {
	Email  string
	Expiry time.Time
	Domain string
}

func (c *sessionCookie) encode(secret []byte) string {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(c.Expiry.Unix()))
	mac := calculateMAC(secret, ts, []byte(c.Email))
	return hex.EncodeToString(mac) + hex.EncodeToString(ts) + c.Email
}

func (c *sessionCookie) decode(secret []byte, s string) error {
	const macSize = 32                   // 256 bits
	const timeSize = 8                   // 64 bits
	const encodedMACSize = 2 * macSize   // 2 * 256 bits
	const encodedTimeSize = 2 * timeSize // 2 * 64 bits

	if len(s) < encodedMACSize+encodedTimeSize {
		return errCookieInvalidStructure
	}
	bin, err := hex.DecodeString(s[:encodedMACSize+encodedTimeSize])
	if err != nil {
		return errCookieInvalidStructure
	}
	s = s[encodedMACSize+encodedTimeSize:]

	mac := bin[:macSize]
	calcMac := calculateMAC(secret, bin[macSize:], []byte(s))
	if bytes.Compare(mac, calcMac) != 0 {
		return errCookieInvalidMAC
	}

	c.Expiry = time.Unix(int64(binary.BigEndian.Uint64(bin[macSize:])), 0)
	c.Email = s
	return nil
}

func calculateMAC(secret []byte, parts ...[]byte) []byte {
	hash := hmac.New(sha256.New, secret)
	for _, part := range parts {
		hash.Write(part)
	}
	return hash.Sum(nil)
}

type sessionCookieHandler struct {
	SecureCookie bool
	Secret       []byte
	lock         sync.Mutex
	sessions     map[string]sessionCookie
}

func (h *sessionCookieHandler) getUser(c *http.Cookie) (string, error) {
	h.lock.Lock()
	defer h.lock.Unlock()

	sc, ok := h.sessions[c.Value]
	if !ok {
		if err := sc.decode(h.Secret, c.Value); err != nil {
			return "", err
		}
	}
	if sc.Expiry.Before(time.Now()) {
		return "", errCookieExpired
	}

	if !ok {
		h.sessions[sc.encode(h.Secret)] = sc
	}
	return sc.Email, nil
}

func (h *sessionCookieHandler) deleteSession(c *http.Cookie) {
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.sessions, c.Value)
}

func (h *sessionCookieHandler) saveCookie(c sessionCookie) {
	var value string
	if c.Email != "" {
		value = c.encode(h.Secret)
	}

	h.lock.Lock()
	defer h.lock.Unlock()
	if value != "" {
		h.sessions[value] = c
	} else {
		delete(h.sessions, c.Email)
	}
}
