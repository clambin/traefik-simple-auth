package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const sessionCookieName = "_simple_auth"

var (
	errCookieExpired      = errors.New("expired cookie")
	errCookieInvalidMAC   = errors.New("invalid MAC in cookie")
	errCookieInvalidValue = errors.New("invalid value in cookie")
)

type SessionCookie struct {
	Email  string
	Expiry time.Time
	Domain string
}

type SessionCookieHandler struct {
	SecureCookie bool
	Secret       []byte
}

func (h SessionCookieHandler) GetCookie(r *http.Request) (SessionCookie, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return SessionCookie{}, err
	}
	parts := strings.Split(c.Value, "|")
	if len(parts) != 3 {
		return SessionCookie{}, errCookieInvalidValue
	}

	calculatedMAC := calculateMAC(h.Secret, parts[0], parts[1])
	if calculatedMAC != parts[2] {
		return SessionCookie{}, errCookieInvalidMAC
	}

	unixTime, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return SessionCookie{}, errCookieInvalidValue
	}
	if time.Now().After(time.Unix(unixTime, 0)) {
		return SessionCookie{}, errCookieExpired
	}

	return SessionCookie{
		Email:  parts[0],
		Expiry: time.Unix(unixTime, 0),
	}, nil
}

func (h SessionCookieHandler) SaveCookie(w http.ResponseWriter, c SessionCookie) {
	var value string
	if c.Email != "" {
		parts := []string{c.Email, strconv.FormatInt(c.Expiry.Unix(), 10), ""}
		parts[2] = calculateMAC(h.Secret, parts[:2]...)
		value = strings.Join(parts, "|")
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Domain:   c.Domain,
		Expires:  c.Expiry,
		Secure:   h.SecureCookie,
		HttpOnly: true,
	})
}

func calculateMAC(secret []byte, parts ...string) string {
	hash := hmac.New(sha256.New, secret)
	for _, part := range parts {
		hash.Write([]byte(part))
	}
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}
