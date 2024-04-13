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
	errCookieExpired          = errors.New("expired cookie")
	errCookieInvalidMAC       = errors.New("cookie has invalid MAC")
	errCookieInvalidStructure = errors.New("cookie has invalid structure")
)

type sessionCookie struct {
	Email  string
	Expiry time.Time
	Domain string
}

type sessionCookieHandler struct {
	SecureCookie bool
	Secret       []byte
}

func (h sessionCookieHandler) GetCookie(r *http.Request) (sessionCookie, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || len(c.Value) == 0 {
		return sessionCookie{}, http.ErrNoCookie
	}

	parts := strings.Split(c.Value, "|")
	if len(parts) != 3 {
		return sessionCookie{}, errCookieInvalidStructure
	}

	calculatedMAC := calculateMAC(h.Secret, parts[0], parts[1])
	if calculatedMAC != parts[2] {
		return sessionCookie{}, errCookieInvalidMAC
	}

	unixTime, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return sessionCookie{}, errCookieInvalidStructure
	}
	if time.Now().After(time.Unix(unixTime, 0)) {
		return sessionCookie{}, errCookieExpired
	}

	return sessionCookie{
		Email:  parts[0],
		Expiry: time.Unix(unixTime, 0),
	}, nil
}

func (h sessionCookieHandler) SaveCookie(w http.ResponseWriter, c sessionCookie) {
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
