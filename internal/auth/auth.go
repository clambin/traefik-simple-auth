package auth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

// Authenticator creates and validate JWT tokens inside a http.Cookie.
type Authenticator struct {
	CookieName string
	Secret     []byte
	Expiration time.Duration
	parser     *jwt.Parser
}

func New(cookieName string, secret []byte, expiration time.Duration) *Authenticator {
	return &Authenticator{
		CookieName: cookieName,
		Secret:     secret,
		Expiration: expiration,
		parser:     jwt.NewParser(jwt.WithValidMethods([]string{"HS256"})),
	}
}

// CookieWithSignedToken returns a http.Cookie with a signed token.
func (a *Authenticator) CookieWithSignedToken(userID string, domain string) (c *http.Cookie, err error) {
	var token string
	if token, err = a.makeSignedToken(userID); err == nil {
		c = a.Cookie(token, a.Expiration, domain)
	}
	return c, err
}

func (a *Authenticator) makeSignedToken(userID string) (string, error) {
	// Define claims
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(a.Expiration).Unix(),
		"iat": time.Now().Unix(),
	}

	// Create a new token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	return token.SignedString(a.Secret)
}

// Cookie returns a new http.Cookie for the provided token, expiration time and domain.
func (a *Authenticator) Cookie(token string, expiration time.Duration, domain string) *http.Cookie {
	return &http.Cookie{
		Name:     a.CookieName,
		Value:    token,
		MaxAge:   int(expiration.Seconds()),
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   true,
		//SameSite: http.SameSiteStrictMode,
	}
}

// Validate extracts the JWT from an http.Request, validates it and returns the User ID.
// It returns an error if the JWT is missing or invalid.
func (a *Authenticator) Validate(r *http.Request) (userId string, err error) {
	// retrieve the cookie
	var cookie *http.Cookie
	if cookie, err = r.Cookie(a.CookieName); err != nil {
		return "", err
	}

	// Parse and validate the JWT. We only accept HMAC256, since that's what we created.
	token, err := a.parser.Parse(cookie.Value, a.getKey)
	if err != nil || !token.Valid { // Valid is only true if err == nil ?!?
		return "", fmt.Errorf("parse jwt: %w", err)
	}

	// Extract User Id
	if userId, _ = token.Claims.GetSubject(); userId == "" {
		return "", errors.New("jwt: subject missing")
	}
	return userId, nil
}

func (a *Authenticator) getKey(token *jwt.Token) (any, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
	}
	return a.Secret, nil
}
