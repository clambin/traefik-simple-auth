package auth

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"time"
)

// Authenticator creates and validate JWT tokens inside a Cookie of an HTTP request / response.
type Authenticator struct {
	Secret     []byte
	CookieName string
	Expiration time.Duration
}

// JWTCookie returns an HTTP Cookie with a new JWT.
func (s Authenticator) JWTCookie(userID string, domain string) (*http.Cookie, error) {
	token, err := s.makeToken(userID)
	if err != nil {
		return nil, fmt.Errorf("unable to make token: %w", err)
	}
	return s.Cookie(token, time.Now().Add(s.Expiration), domain), nil
}

// Cookie returns a new HTTP Cookie for the provided token, expiration time and domain.
func (s Authenticator) Cookie(token string, expires time.Time, domain string) *http.Cookie {
	return &http.Cookie{
		Name:     s.CookieName,
		Value:    token,
		Expires:  expires,
		Path:     "/",
		Domain:   domain,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

func (s Authenticator) makeToken(userID string) (string, error) {
	// Define claims
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(s.Expiration).Unix(),
		"iat":     time.Now().Unix(),
	}

	// Create a new token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	return token.SignedString(s.Secret)
}

// Validate extracts the JWT from the HTTP requests, validates it and returns the User ID.
// It returns an error if the JWT is missing or invalid.
func (s Authenticator) Validate(r *http.Request) (string, error) {
	// retrieve the cookie
	cookie, err := r.Cookie(s.CookieName)
	if err != nil {
		return "", fmt.Errorf("cookie not found: %w", err)
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return s.Secret, nil
	})
	if err != nil {
		return "", fmt.Errorf("parse jwt: %w", err)
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid jwt token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid jwt claims type: %T", token.Claims)
	}
	return claims["user_id"].(string), nil
}
