package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// authenticator creates and validates JWT tokens inside an http.Cookie.
type authenticator struct {
	parser     *jwt.Parser
	CookieName string
	Domain     string
	Secret     []byte
	Expiration time.Duration
}

func newAuthenticator(cookieName string, domain string, secret []byte, expiration time.Duration) *authenticator {
	return &authenticator{
		CookieName: cookieName,
		Domain:     domain,
		Secret:     secret,
		Expiration: expiration,
		parser:     jwt.NewParser(jwt.WithValidMethods([]string{"HS256"})),
	}
}

// Authenticate extracts the JWT from an http.Request, validates it, and returns the User ID.
// It returns an error if the JWT is missing or invalid.
func (a *authenticator) Authenticate(r *http.Request) (string, error) {
	// retrieve the cookie
	cookie, err := r.Cookie(a.CookieName)
	if err != nil {
		return "", err
	}
	if cookie.Value == "" {
		return "", errors.New("cookie is empty")
	}

	// Parse and validate the JWT. We only accept HMAC256, since that's what we created.
	token, err := a.parser.Parse(cookie.Value, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Method.Alg())
		}
		return a.Secret, nil
	})
	if err != nil || !token.Valid { // Valid is only true if err == nil ?!?
		return "", fmt.Errorf("parse jwt: %w", err)
	}

	// Extract User Id
	userId, _ := token.Claims.GetSubject()
	if userId == "" {
		return "", errors.New("jwt: subject missing")
	}
	return userId, nil
}

// CookieWithSignedToken returns an http.Cookie with a signed token.
func (a *authenticator) CookieWithSignedToken(userID string) (*http.Cookie, error) {
	// Define claims
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(a.Expiration).Unix(),
		"iat": time.Now().Unix(),
	}

	// Create a new token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with the secret key
	signedToken, err := token.SignedString(a.Secret)
	if err != nil {
		return nil, err
	}
	return a.Cookie(signedToken, a.Expiration), nil
}

// Cookie returns a new http.Cookie for the provided token, expiration time, and domain.
func (a *authenticator) Cookie(token string, expiration time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     a.CookieName,
		Value:    token,
		MaxAge:   int(expiration.Seconds()),
		Path:     "/",
		Domain:   a.Domain,
		HttpOnly: true,
		Secure:   true,
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var (
	errInvalidUser   = errors.New("invalid user")
	errInvalidDomain = errors.New("invalid domain")
)

// The authorizer authorizes an HTTP request if the request comes from an authenticated user in the whitelist
// and if the URL is part of the configured Domain.
type authorizer struct {
	whitelist Whitelist
	domain    Domain
}

// AuthorizeRequest authorizes the request and, if valid, returns the username (email address) of the authenticated & authorized user.
func (a authorizer) AuthorizeRequest(r *http.Request) (string, error) {
	user, err := getUserInfo(r)
	if err != nil {
		return "", err
	}
	return user, a.Authorize(user, r.URL)
}

// Authorize authorizes the user and target URL.
func (a authorizer) Authorize(user string, u *url.URL) error {
	if !a.whitelist.Match(user) {
		return errInvalidUser
	}
	if !a.domain.Matches(u) {
		return errInvalidDomain
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// A Whitelist is a list of valid email addresses that the authorizer should accept.
type Whitelist map[string]struct{}

// NewWhitelist creates a new Whitelist for the provided email addresses.
func NewWhitelist(emails []string) (Whitelist, error) {
	list := make(map[string]struct{}, len(emails))
	for _, email := range emails {
		if email = strings.TrimSpace(email); email != "" {
			if _, err := mail.ParseAddress(email); err != nil {
				return nil, fmt.Errorf("invalid email address %q: %w", email, err)
			}
			list[strings.ToLower(email)] = struct{}{}
		}
	}
	return list, nil
}

// Match returns true if the email address is on the whitelist or if the whitelist is empty.
func (w *Whitelist) Match(email string) bool {
	if len(*w) == 0 {
		return true
	}
	_, ok := (*w)[strings.ToLower(email)]
	return ok
}

func (w *Whitelist) list() []string {
	list := make([]string, 0, len(*w))
	for email := range *w {
		list = append(list, email)
	}
	return list
}

func (w *Whitelist) Add(s ...string) error {
	newWhitelist, err := NewWhitelist(s)
	if err != nil {
		return err
	}
	if *w == nil {
		*w = newWhitelist
		return nil
	}
	for user := range newWhitelist {
		(*w)[strings.ToLower(user)] = struct{}{}
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// A Domain groups a set of hostnames (e.g. ".example.com" covers "www.example.com", "www2.example.com", etc),
// that the authorizer should accept.
type Domain string

// NewDomain returns a new Domain.  If the domain is not valid, an error is returned.
func NewDomain(domain string) (Domain, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}
	if domain[0] != '.' {
		domain = "." + domain
	}
	if _, port, _ := net.SplitHostPort(domain); port != "" {
		return "", fmt.Errorf("domain cannot contain port")
	}
	if _, err := url.Parse("https://www" + domain); err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	return Domain(domain), nil
}

// Matches returns true if the url is part of the Domain.
func (d Domain) Matches(u *url.URL) bool {
	host := strings.ToLower(u.Host)
	if n := strings.LastIndexByte(host, ':'); n != -1 {
		host = host[:n]
	}
	if Domain(host) == d[1:] {
		return true
	}
	return strings.HasSuffix(host, string(d))
}
