// Package sessions maintains a list of user sessions, each defined by a key.  Sessions can expire according to a shared
// expiration timer.  Sessions can extract a session from a http.Cookie and validate its integrity and expiry. Likewise,
// it can generate a new http.Cookie for a given session.
//
// Session integrity is protected through a HMAC256 hash, signed with a shared secret key.
package sessions

import (
	"github.com/clambin/go-common/cache"
	"net/http"
	"time"
)

// Sessions maintains a list of user sessions.
type Sessions struct {
	SessionCookieName string
	secret            []byte
	expiration        time.Duration
	sessions          *cache.Cache[string, Session]
}

// New returns an empty Sessions store.
func New(cookieName string, secret []byte, expiration time.Duration) Sessions {
	return Sessions{
		SessionCookieName: cookieName,
		secret:            secret,
		expiration:        expiration,
		sessions:          cache.New[string, Session](expiration, time.Minute),
	}
}

// NewSession creates a session for the given key, using the shared expiration time and returns it.
//
// Note: users may log in from multiple browsers, meaning multiple sessions can exist for a single user.
// NewSession does not delete any existing Sessions for the given key. It only adds a new Session.
func (s Sessions) NewSession(key string) Session {
	return s.NewSessionWithExpiration(key, s.expiration)
}

// NewSessionWithExpiration creates a session for the given key & expiration time and returns it.
//
// Note: users may log in from multiple browsers, meaning multiple sessions can exist for a single user.
// NewSessionWithExpiration does not delete any existing Sessions for the given key. It only adds a new Session.
func (s Sessions) NewSessionWithExpiration(key string, expiration time.Duration) Session {
	var userSession Session
	if key != "" {
		userSession = newSession(key, expiration, s.secret)
	}
	s.sessions.AddWithExpiry(string(userSession.mac), userSession, expiration)
	return userSession
}

// DeleteSession deletes the session.
func (s Sessions) DeleteSession(session Session) {
	s.sessions.Remove(string(session.mac))
}

// Validate extracts the session cookie from the http.Request and validates the session.
func (s Sessions) Validate(r *http.Request) (Session, error) {
	c, err := r.Cookie(s.SessionCookieName)
	if err != nil {
		return Session{}, err
	}
	userSession, err := sessionFromCookie(c)
	if err != nil {
		return Session{}, err
	}
	if cachedSession, ok := s.sessions.Get(string(userSession.mac)); ok {
		return cachedSession, nil
	}
	if err = userSession.validate(s.secret); err != nil {
		return Session{}, err
	}
	s.sessions.AddWithExpiry(string(userSession.mac), userSession, time.Until(userSession.expiration))
	return userSession, nil
}

// Cookie returns a cookie for the given session and domain.
func (s Sessions) Cookie(session Session, domain string) *http.Cookie {
	var value string
	var expiration time.Time

	if session.Key != "" {
		value = session.encode()
		expiration = session.expiration
	}

	return &http.Cookie{
		Name:     s.SessionCookieName,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		Expires:  expiration,
		Secure:   true,
		HttpOnly: true,
	}
}

// ActiveUsers returns all active (non-expired) sessions.
//
// Given that a user may be logged in from different browsers, multiple sessions may exist for the same key.
// ActiveUsers returns the count of sessions per key as a map[string]int.
func (s Sessions) ActiveUsers() map[string]int {
	activeUsers := make(map[string]int)
	for _, activeUser := range s.sessions.Iterate() {
		activeUsers[activeUser.Key]++
	}
	return activeUsers
}

// Contains returns true if a valid (non-expired) session exists for the provided key.
func (s Sessions) Contains(key string) bool {
	for _, session := range s.sessions.Iterate() {
		if session.Key == key {
			return true
		}
	}
	return false
}

// Count returns the number of valid (non-expired) sessions.
func (s Sessions) Count() int {
	return s.sessions.Len()
}
