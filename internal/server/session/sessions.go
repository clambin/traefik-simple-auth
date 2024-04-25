package session

import (
	"fmt"
	"github.com/clambin/go-common/cache"
	"net/http"
	"time"
)

type Sessions struct {
	SessionCookieName string
	Secret            []byte
	Expiration        time.Duration
	cache             *cache.Cache[string, Session]
}

func New(cookieName string, secret []byte, expiration time.Duration) *Sessions {
	return &Sessions{
		SessionCookieName: cookieName,
		Secret:            secret,
		Expiration:        expiration,
		cache:             cache.New[string, Session](expiration, time.Minute),
	}
}

func (s Sessions) Validate(r *http.Request) (Session, error) {
	c, err := r.Cookie(s.SessionCookieName)
	if err != nil {
		return Session{}, err
	}
	session, err := newSessionFromCookie(c)
	if err != nil {
		return Session{}, err
	}
	if sess, ok := s.cache.Get(string(session.mac)); ok {
		return sess, nil
	}
	if err = session.validate(s.Secret); err != nil {
		return Session{}, fmt.Errorf("invalid session received: %w", err)
	}
	s.cache.AddWithExpiry(string(session.mac), session, time.Until(session.expiration))
	return session, nil
}

func (s Sessions) MakeSession(email string) Session {
	var session Session
	if email != "" {
		session = NewSession(email, s.Expiration, s.Secret)
	}
	s.cache.Add(string(session.mac), session)
	return session
}

func (s Sessions) DeleteSession(session Session) {
	s.cache.Remove(string(session.mac))
}

func (s Sessions) Cookie(session Session, domain string) *http.Cookie {
	var value string
	var expiration time.Time

	if session.Email != "" {
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
