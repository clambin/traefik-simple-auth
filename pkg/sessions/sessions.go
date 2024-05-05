package sessions

import (
	"github.com/clambin/go-common/cache"
	"net/http"
	"time"
)

type Sessions struct {
	SessionCookieName string
	Secret            []byte
	Expiration        time.Duration
	sessions          *cache.Cache[string, Session]
}

func New(cookieName string, secret []byte, expiration time.Duration) Sessions {
	return Sessions{
		SessionCookieName: cookieName,
		Secret:            secret,
		Expiration:        expiration,
		sessions:          cache.New[string, Session](expiration, time.Minute),
	}
}

func (s Sessions) Session(email string) Session {
	return s.SessionWithExpiration(email, s.Expiration)
}

func (s Sessions) SessionWithExpiration(email string, expiration time.Duration) Session {
	var userSession Session
	if email != "" {
		userSession = newSession(email, expiration, s.Secret)
	}
	s.sessions.AddWithExpiry(string(userSession.mac), userSession, expiration)
	return userSession
}

func (s Sessions) DeleteSession(session Session) {
	s.sessions.Remove(string(session.mac))
}

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
	if err = userSession.validate(s.Secret); err != nil {
		return Session{}, err
	}
	s.sessions.AddWithExpiry(string(userSession.mac), userSession, time.Until(userSession.expiration))
	return userSession, nil
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

func (s Sessions) ActiveUsers() map[string]int {
	activeUsers := make(map[string]int)
	for _, key := range s.sessions.GetKeys() {
		activeSession, _ := s.sessions.Get(key)
		if !activeSession.expired() {
			activeUsers[activeSession.Email] = activeUsers[activeSession.Email] + 1
		}
	}
	return activeUsers
}

func (s Sessions) Contains(email string) bool {
	for _, key := range s.sessions.GetKeys() {
		sess, _ := s.sessions.Get(key)
		if sess.Email == email {
			return true
		}
	}
	return false
}

func (s Sessions) Count() int {
	return s.sessions.Len()
}
