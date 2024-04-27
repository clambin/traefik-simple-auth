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

func New(cookieName string, secret []byte, expiration time.Duration) *Sessions {
	return &Sessions{
		SessionCookieName: cookieName,
		Secret:            secret,
		Expiration:        expiration,
		sessions:          cache.New[string, Session](expiration, time.Minute),
	}
}

func (s Sessions) Validate(r *http.Request) (Session, error) {
	c, err := r.Cookie(s.SessionCookieName)
	if err != nil {
		return Session{}, err
	}
	session, err := sessionFromCookie(c)
	if err != nil {
		return Session{}, err
	}
	if sess, ok := s.sessions.Get(string(session.mac)); ok {
		return sess, nil
	}
	if err = session.validate(s.Secret); err != nil {
		return Session{}, err
	}
	s.sessions.AddWithExpiry(string(session.mac), session, time.Until(session.expiration))
	return session, nil
}

func (s Sessions) MakeSession(email string) Session {
	return s.MakeSessionWithExpiration(email, s.Expiration)
}

func (s Sessions) MakeSessionWithExpiration(email string, expiration time.Duration) Session {
	var sess Session
	if email != "" {
		sess = newSession(email, expiration, s.Secret)
	}
	s.sessions.AddWithExpiry(string(sess.mac), sess, expiration)
	return sess
}

func (s Sessions) DeleteSession(session Session) {
	s.sessions.Remove(string(session.mac))
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
