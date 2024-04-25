package server

import (
	"errors"
	"github.com/clambin/go-common/http/middleware"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/session"
	"github.com/clambin/traefik-simple-auth/pkg/domains"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/state"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

const OAUTHPath = "/_oauth"

type Server struct {
	oauthHandlers map[string]oauth.Handler
	sessions      *session.Sessions
	store         state.Store[string]
	whitelist     whitelist.Whitelist
	domains       domains.Domains
	http.Handler
}

func New(config configuration.Configuration, m *Metrics, l *slog.Logger) *Server {
	oauthHandlers := make(map[string]oauth.Handler)
	for _, d := range config.Domains {
		var err error
		if oauthHandlers[d], err = oauth.NewHandler(config.Provider, config.ClientID, config.ClientSecret, makeAuthURL(config.AuthPrefix, d, OAUTHPath), l.With("oauth", config.Provider)); err != nil {
			panic("unknown provider: " + config.Provider)
		}
	}
	s := Server{
		oauthHandlers: oauthHandlers,
		sessions:      session.New(config.SessionCookieName, config.Secret, config.Expiry),
		store:         state.New[string](5 * time.Minute),
		whitelist:     whitelist.New(config.Users),
		domains:       config.Domains,
	}

	mw := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}
	if m != nil {
		// TODO: ugly!!!
		m.server = &s
		mw = middleware.WithRequestMetrics(m)
	}

	h := http.NewServeMux()
	h.Handle(OAUTHPath, s.authCallbackHandler(l))
	h.Handle(OAUTHPath+"/logout", s.logoutHandler(l))
	h.Handle("/", s.authHandler(l))
	s.Handler = traefikForwardAuthParser()(mw(h))
	return &s
}

func (s *Server) authHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "authHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		// validate that the request has a valid session cookie
		sess, err := s.sessions.Validate(r)
		if err != nil {
			if !errors.Is(err, http.ErrNoCookie) {
				l.Warn("error validating session", "err", err)
			}
			s.redirectToAuth(w, r, l)
			return
		}

		// check that the request is for one of the configured domains
		if _, ok := s.domains.Domain(r.URL); !ok {
			l.Warn("host doesn't match any configured domains", "host", r.URL.Host)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// all good. tell traefik to forward the request
		l.Debug("allowing valid request", "email", sess.Email)
		w.Header().Set("X-Forwarded-User", sess.Email)
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) redirectToAuth(w http.ResponseWriter, r *http.Request, l *slog.Logger) {
	// To protect against CSRF attacks, we generate a random state and associate it with the final destination of the request.
	// authCallbackHandler uses the random state to retrieve the final destination, thereby validating that the request came from us.
	encodedState := s.store.Add(r.URL.String())

	domain, ok := s.domains.Domain(r.URL)
	if !ok {
		l.Error("invalid target host", "host", r.URL.Host)
		http.Error(w, "Invalid target host", http.StatusUnauthorized)
		return
	}

	// Redirect user to oauth provider to select the account to be used to authenticate the request
	authCodeURL := s.oauthHandlers[domain].AuthCodeURL(encodedState, oauth2.SetAuthURLParam("prompt", "select_account"))
	l.Debug("redirecting ...", "authCodeURL", authCodeURL)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func (s *Server) authCallbackHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "authCallbackHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		// Look up the (random) state to find the final destination.
		encodedState := r.URL.Query().Get("state")
		redirectURL, ok := s.store.Get(encodedState)
		if !ok {
			l.Warn("invalid state. Dropping request ...")
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		// we already validated the host vs the domain during the redirect.
		// since the state matches, we can trust the request to be valid.
		u, _ := url.Parse(redirectURL)
		domain, _ := s.domains.Domain(u)

		// Use the "code" in the response to determine the user's email address.
		user, err := s.oauthHandlers[domain].GetUserEmailAddress(r.FormValue("code"))
		if err != nil {
			l.Error("failed to log in", "err", err)
			http.Error(w, "oauth2 failed", http.StatusBadGateway)
			return
		}
		l.Debug("user authenticated", "user", user)

		// Check that the user's email address is in the whitelist.
		if !s.whitelist.Contains(user) {
			l.Warn("not a valid user. rejecting ...", "user", user)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// GetUserEmailAddress successful. Add session cookie and redirect the user to the final destination.
		sess := s.sessions.MakeSession(user)
		http.SetCookie(w, s.sessions.Cookie(sess, domain))

		l.Info("user logged in. redirecting ...", "user", user, "url", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	}
}

func (s *Server) logoutHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "logoutHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		// remove the cached cookie
		if sess, err := s.sessions.Validate(r); err == nil {
			s.sessions.DeleteSession(sess)
		}

		// Write a blank session cookie to override the current valid one.
		domain, _ := s.domains.Domain(r.URL)
		http.SetCookie(w, s.sessions.Cookie(session.Session{}, domain))

		http.Error(w, "You have been logged out", http.StatusUnauthorized)
		l.Info("user has been logged out")
	}
}

// makeAuthURL returns the auth URL for a given domain
func makeAuthURL(authPrefix, domain, OAUTHPath string) string {
	var dot string
	if domain != "" && domain[0] != '.' {
		dot = "."
	}
	return "https://" + authPrefix + dot + domain + OAUTHPath
}
