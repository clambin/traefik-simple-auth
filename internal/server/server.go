package server

import (
	"errors"
	"github.com/clambin/go-common/cache"
	"github.com/clambin/traefik-simple-auth/internal/configuration"
	"github.com/clambin/traefik-simple-auth/internal/server/session"
	"github.com/clambin/traefik-simple-auth/pkg/oauth"
	"github.com/clambin/traefik-simple-auth/pkg/whitelist"
	"golang.org/x/oauth2"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

const OAUTHPath = "/_oauth"

type Server struct {
	configuration.Configuration
	oauthHandlers map[string]oauth.Handler
	sessions      *session.Sessions
	stateHandler
	whitelist.Whitelist
	http.Handler
}

func New(config configuration.Configuration, l *slog.Logger) *Server {
	oauthHandlers := make(map[string]oauth.Handler)
	for _, domain := range config.Domains {
		var err error
		if oauthHandlers[domain], err = oauth.NewHandler(config.Provider, config.ClientID, config.ClientSecret, makeAuthURL(config.AuthPrefix, domain, OAUTHPath), l.With("oauth", config.Provider)); err != nil {
			panic("unknown provider: " + config.Provider)
		}
	}
	s := Server{
		Configuration: config,
		oauthHandlers: oauthHandlers,
		sessions:      session.New(config.SessionCookieName, config.Secret, config.Expiry),
		stateHandler: stateHandler{
			// 5 minutes should be enough for the user to log in
			cache: cache.New[string, string](5*time.Minute, time.Minute),
		},
		Whitelist: whitelist.New(config.Users),
	}

	h := http.NewServeMux()
	h.Handle(OAUTHPath, s.authCallbackHandler(l))
	h.HandleFunc(OAUTHPath+"/logout", s.logoutHandler(l))
	h.HandleFunc("/", s.authHandler(l))
	s.Handler = traefikParser()(h)
	return &s
}

func (s *Server) authHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "authHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		sess, err := s.sessions.Validate(r)
		if err != nil {
			if !errors.Is(err, http.ErrNoCookie) {
				l.Warn("error validating session", "err", err)
			}
			s.redirectToAuth(w, r, l)
			return
		}

		if _, ok := s.Domains.GetDomain(r.URL); !ok {
			l.Warn("host doesn't match any configured domains", "host", r.URL.Host)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		l.Debug("allowing valid request", "email", sess.Email)
		w.Header().Set("X-Forwarded-User", sess.Email)
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) redirectToAuth(w http.ResponseWriter, r *http.Request, l *slog.Logger) {
	// To protect against CSRF attacks, we generate a random state and associate it with the final destination of the request.
	// authCallbackHandler uses the random state to retrieve the final destination, thereby validating that the request came from us.
	encodedState, err := s.stateHandler.add(r.URL.String())
	if err != nil {
		l.Error("error adding to state cache", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	domain, ok := s.Domains.GetDomain(r.URL)
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
		redirectURL, ok := s.stateHandler.get(encodedState)
		if !ok {
			l.Warn("invalid state. Dropping request ...")
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		// we already validated the host vs the domain during the redirect
		// since the state matches, we can trust the request to be valid
		u, _ := url.Parse(redirectURL)
		domain, _ := s.Domains.GetDomain(u)

		// Use the "code" in the response to determine the user's email address.
		user, err := s.oauthHandlers[domain].GetUserEmailAddress(r.FormValue("code"))
		if err != nil {
			l.Error("failed to log in", "err", err)
			http.Error(w, "oauth2 failed", http.StatusBadGateway)
			return
		}
		l.Debug("user authenticated", "user", user)

		// Check that the user's email address is in the whitelist.
		if !s.Whitelist.Contains(user) {
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

		// get the domain for the target
		domain, _ := s.Domains.GetDomain(r.URL)

		// Write a blank session cookie to override the current valid one.
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
