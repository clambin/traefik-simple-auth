package server

import (
	"github.com/clambin/go-common/cache"
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
	Config
	oauthHandlers map[string]OAuthHandler
	sessionCookieHandler
	stateHandler
	whitelist.Whitelist
	http.Handler
}

type OAuthHandler interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	GetUserEmailAddress(code string) (string, error)
}

type Config struct {
	Expiry         time.Duration
	Secret         []byte
	InsecureCookie bool
	Provider       string
	Domains        Domains
	Users          []string
	ClientID       string
	ClientSecret   string
	AuthPrefix     string
}

func New(config Config, l *slog.Logger) *Server {
	oauthHandlers := make(map[string]OAuthHandler)
	for _, domain := range config.Domains {
		h, err := oauth.NewHandler(config.Provider, config.ClientID, config.ClientSecret, config.AuthPrefix, domain, OAUTHPath)
		if err != nil {
			panic(err)
		}
		oauthHandlers[domain] = h
	}
	s := Server{
		Config:        config,
		oauthHandlers: oauthHandlers,
		sessionCookieHandler: sessionCookieHandler{
			SecureCookie: !config.InsecureCookie,
			Secret:       config.Secret,
			Expiry:       config.Expiry,
			sessions:     cache.New[string, sessionCookie](config.Expiry, time.Minute),
		},
		stateHandler: stateHandler{
			// 5 minutes should be enough for the user to log in to Google
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

		c, err := r.Cookie(sessionCookieName)
		if err != nil || c.Value == "" {
			// Client doesn't have a valid cookie. Redirect to Google to authenticate the user.
			// When the user is authenticated, authCallbackHandler generates a new valid cookie.
			l.Debug("no cookie found, redirecting ...")
			s.redirectToAuth(w, r, l)
			return
		}
		session, err := s.getSessionCookie(c)
		if err != nil {
			// Client has an invalid cookie. Redirect to Google to authenticate the user.
			// When the user is authenticated, authCallbackHandler generates a new valid cookie.
			l.Warn("invalid cookie. redirecting ...", "err", err)
			s.redirectToAuth(w, r, l)
			return
		}
		if session.expired() {
			// Client has an expired cookie. Redirect to Google to authenticate the user.
			// When the user is authenticated, authCallbackHandler generates a new valid cookie.
			l.Debug("expired cookie. redirecting ...")
			s.redirectToAuth(w, r, l)
			return

		}

		if _, ok := s.Domains.getDomain(r.URL); !ok {
			l.Warn("host doesn't match any configured domains", "host", r.URL.Host)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		l.Debug("allowing valid request", "email", session.Email)
		w.Header().Set("X-Forwarded-User", session.Email)
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

	domain, ok := s.Domains.getDomain(r.URL)
	if !ok {
		l.Error("invalid target host", "host", r.URL.Host)
		http.Error(w, "Invalid target host", http.StatusUnauthorized)
		return
	}

	// Redirect user to Google to select the account to be used to authenticate the request
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
		domain, _ := s.Domains.getDomain(u)

		// Use the "code" in the response to determine the user's email address.
		user, err := s.oauthHandlers[domain].GetUserEmailAddress(r.FormValue("code"))
		if err != nil {
			l.Error("failed to log in to google", "err", err)
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
		sc := sessionCookie{
			Email:  user,
			Expiry: time.Now().Add(s.Config.Expiry),
		}
		s.sessionCookieHandler.saveCookie(sc)

		http.SetCookie(w, s.makeCookie(sc.encode(s.Config.Secret), domain))
		l.Info("user logged in. redirecting ...", "user", user, "url", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	}
}

func (s *Server) logoutHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "logoutHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		// remove the cached cookie
		if c, err := r.Cookie(sessionCookieName); err == nil {
			s.deleteSessionCookie(c)
		}

		// get the domain for the target
		domain, _ := s.Domains.getDomain(r.URL)

		// Write a blank session cookie to override the current valid one.
		http.SetCookie(w, s.makeCookie("", domain))

		http.Error(w, "You have been logged out", http.StatusUnauthorized)
		l.Info("user has been logged out")
	}
}

func (s *Server) makeCookie(value, domain string) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Domain:   domain,
		Path:     "/",
		Secure:   !s.InsecureCookie,
		HttpOnly: true,
	}
}
