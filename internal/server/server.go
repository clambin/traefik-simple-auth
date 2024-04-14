package server

import (
	"errors"
	"github.com/clambin/go-common/cache"
	"github.com/clambin/go-common/set"
	"github.com/clambin/traefik-simple-auth/internal/server/oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log/slog"
	"net/http"
	"time"
)

const oauthPath = "/_oauth"

type Server struct {
	http.Handler
	OAuthHandler
	sessionCookieHandler
	stateHandler
	config Config
}

type OAuthHandler interface {
	AuthCodeURL(state string) string
	Login(code string) (string, error)
}

type Config struct {
	Expiry         time.Duration
	Secret         []byte
	InsecureCookie bool
	Domain         string
	Users          set.Set[string]
	AuthHost       string
	ClientID       string
	ClientSecret   string
}

func New(config Config, l *slog.Logger) *Server {
	s := Server{
		config: config,
		OAuthHandler: oauth.Handler{
			HTTPClient: http.DefaultClient,
			Config: oauth2.Config{
				ClientID:     config.ClientID,
				ClientSecret: config.ClientSecret,
				Endpoint:     google.Endpoint,
				RedirectURL:  "https://" + config.AuthHost + oauthPath,
				Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			},
		},
		sessionCookieHandler: sessionCookieHandler{
			SecureCookie: !config.InsecureCookie,
			Secret:       config.Secret,
		},
		stateHandler: stateHandler{
			cache: cache.New[string, string](5*time.Second, 10*time.Minute),
		},
	}

	h := http.NewServeMux()
	h.Handle(oauthPath, s.AuthCallbackHandler(l))
	h.HandleFunc(oauthPath+"/logout", s.LogoutHandler(l))
	h.HandleFunc("/", s.AuthHandler(l))
	s.Handler = traefikParser()(h)
	return &s
}

func (s Server) AuthHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "AuthHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		c, err := s.GetCookie(r)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				l.Debug("no cookie found, redirecting ...")
			} else {
				l.Warn("invalid cookie. redirecting ...", "err", err)
			}
			s.authRedirect(w, r, l)
			return
		}

		// TODO: these two checks could be done in AuthCallbackHandler so we don't issue a cookie if these conditations aren't met
		if !s.config.Users.Contains(c.Email) {
			l.Debug("invalid user", "user", c.Email, "valid", s.config.Users.List())
			l.Warn("invalid user", "user", c.Email)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		if host := r.Host; !isValidSubdomain(s.config.Domain, host) {
			l.Warn("invalid host", "host", host, "domain", s.config.Domain)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		l.Debug("Allowing valid request", "email", c.Email)
		w.Header().Set("X-Forwarded-User", c.Email)
		w.WriteHeader(http.StatusOK)
	}
}

func (s Server) authRedirect(w http.ResponseWriter, r *http.Request, l *slog.Logger) {
	key, err := s.stateHandler.Add(r.URL.String())
	if err != nil {
		l.Error("error adding to state to cache", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	authCodeURL := s.OAuthHandler.AuthCodeURL(key)
	l.Debug("Redirecting", "authCodeURL", authCodeURL)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func (s Server) AuthCallbackHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "AuthCallbackHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		key := r.URL.Query().Get("state")
		redirectURL, ok := s.stateHandler.Get(key)
		if !ok {
			l.Warn("invalid state")
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		user, err := s.OAuthHandler.Login(r.FormValue("code"))
		if err != nil {
			l.Error("failed to log in to google", "err", err)
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		// login successful. add session cookie
		s.SaveCookie(w, sessionCookie{
			Email:  user,
			Expiry: time.Now().Add(s.config.Expiry),
			Domain: s.config.Domain,
		})

		l.Info("user logged in. redirecting ...", "user", user, "url", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	}
}

func (s Server) LogoutHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "LogoutHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		s.SaveCookie(w, sessionCookie{})
		http.Error(w, "You have been logged out", http.StatusUnauthorized)
		l.Info("user has been logged out")
	}
}

func isValidSubdomain(domain, subdomain string) bool {
	return len(subdomain) >= len(domain) && subdomain[len(subdomain)-len(domain):] == domain
}
