package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/clambin/go-common/cache"
	"github.com/clambin/go-common/set"
	"github.com/clambin/traefik-simple-auth/internal/server/oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const oauthPath = "/_oauth"
const nonceSize = 32

type Server struct {
	OAuthHandler
	SessionCookieHandler
	cache  *cache.Cache[string, string]
	config Config
}

type OAuthHandler interface {
	Login(code string) (string, error)
	AuthCodeURL(state string) string
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

func New(config Config, l *slog.Logger) http.Handler {
	s := Server{
		config: config,
		cache:  cache.New[string, string](5*time.Minute, time.Hour),

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
		SessionCookieHandler: SessionCookieHandler{
			SecureCookie: !config.InsecureCookie,
			Secret:       config.Secret,
		},
	}

	h := http.NewServeMux()
	h.Handle(oauthPath, s.AuthCallbackHandler(l))
	h.HandleFunc(oauthPath+"/logout", s.LogoutHandler(l))
	h.HandleFunc("/", s.AuthHandler(l))

	return traefikParser()(h)
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
	key := make([]byte, nonceSize)
	if _, err := rand.Read(key); err != nil {
		l.Error("error generating random key", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
	encodedKey := hex.EncodeToString(key)
	s.cache.Add(encodedKey, r.URL.String())

	authCodeURL := s.OAuthHandler.AuthCodeURL(encodedKey)
	l.Debug("Redirecting", "authCodeURL", authCodeURL)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func (s Server) AuthCallbackHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "AuthCallbackHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		key := r.URL.Query().Get("state")
		redirectURL, ok := s.cache.Get(key)
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
		s.SaveCookie(w, SessionCookie{
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

		s.SaveCookie(w, SessionCookie{})
		http.Error(w, "You have been logged out", http.StatusUnauthorized)
		l.Info("user has been logged out")
	}
}

func isValidSubdomain(domain, subdomain string) bool {
	return len(subdomain) >= len(domain) && subdomain[len(subdomain)-len(domain):] == domain
}

var _ slog.LogValuer = loggedRequest{}

type loggedRequest struct{ r *http.Request }

func (r loggedRequest) LogValue() slog.Value {
	cookies := make([]string, 0, 1)
	for _, c := range r.r.Cookies() {
		if c.Name == sessionCookieName {
			cookies = append(cookies, c.Name)
		}
	}
	return slog.GroupValue(
		slog.String("http", r.r.URL.String()),
		slog.String("traefik", getOriginalTarget(r.r)),
		slog.String("cookies", strings.Join(cookies, ",")),
		slog.String("source", r.r.Header.Get("X-Forwarded-For")),
	)
}
