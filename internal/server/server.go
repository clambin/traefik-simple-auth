package server

import (
	"errors"
	"github.com/clambin/go-common/cache"
	"github.com/clambin/traefik-simple-auth/internal/server/oauth"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const OAUTHPath = "/_oauth"

type Server struct {
	http.Handler
	OAuthHandler
	sessionCookieHandler
	stateHandler
	whitelist
	config Config
}

type OAuthHandler interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Login(code string) (string, error)
}

type Config struct {
	Expiry         time.Duration
	Secret         []byte
	InsecureCookie bool
	Domain         string
	Users          []string
	AuthHost       string
	ClientID       string
	ClientSecret   string
}

func New(config Config, l *slog.Logger) *Server {
	s := Server{
		config: config,
		OAuthHandler: &oauth.Handler{
			HTTPClient: http.DefaultClient,
			Config: oauth2.Config{
				ClientID:     config.ClientID,
				ClientSecret: config.ClientSecret,
				Endpoint:     google.Endpoint,
				RedirectURL:  "https://" + config.AuthHost + OAUTHPath,
				Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			},
		},
		sessionCookieHandler: sessionCookieHandler{
			SecureCookie: !config.InsecureCookie,
			Secret:       config.Secret,
		},
		stateHandler: stateHandler{
			// 5 minutes should be enough for the user to log in to Google
			cache: cache.New[string, string](5*time.Minute, time.Minute),
		},
		whitelist: newWhitelist(config.Users),
	}

	h := http.NewServeMux()
	h.Handle(OAUTHPath, s.AuthCallbackHandler(l))
	h.HandleFunc(OAUTHPath+"/logout", s.LogoutHandler(l))
	h.HandleFunc("/", s.AuthHandler(l))
	s.Handler = traefikParser()(h)
	return &s
}

func (s *Server) AuthHandler(l *slog.Logger) http.HandlerFunc {
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
			// Client doesn't have a valid cookie. Redirect to Google to authenticate the user.
			// When the user is authenticated, AuthCallbackHandler generates a new valid cookie.
			s.redirectToAuth(w, r, l)
			return
		}

		if host := r.URL.Host; !isValidSubdomain(s.config.Domain, host) {
			l.Warn("invalid host", "host", host, "domain", s.config.Domain)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		l.Debug("allowing valid request", "email", c.Email)
		w.Header().Set("X-Forwarded-User", c.Email)
		w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) redirectToAuth(w http.ResponseWriter, r *http.Request, l *slog.Logger) {
	// To protect against CSRF attacks, we generate a random state and associate it with the final destination of the request.
	// AuthCallbackHandler uses the random state to retrieve the final destination, thereby validating that the request came from us.
	encodedState, err := s.stateHandler.Add(r.URL.String())
	if err != nil {
		l.Error("error adding to state cache", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	// Redirect user to Google to select the account to be used to authenticate the request
	authCodeURL := s.OAuthHandler.AuthCodeURL(encodedState, oauth2.SetAuthURLParam("prompt", "select_account"))
	l.Debug("redirecting ...", "authCodeURL", authCodeURL)
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func (s *Server) AuthCallbackHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "AuthCallbackHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		// Look up the (random) state to find the final destination.
		encodedState := r.URL.Query().Get("state")
		redirectURL, ok := s.stateHandler.Get(encodedState)
		if !ok {
			l.Warn("invalid state. Dropping request ...")
			http.Error(w, "Invalid state", http.StatusBadRequest)
			return
		}

		// Use the "code" in the response to determine the user's email address.
		user, err := s.OAuthHandler.Login(r.FormValue("code"))
		if err != nil {
			l.Error("failed to log in to google", "err", err)
			http.Error(w, "oauth2 failed", http.StatusBadGateway)
			return
		}
		l.Debug("user authenticated", "user", user)

		// Check that the user's email address is in the whitelist.
		if !s.whitelist.contains(user) {
			l.Warn("not a valid user. rejecting ...", "user", user)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// Login successful. Add session cookie and redirect the user to the final destination.
		s.SaveCookie(w, sessionCookie{
			Email:  user,
			Expiry: time.Now().Add(s.config.Expiry),
			Domain: s.config.Domain,
		})

		l.Info("user logged in. redirecting ...", "user", user, "url", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	}
}

func (s *Server) LogoutHandler(l *slog.Logger) http.HandlerFunc {
	l = l.With("handler", "LogoutHandler")

	return func(w http.ResponseWriter, r *http.Request) {
		l.Debug("request received", "request", loggedRequest{r: r})

		// Write a blank session cookie to override the current valid one.
		s.SaveCookie(w, sessionCookie{})
		http.Error(w, "You have been logged out", http.StatusUnauthorized)
		l.Info("user has been logged out")
	}
}

func isValidSubdomain(domain, input string) bool {
	if domain == "" {
		return false
	}
	if domain[0] != '.' {
		domain = "." + domain
	}
	if "."+input == domain {
		return true
	}
	return strings.HasSuffix(input, domain)
}
