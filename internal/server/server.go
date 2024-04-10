package server

import (
	"errors"
	"github.com/clambin/go-common/set"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"log/slog"
	"net/http"
	"time"
)

const oauthPath = "/_oauth"

type Server struct {
	http.Handler
	oauthHandler
	SessionCookieHandler
	config Config
	logger *slog.Logger
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
		logger: l,

		oauthHandler: oauthHandler{
			httpClient: http.DefaultClient,
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
	m := http.NewServeMux()
	m.HandleFunc(oauthPath, s.AuthCallbackHandler)
	m.HandleFunc(oauthPath+"/logout", s.LogoutHandler)
	m.HandleFunc("/", s.AuthHandler)
	s.Handler = m

	return &s
}

/*
	func (s Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
		// TODO: do we need to do this? Or can we rely on the X-Forwarded headers instead?
		// Modify request
		//r.Method = r.Header.Get("X-Forwarded-Method")
		//r.Host = r.Header.Get("X-Forwarded-Host")

		// Read URI from header if we're acting as forward auth middleware
		//if _, ok := r.Header["X-Forwarded-Uri"]; ok {
		//	r.URL, _ = url.Parse(r.Header.Get("X-Forwarded-Uri"))
		//}

		// Pass to mux
		s.Handler.ServeHTTP(w, r)
	}
*/
func (s Server) AuthHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r)

	c, err := s.GetCookie(r)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			s.logger.Warn("no cookie found, redirecting ...")
			s.authRedirect(w, r)
			return
		}
		s.logger.Warn("invalid cookie", "err", err)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
	if !s.config.Users.Contains(c.Email) {
		s.logger.Warn("invalid user", "user", c.Email)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}
	if host := r.Header.Get("X-Forwarded-Host"); !isValidSubdomain(s.config.Domain, host) {
		s.logger.Warn("invalid host", "host", host, "domain", s.config.Domain)
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	s.logger.Debug("Allowing valid request", "email", c.Email)
	w.Header().Set("X-Forwarded-User", c.Email)
	w.WriteHeader(http.StatusOK)
}

func isValidSubdomain(domain, subdomain string) bool {
	return len(subdomain) >= len(domain) && subdomain[len(subdomain)-len(domain):] == domain
}

func (s Server) authRedirect(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.Header.Get("X-Forwarded-Proto") + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")

	state, err := makeOAuthState(redirectURL)
	if err != nil {
		s.logger.Warn("could not generate state", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	encodedState := state.Encode()

	cookie := http.Cookie{Name: oauthStateCookieName, Value: encodedState, Expires: time.Now().Add(time.Hour)}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, s.oauthHandler.Config.AuthCodeURL(encodedState), http.StatusTemporaryRedirect)
}
func (s Server) AuthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r)

	// TODO: verify hmac to ensure it came from us
	oauthState, err := GetOAuthState(r)
	if err != nil {
		s.logger.Warn("could not get oauth state", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if r.FormValue("state") != oauthState.Encode() {
		s.logger.Error("invalid oauth google state", "state", r.FormValue("state"))
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	user, err := s.oauthHandler.login(r.FormValue("code"))
	if err != nil {
		s.logger.Error("failed to log in to google", "err", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// login successful. add session cookie
	s.SaveCookie(w, SessionCookie{
		Email:  user,
		Expiry: time.Now().Add(s.config.Expiry),
		Domain: s.config.Domain,
	})

	var redirectURL string
	s.logger.Info("user logged in. redirecting ...", "user", user, "url", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

func (s Server) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r)

	s.SaveCookie(w, SessionCookie{})
	http.Error(w, "You have been logged out", http.StatusUnauthorized)
	s.logger.Info("user has been logged out")
}

func (s Server) logRequest(r *http.Request) {
	if !s.logger.Handler().Enabled(r.Context(), slog.LevelDebug) {
		return
	}

	var cookies []any
	if c, err := r.Cookie(sessionCookieName); err == nil {
		cookies = append(cookies, slog.String("oauth", c.Value))
	}
	if c, err := r.Cookie(oauthStateCookieName); err == nil {
		cookies = append(cookies, slog.String("oauth_state", c.Value))
	}

	attrs := make([]any, 2, 3)
	attrs[0] = slog.String("path", r.URL.Path)
	attrs[1] = slog.String("method", r.Method)
	if len(cookies) > 0 {
		attrs = append(attrs, slog.Group("cookies", cookies...))
	}

	s.logger.Debug("request received", slog.Group("request", attrs...))
}
