package server

import (
	"github.com/clambin/go-common/set"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestServer_AuthHandler(t *testing.T) {
	config := Config{
		Domain:   "example.com",
		Secret:   []byte("secret"),
		Expiry:   time.Hour,
		Users:    set.New("foo@example.com"),
		AuthHost: "https://auth.example.com",
	}
	p := SessionCookieHandler{Secret: config.Secret}

	s := New(config, slog.Default())
	type args struct {
		host   string
		cookie SessionCookie
	}
	tests := []struct {
		name string
		args args
		want int
		user string
	}{
		{
			name: "missing cookie",
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "valid cookie",
			args: args{
				host:   "example.com",
				cookie: SessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)},
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		{
			name: "invalid cookie",
			args: args{
				host:   "example.com",
				cookie: SessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(-time.Hour)},
			},
			want: http.StatusTemporaryRedirect,
		},
		{
			name: "invalid user",
			args: args{
				host:   "example.com",
				cookie: SessionCookie{Email: "bar@example.com", Expiry: time.Now().Add(time.Hour)},
			},
			want: http.StatusUnauthorized,
		},
		{
			name: "valid subdomain",
			args: args{
				host:   "www.example.com",
				cookie: SessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)},
			},
			want: http.StatusOK,
			user: "foo@example.com",
		},
		/*		{
					name: "valid domain with user info",
					args: args{
						host:   "user:password@www.example.com",
						cookie: s.makeSessionCookie("foo@example.com", config.Secret),
					},
					want: http.StatusOK,
					user: "foo@example.com",
				},
		*/
		{
			name: "invalid domain",
			args: args{
				host:   "example2.com",
				cookie: SessionCookie{Email: "foo@example.com", Expiry: time.Now().Add(time.Hour)},
			},
			want: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := makeHTTPRequest(http.MethodGet, tt.args.host, "/foo")
			w := httptest.NewRecorder()
			if tt.args.cookie.Email != "" {
				// Generate a new cookie.
				// SaveCookie works in ResponseWriters, so save it there and then copy it to the request
				p.SaveCookie(w, tt.args.cookie)
				for _, c := range w.Header()["Set-Cookie"] {
					r.Header.Add("Cookie", c)
				}
			}

			s.ServeHTTP(w, r)

			if w.Code != tt.want {
				t.Fatalf("got %d, want %d", w.Code, tt.want)
			}

			switch w.Code {
			case http.StatusOK:
				if got := w.Header().Get("X-Forwarded-User"); got != tt.user {
					t.Errorf("X-Forwarded-User: got %q, want %q", got, tt.user)
				}
			case http.StatusTemporaryRedirect:
				if got := w.Header().Get("Location"); got == "" {
					t.Errorf("Location: empty, want redirect URL")
				}
			}
		})
	}
}

func Test_isSubdomain(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		subdomain string
		want      bool
	}{
		{
			name:      "equal",
			domain:    "example.com",
			subdomain: "example.com",
			want:      true,
		},
		{
			name:      "valid subdomain",
			domain:    "example.com",
			subdomain: "www.example.com",
			want:      true,
		},
		{
			name:      "mismatch",
			domain:    "example.com",
			subdomain: "example2.com",
			want:      false,
		},
		{
			name:      "mismatch",
			domain:    "example.com",
			subdomain: "www.example2.com",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidSubdomain(tt.domain, tt.subdomain); got != tt.want {
				t.Errorf("isValidSubdomain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServer_authRedirect(t *testing.T) {
	config := Config{
		AuthHost:     "auth.example.com",
		ClientID:     "1234",
		ClientSecret: "secret",
	}
	s := New(config, slog.Default())

	r := makeHTTPRequest(http.MethodGet, "example.com", "/foo")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)

	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("got %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	got := w.Header().Get("Location")
	if got == "" {
		t.Error("Location missing")
	}
	{
		u, err := url.Parse(got)
		if err != nil {
			t.Fatal(err)
		}
		uri, err := url.QueryUnescape(u.Query().Get("redirect_uri"))
		if err != nil {
			t.Fatal(err)
		}
		t.Log(uri)
	}
	gotURL, err := url.Parse(got)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", got, err)
	}

	for key, wantValue := range map[string]string{
		"client_id":     config.ClientID,
		"redirect_uri":  "https://" + config.AuthHost + oauthPath,
		"response_type": "code",
		"scope":         "https://www.googleapis.com/auth/userinfo.email",
	} {
		if got := gotURL.Query().Get(key); got != wantValue {
			t.Errorf("redirect is missing expected parameter %q: got %q, want %q", key, got, wantValue)
		}
	}

	var cookieFound bool
	for _, cookie := range w.Result().Header["Set-Cookie"] {
		if strings.HasPrefix(cookie, oauthStateCookieName+"=") {
			cookieFound = true
			cookie = strings.Split(cookie, ";")[0]
			cookie = cookie[len(oauthStateCookieName)+1+2*nonceSize:]
			if cookie != "https://example.com/foo" {
				t.Errorf("oauthstate cookie: got %q, want https://example.com/foo", cookie)
			}
			break
		}
	}
	if !cookieFound {
		t.Errorf("no oauthstate cookie found")
	}
}

func TestServer_AuthCallbackHandler(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantCode int
	}{
		{
			name:     "valid",
			path:     "/_oauth?args=foo",
			wantCode: http.StatusInternalServerError,
		},
	}

	l := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s := New(Config{}, l)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, _ := http.NewRequest(http.MethodGet, "https://example.com"+tt.path, nil)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req)
			if w.Code != tt.wantCode {
				t.Errorf("got %d, want %d", w.Code, tt.wantCode)
			}
		})
	}
}

func TestServer_LogoutHandler(t *testing.T) {
	var config Config
	s := New(config, slog.Default())

	r, _ := http.NewRequest(http.MethodGet, oauthPath+"logout", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if w.Body.String() != "You have been logged out\n" {
		t.Errorf("got %q, want %q", w.Body.String(), "You have been logged out\n")
	}
}

func makeHTTPRequest(method, host, uri string) *http.Request {
	req, _ := http.NewRequest(http.MethodPut, "https://traefik/auth", nil)
	req.Header.Set("X-Forwarded-Method", method)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", host)
	req.Header.Set("X-Forwarded-Uri", uri)
	return req
}
