package server

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func Test_authorizer(t *testing.T) {
	tests := []struct {
		name   string
		target string
		info   userInfo
		err    assert.ErrorAssertionFunc
		want   string
	}{
		{
			name:   "success",
			target: "https://www.example.com",
			info:   userInfo{email: "foo@example.com"},
			err:    assert.NoError,
		},
		{
			name:   "invalid token",
			target: "https://www.example.com",
			info:   userInfo{email: "foo@example.com", err: errors.New("invalid token")},
			err:    assert.Error,
			want:   "invalid token",
		},
		{
			name:   "missing token",
			target: "https://www.example.com",
			info:   userInfo{email: ""},
			err:    assert.Error,
			want:   "http: named cookie not present",
		},
		{
			name:   "invalid user",
			target: "https://www.example.com",
			info:   userInfo{email: "bar@example.com"},
			err:    assert.Error,
			want:   "invalid user",
		},
		{
			name:   "invalid domain",
			target: "https://www.example.org",
			info:   userInfo{email: "foo@example.com"},
			err:    assert.Error,
			want:   "invalid domain",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := authorizer{
				Whitelist: map[string]struct{}{"foo@example.com": {}},
				Domain:    ".example.com",
			}

			r, _ := http.NewRequest(http.MethodGet, tt.target, nil)
			if tt.info.email != "" {
				r = withUserInfo(r, tt.info)
			}

			email, err := a.AuthorizeRequest(r)
			tt.err(t, err)
			if err == nil {
				assert.Equal(t, tt.info.email, email)
			}
			if err != nil {
				assert.Equal(t, tt.want, err.Error())
			}
		})
	}
}
