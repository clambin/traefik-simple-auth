package server

import (
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func Test_getOAuthState(t *testing.T) {
	type args struct {
		nonce  []byte
		target string
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{
			name: "success",
			args: args{
				nonce:  []byte("12345678901234567890123456789012"),
				target: "https://example.com/",
			},
			wantErr: nil,
		},
		{
			name:    "missing oauth parameter",
			args:    args{},
			wantErr: errNoOauthState,
		},
		{
			name: "oauth parameter invalid: nonce too short",
			args: args{
				nonce:  []byte("too-short"),
				target: "https://example.com/",
			},
			wantErr: errInvalidOauthState{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := url.Values{}
			if len(tt.args.nonce) > 0 {
				s := oauthState{Nonce: tt.args.nonce, RedirectURL: tt.args.target}
				values.Add(oauthStateCookieName, s.encode())
			}
			r, _ := http.NewRequest(http.MethodGet, "/?"+values.Encode(), nil)

			got, err := getOAuthState(r)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("getOAuthState() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if string(got.Nonce) != string(tt.args.nonce) {
				t.Errorf("getOAuthState() nonce = %v, want %v", string(got.Nonce), string(tt.args.nonce))
			}
			if got.RedirectURL != tt.args.target {
				t.Errorf("getOAuthState() redirectURL = %v, want %v", got.RedirectURL, tt.args.target)
			}
		})
	}
}
