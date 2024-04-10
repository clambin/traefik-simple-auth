package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
)

const oauthStateCookieName = "oauthstate"
const nonceSize = 32

type OAuthState struct {
	Nonce       []byte
	RedirectURL string
}

func makeOAuthState(redirectURL string) (OAuthState, error) {
	oauthState := OAuthState{
		Nonce:       make([]byte, nonceSize),
		RedirectURL: redirectURL,
	}
	_, err := rand.Read(oauthState.Nonce)
	return oauthState, err
}

func GetOAuthState(r *http.Request) (OAuthState, error) {
	state := r.URL.Query().Get(oauthStateCookieName)
	if len(state) < nonceSize {
		return OAuthState{}, errors.New("invalid state parameter")
	}
	nonce, err := hex.DecodeString(state[:32])
	if err != nil {
		return OAuthState{}, fmt.Errorf("invalid nonce parameter: %v", err)
	}
	return OAuthState{
		Nonce:       nonce,
		RedirectURL: state[33:],
	}, nil
}

func (s OAuthState) Encode() string {
	return hex.EncodeToString(s.Nonce) + s.RedirectURL
}
