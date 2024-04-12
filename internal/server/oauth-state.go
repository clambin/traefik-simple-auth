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

type oauthState struct {
	Nonce       []byte
	RedirectURL string
}

func makeOAuthState(redirectURL string) (oauthState, error) {
	state := oauthState{
		Nonce:       make([]byte, nonceSize),
		RedirectURL: redirectURL,
	}
	_, err := rand.Read(state.Nonce)
	return state, err
}

func getOAuthState(r *http.Request) (oauthState, error) {
	state := r.URL.Query().Get(oauthStateCookieName)
	if len(state) < nonceSize+1 {
		return oauthState{}, errors.New("invalid state parameter")
	}
	nonce, err := hex.DecodeString(state[:nonceSize])
	if err != nil {
		return oauthState{}, fmt.Errorf("invalid nonce parameter: %v", err)
	}
	return oauthState{
		Nonce:       nonce,
		RedirectURL: state[nonceSize+1:],
	}, nil
}

func (s oauthState) encode() string {
	return hex.EncodeToString(s.Nonce) + s.RedirectURL
}
