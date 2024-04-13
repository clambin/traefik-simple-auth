package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
)

const oauthStateCookieName = "state"
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
	if len(state) == 0 {
		return oauthState{}, errNoOauthState
	}
	if len(state) < 2*nonceSize+1 {
		return oauthState{}, errInvalidOauthState{Reason: fmt.Sprintf("too small. got %d bytes, expected at least %d bytes", len(state), 2*nonceSize+1)}
	}
	nonce, err := hex.DecodeString(state[:2*nonceSize])
	if err != nil {
		return oauthState{}, errInvalidOauthState{Reason: "decode failed: " + err.Error()}
	}
	return oauthState{
		Nonce:       nonce,
		RedirectURL: state[2*nonceSize:],
	}, nil
}

func (s oauthState) encode() string {
	return hex.EncodeToString(s.Nonce) + s.RedirectURL
}

var errNoOauthState = errors.New("oauth state not found")

type errInvalidOauthState struct{ Reason string }

func (e errInvalidOauthState) Error() string { return "oauth state is invalid: " + e.Reason }
func (e errInvalidOauthState) Is(err error) bool {
	var errInvalidOauthState errInvalidOauthState
	ok := errors.As(err, &errInvalidOauthState)
	return ok
}
