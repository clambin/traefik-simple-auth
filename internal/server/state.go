package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/clambin/go-common/cache"
)

const stateSize = 32

type stateHandler struct {
	cache *cache.Cache[string, string]
}

func (s *stateHandler) add(redirectURL string) (string, error) {
	state := make([]byte, stateSize)
	_, err := rand.Read(state)
	if err != nil {
		return "", fmt.Errorf("error generating random state: %v", err)
	}
	encodedState := hex.EncodeToString(state)
	s.cache.Add(encodedState, redirectURL)
	return encodedState, nil
}

func (s *stateHandler) get(state string) (string, bool) {
	return s.cache.Get(state)
}
