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

func (s *stateHandler) Add(redirectURL string) (string, error) {
	key := make([]byte, stateSize)
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("error generating random key: %v", err)
	}
	keyString := hex.EncodeToString(key)
	s.cache.Add(keyString, redirectURL)
	return keyString, nil
}

func (s *stateHandler) Get(state string) (string, bool) {
	return s.cache.Get(state)
}
