package state

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/clambin/go-common/cache"
	"time"
)

const stateSize = 32

// A Store maintains a (random) state that is associated with a value.  It is used by traefik-simple-auth to protect against CSRF attacks:
// before redirecting to the oauth provider, we generate a random state. During callback, we then check if the oauth provider
// sent us back the same state. The state is maintained for a limited amount of time to prevent (very unlikely) replay attacks.
type Store[T any] struct {
	cache *cache.Cache[string, T]
}

// New creates a new state Store
func New[T any](retention time.Duration) Store[T] {
	return Store[T]{
		cache: cache.New[string, T](retention, time.Minute),
	}
}

// Add returns a new state
func (s Store[T]) Add(value T) string {
	state := make([]byte, stateSize)
	// theoretically this could fail, but in practice this will never happen.
	_, _ = rand.Read(state)
	encodedState := hex.EncodeToString(state)
	s.cache.Add(encodedState, value)
	return encodedState
}

// Get checks if the state exists and returns the associated value
func (s Store[T]) Get(state string) (T, bool) {
	return s.cache.Get(state)
}