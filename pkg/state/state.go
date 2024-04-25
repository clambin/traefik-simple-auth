package state

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/clambin/go-common/cache"
	"time"
)

const stateSize = 32

// A Store maintains a (random) state that is associated with a string.  It is used by the Server to protect against CSRF attacks:
// before redirecting to the oauth provider, we generate a random state. During callback, we then check if the oauth provider
// sent us back the same state.
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
	if _, err := rand.Read(state); err != nil {
		panic("error generating random state: " + err.Error())
	}
	encodedState := hex.EncodeToString(state)
	s.cache.Add(encodedState, value)
	return encodedState
}

// Get checks if the state exists and returns the associated value
func (s Store[T]) Get(state string) (T, bool) {
	return s.cache.Get(state)
}
