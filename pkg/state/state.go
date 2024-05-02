// Package state provides a repository for temporary (random) states, associated with a value. It is used by traefik-simple-auth
// to protect against CSRF attacks: before redirecting to the oauth provider, we generate a random state. During callback,
// we then check if the oauth provider sent us back the same state. The state is maintained for a limited amount of time
// to prevent (very unlikely) replay attacks.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/clambin/go-common/cache"
	"time"
)

const stateSize = 32 // 256 bits

// States maintains a (random) state that is associated with a value.
type States[T any] struct {
	values *cache.Cache[string, T]
}

// New creates a new States repository. The retention parameter determines how long the state should be maintained.
func New[T any](retention time.Duration) States[T] {
	return States[T]{
		values: cache.New[string, T](retention, time.Minute),
	}
}

// Add returns a new state, associated with the provided value.
func (s States[T]) Add(value T) string {
	state := make([]byte, stateSize)
	// theoretically this could fail, but in practice this will never happen.
	_, _ = rand.Read(state)
	encodedState := hex.EncodeToString(state)
	s.values.Add(encodedState, value)
	return encodedState
}

// Get checks if the state exists and returns the associated value.
func (s States[T]) Get(state string) (T, bool) {
	return s.values.Get(state)
}
