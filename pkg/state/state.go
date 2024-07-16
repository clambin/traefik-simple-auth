// Package state provides a repository for temporary (random) states, associated with a value. It is used by traefik-simple-auth
// to protect against CSRF attacks: before redirecting to the oauth provider, we generate a random state. During callback,
// we then check if the oauth provider sent us back the same state. The state is maintained for a limited amount of time
// to prevent (very unlikely) replay attacks.
package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/clambin/traefik-simple-auth/pkg/cache"
	"time"
)

const stateSize = 32 // 256 bits

// States maintains a (random) state that is associated with a value.
type States[T any] struct {
	cache.Cache[T]
	TTL       time.Duration
	Namespace string
}

// Add returns a new state, associated with the provided value.
func (s States[T]) Add(ctx context.Context, value T) (string, error) {
	state := make([]byte, stateSize)
	// theoretically this could fail, but in practice this will never happen.
	_, _ = rand.Read(state)
	encodedState := hex.EncodeToString(state)
	err := s.Cache.Add(ctx, s.key(encodedState), value, s.TTL)
	return encodedState, err
}

// Validate checks if the state exists. If it exists, we remove the state and return the associated value.
// If the state does not exist, bool is false.
func (s States[T]) Validate(ctx context.Context, state string) (T, error) {
	return s.Cache.GetDel(ctx, s.key(state))
}

func (s States[T]) Count(ctx context.Context) (int, error) {
	return s.Cache.Len(ctx)
}

func (s States[T]) key(value string) string {
	return s.Namespace + "|state|" + value
}
