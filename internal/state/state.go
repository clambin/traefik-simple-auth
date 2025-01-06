// Package state provides a repository for temporary (random) states, associated with a value. It is used by traefik-simple-auth
// to protect against CSRF attacks: before redirecting to the oauth provider, we generate a random state. During callback,
// we then check if the oauth provider sent us back the same state. The state is maintained for a limited amount of time
// to prevent (very unlikely) replay attacks.
//
// States supports three types of cache: a local in-memory cache, memcached and redis. The latter two allow multiple instances
// of traefik-simple-auth to run, while still sharing one set of States.
package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"
)

const stateSize = 32 // 256 bits

// States maintains a (random) state that is associated with a value. traefik-simple-auth uses this to protect login requests against CSRF attacks.
type States struct {
	cache[string]
	namespace string
	ttl       time.Duration
}

// New returns a new States structure for the provided configuration.
//
// Configuration.CacheType determines the type of cache to use.
// Currently supported values are "memory", "memcached" and "redis".
func New(configuration Configuration) States {
	return States{
		ttl:       configuration.TTL,
		namespace: configuration.Namespace,
		cache:     newCache[string](configuration),
	}
}

// Add returns a new state, associated with the provided value.
func (s States) Add(ctx context.Context, value string) (string, error) {
	state := make([]byte, stateSize)
	// theoretically this could fail, but in practice this will never happen.
	_, _ = rand.Read(state)
	encodedState := hex.EncodeToString(state)
	err := s.cache.Add(ctx, s.key(encodedState), value, s.ttl)
	return encodedState, err
}

// Validate checks if the state exists. If it exists, we remove the state and return the associated value.
// If the state does not exist, bool is false.
func (s States) Validate(ctx context.Context, state string) (string, error) {
	return s.cache.GetDel(ctx, s.key(state))
}

func (s States) key(value string) string {
	return s.namespace + "|state|" + value
}

// Ping checks the underlying cache. For redis & memcached, this checks connectivity with the configured server. For in-memory cache, this does nothing.
func (s States) Ping(ctx context.Context) error {
	return s.cache.Ping(ctx)
}
