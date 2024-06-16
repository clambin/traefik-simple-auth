// Package state provides a repository for temporary (random) states, associated with a value. It is used by traefik-simple-auth
// to protect against CSRF attacks: before redirecting to the oauth provider, we generate a random state. During callback,
// we then check if the oauth provider sent us back the same state. The state is maintained for a limited amount of time
// to prevent (very unlikely) replay attacks.
package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/clambin/go-common/cache"
	"github.com/redis/go-redis/v9"
	"time"
)

const stateSize = 32 // 256 bits

// States maintains a (random) state that is associated with a value.
type States[T any] struct {
	Backend[T]
	TTL time.Duration
}

// Add returns a new state, associated with the provided value.
func (s States[T]) Add(ctx context.Context, value T) (string, error) {
	state := make([]byte, stateSize)
	// theoretically this could fail, but in practice this will never happen.
	_, _ = rand.Read(state)
	encodedState := hex.EncodeToString(state)
	err := s.Backend.Add(ctx, encodedState, value, s.TTL)
	return encodedState, err
}

// Validate checks if the state exists. If it exists, we remove the state and return the associated value.
// If the state does not exist, bool is false.
func (s States[T]) Validate(ctx context.Context, state string) (T, error) {
	return s.Backend.Get(ctx, state)
}

func (s States[T]) Count(ctx context.Context) (int, error) {
	return s.Backend.Len(ctx)
}

var ErrNotFound = errors.New("not found")

type Backend[T any] interface {
	Add(context.Context, string, T, time.Duration) error
	Get(context.Context, string) (T, error)
	Len(context.Context) (int, error)
}

type LocalCache[T any] struct {
	values *cache.Cache[string, T]
}

func NewLocalCache[T any]() LocalCache[T] {
	return LocalCache[T]{
		values: cache.New[string, T](0, 0),
	}
}

func (l LocalCache[T]) Add(_ context.Context, state string, value T, duration time.Duration) error {
	l.values.AddWithExpiry(state, value, duration)
	return nil
}

func (l LocalCache[T]) Get(_ context.Context, key string) (T, error) {
	var err error
	val, ok := l.values.Get(key)
	if !ok {
		return val, ErrNotFound
	}
	// TODO: this isn't atomic.  need to implement in cache library.
	l.values.Remove(key)
	return val, err
}

func (l LocalCache[T]) Len(_ context.Context) (int, error) {
	return l.values.Len(), nil
}

type RedisCache struct {
	Client RedisClient //*redis.Client
}

type RedisClient interface {
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	GetDel(ctx context.Context, key string) *redis.StringCmd
	Keys(ctx context.Context, pattern string) *redis.StringSliceCmd
}

func (l RedisCache) Add(ctx context.Context, state string, value string, duration time.Duration) error {
	return l.Client.Set(ctx, state, value, duration).Err()
}

func (l RedisCache) Get(ctx context.Context, key string) (string, error) {
	return l.Client.GetDel(ctx, key).Result()
}

func (l RedisCache) Len(ctx context.Context) (int, error) {
	keys, err := l.Client.Keys(ctx, "").Result()
	return len(keys), err
}
