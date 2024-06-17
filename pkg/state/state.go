// Package state provides a repository for temporary (random) states, associated with a value. It is used by traefik-simple-auth
// to protect against CSRF attacks: before redirecting to the oauth provider, we generate a random state. During callback,
// we then check if the oauth provider sent us back the same state. The state is maintained for a limited amount of time
// to prevent (very unlikely) replay attacks.
package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/clambin/go-common/cache"
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
	err := s.Backend.add(ctx, encodedState, value, s.TTL)
	return encodedState, err
}

// Validate checks if the state exists. If it exists, we remove the state and return the associated value.
// If the state does not exist, bool is false.
func (s States[T]) Validate(ctx context.Context, state string) (T, error) {
	return s.Backend.get(ctx, state)
}

func (s States[T]) Count(ctx context.Context) (int, error) {
	return s.Backend.len(ctx)
}

var ErrNotFound = errors.New("not found")

type Backend[T any] interface {
	add(context.Context, string, T, time.Duration) error
	get(context.Context, string) (T, error)
	len(context.Context) (int, error)
}

type LocalCache[T any] struct {
	values *cache.Cache[string, T]
}

func NewLocalCache[T any]() LocalCache[T] {
	return LocalCache[T]{
		values: cache.New[string, T](0, 0),
	}
}

func (l LocalCache[T]) add(_ context.Context, state string, value T, duration time.Duration) error {
	l.values.AddWithExpiry(state, value, duration)
	return nil
}

func (l LocalCache[T]) get(_ context.Context, key string) (T, error) {
	var err error
	val, ok := l.values.GetAndRemove(key)
	if !ok {
		return val, ErrNotFound
	}
	return val, err
}

func (l LocalCache[T]) len(_ context.Context) (int, error) {
	return l.values.Len(), nil
}

type MemcachedCache[T any] struct {
	Client MemcachedClient
}

type MemcachedClient interface {
	Set(*memcache.Item) error
	Get(string) (*memcache.Item, error)
	Delete(string) error
}

func (m MemcachedCache[T]) add(_ context.Context, key string, value T, ttl time.Duration) error {
	val, err := encode[T](value)
	if err != nil {
		return err
	}
	return m.Client.Set(&memcache.Item{
		Key:        key,
		Value:      val,
		Expiration: int32(ttl.Seconds()),
	})
}

func (m MemcachedCache[T]) get(_ context.Context, key string) (T, error) {
	var value T
	item, err := m.Client.Get(key)
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			err = ErrNotFound
		}
		return value, err
	}
	if err = m.Client.Delete(key); err != nil {
		return value, fmt.Errorf("delete: %w", err)
	}
	return decode[T](item.Value)
}

func (m MemcachedCache[T]) len(_ context.Context) (int, error) {
	return 0, nil
}

func encode[T any](value T) ([]byte, error) {
	var p any = &value
	switch v := p.(type) {
	case *string:
		return []byte(*v), nil
	default:
		return json.Marshal(value)
	}
}

func decode[T any](value []byte) (T, error) {
	var v T
	var p any = &v
	switch val := p.(type) {
	case *string:
		*val = string(value)
		return v, nil
	default:
		err := json.Unmarshal(value, &v)
		return v, err
	}
}
