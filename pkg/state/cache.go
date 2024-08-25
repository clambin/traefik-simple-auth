package state

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/clambin/go-common/cache"
	"github.com/redis/go-redis/v9"
	"time"
)

var ErrNotFound = errors.New("not found")

type Cache[T any] interface {
	Add(context.Context, string, T, time.Duration) error
	GetDel(context.Context, string) (T, error)
	Len(context.Context) (int, error)
	Ping(context.Context) error
}

var _ Cache[string] = &LocalCache[string]{}

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

func (l LocalCache[T]) GetDel(_ context.Context, key string) (T, error) {
	var err error
	val, ok := l.values.GetAndRemove(key)
	if !ok {
		err = ErrNotFound
	}
	return val, err
}

func (l LocalCache[T]) Len(_ context.Context) (int, error) {
	return l.values.Len(), nil
}

func (l LocalCache[T]) Ping(context.Context) error {
	return nil
}

type MemcachedCache[T any] struct {
	Client MemcachedClient
}

type MemcachedClient interface {
	Set(*memcache.Item) error
	Get(string) (*memcache.Item, error)
	Delete(string) error
	Ping() error
}

func (m MemcachedCache[T]) Add(_ context.Context, key string, value T, ttl time.Duration) error {
	val, err := encode[T](value)
	if err == nil {
		err = m.Client.Set(&memcache.Item{
			Key:        key,
			Value:      val,
			Expiration: int32(ttl.Seconds()),
		})
	}
	return err
}

func (m MemcachedCache[T]) GetDel(_ context.Context, key string) (T, error) {
	item, err := m.Client.Get(key)
	if err == nil {
		err = m.Client.Delete(key)
	}
	if err != nil {
		if errors.Is(err, memcache.ErrCacheMiss) {
			err = ErrNotFound
		}
		var value T
		return value, err
	}
	return decode[T](item.Value)
}

func (m MemcachedCache[T]) Len(_ context.Context) (int, error) {
	return 0, nil
}

func (m MemcachedCache[T]) Ping(_ context.Context) error {
	return m.Client.Ping()
}

// memcached takes only []byte, so encoded the generic value.
// optimisation: if T is a string, we can just copy it.
func encode[T any](value T) ([]byte, error) {
	return json.Marshal(value)
}

func decode[T any](value []byte) (v T, err error) {
	err = json.Unmarshal(value, &v)
	return v, err
}

var _ Cache[string] = RedisCache[string]{}

type RedisCache[T any] struct {
	Client RedisClient
}

type RedisClient interface {
	Set(context.Context, string, any, time.Duration) *redis.StatusCmd
	GetDel(context.Context, string) *redis.StringCmd
	Ping(context.Context) *redis.StatusCmd
}

func (r RedisCache[T]) Add(ctx context.Context, key string, value T, ttl time.Duration) error {
	val, err := encode[T](value)
	if err == nil {
		err = r.Client.Set(ctx, key, val, ttl).Err()
	}
	return err
}

func (r RedisCache[T]) GetDel(ctx context.Context, key string) (T, error) {
	val, err := r.Client.GetDel(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			err = ErrNotFound
		}
		var value T
		return value, err
	}
	return decode[T]([]byte(val))
}

func (r RedisCache[T]) Len(_ context.Context) (int, error) {
	return 0, nil
}

func (r RedisCache[T]) Ping(ctx context.Context) error {
	return r.Client.Ping(ctx).Err()
}
