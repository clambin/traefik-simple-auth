package state

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	gcc "github.com/clambin/go-common/cache"
	"github.com/redis/go-redis/v9"
	"time"
)

var ErrNotFound = errors.New("not found")

type cache[T any] interface {
	Add(context.Context, string, T, time.Duration) error
	GetDel(context.Context, string) (T, error)
	Ping(context.Context) error
}

func newCache[T any](configuration Configuration) cache[T] {
	switch configuration.CacheType {
	case "memory":
		return localCache[T]{
			values: gcc.New[string, T](0, 0),
		}
	case "memcached":
		return memcachedCache[T]{
			Client: memcache.New(configuration.MemcachedConfiguration.Addr),
		}
	case "redis":
		return redisCache[T]{
			Client: redis.NewClient(&redis.Options{
				Addr:     configuration.RedisConfiguration.Addr,
				Username: configuration.RedisConfiguration.Username,
				Password: configuration.RedisConfiguration.Password,
				DB:       configuration.RedisConfiguration.Database,
			})}
	default:
		panic("Unsupported cache type: " + configuration.CacheType)
	}
}

var _ cache[string] = &localCache[string]{}

type localCache[T any] struct {
	values *gcc.Cache[string, T]
}

func (l localCache[T]) Add(_ context.Context, state string, value T, duration time.Duration) error {
	l.values.AddWithExpiry(state, value, duration)
	return nil
}

func (l localCache[T]) GetDel(_ context.Context, key string) (T, error) {
	var err error
	val, ok := l.values.GetAndRemove(key)
	if !ok {
		err = ErrNotFound
	}
	return val, err
}

func (l localCache[T]) Ping(context.Context) error {
	return nil
}

type memcachedCache[T any] struct {
	Client memcachedClient
}

type memcachedClient interface {
	Set(*memcache.Item) error
	Get(string) (*memcache.Item, error)
	Delete(string) error
	Ping() error
}

func (m memcachedCache[T]) Add(_ context.Context, key string, value T, ttl time.Duration) error {
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

func (m memcachedCache[T]) GetDel(_ context.Context, key string) (T, error) {
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

func (m memcachedCache[T]) Ping(_ context.Context) error {
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

var _ cache[string] = redisCache[string]{}

type redisCache[T any] struct {
	Client redisClient
}

type redisClient interface {
	Set(context.Context, string, any, time.Duration) *redis.StatusCmd
	GetDel(context.Context, string) *redis.StringCmd
	Ping(context.Context) *redis.StatusCmd
}

func (r redisCache[T]) Add(ctx context.Context, key string, value T, ttl time.Duration) error {
	val, err := encode[T](value)
	if err == nil {
		err = r.Client.Set(ctx, key, val, ttl).Err()
	}
	return err
}

func (r redisCache[T]) GetDel(ctx context.Context, key string) (T, error) {
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

func (r redisCache[T]) Ping(ctx context.Context) error {
	return r.Client.Ping(ctx).Err()
}
