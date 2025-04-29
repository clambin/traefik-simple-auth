package oauth2

import (
	gcc "codeberg.org/clambin/go-common/cache"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/redis/go-redis/v9"
	"time"
)

// Configuration options for a CSRFStateStore
type Configuration struct {
	// CacheType indicates the type of cache ("memory", "memcached" or "redis").
	// When using multiple instances of traefik-simple-auth, an external cache (ie memcached or redis) is required.
	CacheType string
	// Namespace for the keys maintained in the CSRFStateStore
	Namespace string
	// MemcachedConfiguration contains the connectivity parameters for a memcached service
	MemcachedConfiguration MemcachedConfiguration
	// RedisConfiguration contains the connectivity parameters for a redis service
	RedisConfiguration RedisConfiguration
	// TTL is the type to maintain a created state in the CSRFStateStore, i.e. the time we give the used to login in to their OAuth2 provider.
	TTL time.Duration
}

type RedisConfiguration struct {
	Addr     string
	Username string
	Password string
	Database int
}

type MemcachedConfiguration struct {
	Addr string
}

const stateSize = 32 // 256 bits

// CSRFStateStore provides a repository for temporary (random) states, associated with a value. It is used by traefik-simple-auth
// to protect against CSRF attacks: before redirecting to the oauth provider, we generate a random state. During callback,
// we then check if the oauth provider sent us back the same state. The state is maintained for a limited amount of time
// to prevent (very unlikely) replay attacks.
//
// CSRFStateStore supports three types of cache: a local in-memory cache, memcached and redis. The latter two allow multiple instances
// of traefik-simple-auth to run, while still sharing one set of CSRFStateStore.
type CSRFStateStore struct {
	cache     cache[string]
	namespace string
	ttl       time.Duration
}

// NewCSFRStateStore returns a new CSRFStateStore.
//
// Configuration.CacheType determines the type of cache to use.
// Currently supported values are "memory", "memcached" and "redis".
func NewCSFRStateStore(configuration Configuration) CSRFStateStore {
	return CSRFStateStore{
		ttl:       configuration.TTL,
		namespace: configuration.Namespace,
		cache:     newCache[string](configuration),
	}
}

// Add returns a new state, associated with the provided value.
func (s CSRFStateStore) Add(ctx context.Context, value string) (string, error) {
	state := make([]byte, stateSize)
	// theoretically, this could fail. but in practice, this will never happen.
	_, _ = rand.Read(state)
	encodedState := hex.EncodeToString(state)
	err := s.cache.Add(ctx, s.key(encodedState), value, s.ttl)
	return encodedState, err
}

// Validate checks if the state exists. If it exists, we remove the state and return the associated value.
// If the state does not exist, bool is false.
func (s CSRFStateStore) Validate(ctx context.Context, state string) (string, error) {
	return s.cache.GetDel(ctx, s.key(state))
}

func (s CSRFStateStore) key(value string) string {
	return s.namespace + "|state|" + value
}

// Ping checks the underlying cache. For redis & memcached, this checks connectivity with the configured server. For in-memory cache, this does nothing.
func (s CSRFStateStore) Ping(ctx context.Context) error {
	return s.cache.Ping(ctx)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
