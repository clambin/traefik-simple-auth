package csrf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	memcache "codeberg.org/clambin/go-common/cache"
	"github.com/redis/go-redis/v9"
)

// Configuration options for a StateStore
type Configuration struct {
	// Redis contains the connectivity parameters for a redis service. If Addr is blank, a local (in-memory) cache is used.
	Redis RedisConfiguration
	// TTL is the time to maintain a created state in the StateStore, i.e., the time we give the user to log in with their OAuth2 provider.
	TTL time.Duration `flagger.usage:"Lifetime of a CSRF token"`
}

type RedisConfiguration struct {
	Addr      string `flagger.usage:"Redis server address"`
	Username  string `flagger.usage:"Redis username"`
	Password  string `flagger.usage:"Redis password"`
	Namespace string `flagger.usage:"When sharing a redis db, namespace can be prepended to the key to avoid collision with other applications "`
	Database  int    `flagger.usage:"Redis database number"`
}

const stateSize = 32 // 256 bits

// StateStore provides a repository for temporary (random) states, associated with a value.
// traefik-simple-auth uses this to protect against CSRF attacks: before redirecting to the oauth provider, we generate a random state.
// During callback, we then check if the oauth provider sent us back the same state. The state is maintained for a limited amount of time
// to prevent (very unlikely) replay attacks.
//
// StateStore supports two types of cache: a local in-memory cache and redis. The latter allows multiple instances
// of traefik-simple-auth to run, while still sharing a common StateStore.
type StateStore struct {
	cache cache[string]
	ttl   time.Duration
}

// New returns a new StateStore.
func New(configuration Configuration) StateStore {
	return StateStore{
		ttl:   configuration.TTL,
		cache: newCache[string](configuration),
	}
}

// Add returns a new state, associated with the provided value.
func (s StateStore) Add(ctx context.Context, value string) (string, error) {
	state := make([]byte, stateSize)
	// theoretically, this could fail. but in practice, this will never happen.
	_, _ = rand.Read(state)
	encodedState := hex.EncodeToString(state)
	err := s.cache.Add(ctx, encodedState, value, s.ttl)
	return encodedState, err
}

// Validate checks if the state exists. If it exists, we remove the state and return the associated value.
// If the state does not exist, bool is false.
func (s StateStore) Validate(ctx context.Context, state string) (string, error) {
	return s.cache.GetDel(ctx, state)
}

// Ping checks the underlying cache. For redis & memcached, this checks connectivity with the configured server. For in-memory cache, this does nothing.
func (s StateStore) Ping(ctx context.Context) error {
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
	if configuration.Redis.Addr == "" {
		return localCache[T]{
			values: memcache.New[string, T](0, 0),
		}
	}
	return redisCache[T]{
		Client: redis.NewClient(&redis.Options{
			Addr:     configuration.Redis.Addr,
			Username: configuration.Redis.Username,
			Password: configuration.Redis.Password,
			DB:       configuration.Redis.Database,
		}),
		Namespace: configuration.Redis.Namespace,
	}

}

var _ cache[string] = &localCache[string]{}

type localCache[T any] struct {
	values *memcache.Cache[string, T]
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

var _ cache[string] = redisCache[string]{}

type redisCache[T any] struct {
	Client    redisClient
	Namespace string
}

type redisClient interface {
	Set(context.Context, string, any, time.Duration) *redis.StatusCmd
	GetDel(context.Context, string) *redis.StringCmd
	Ping(context.Context) *redis.StatusCmd
}

func (r redisCache[T]) Add(ctx context.Context, key string, value T, ttl time.Duration) error {
	if r.Namespace != "" {
		key = r.Namespace + "|" + key
	}
	val, err := encode[T](value)
	if err == nil {
		err = r.Client.Set(ctx, key, val, ttl).Err()
	}
	return err
}

func (r redisCache[T]) GetDel(ctx context.Context, key string) (T, error) {
	if r.Namespace != "" {
		key = r.Namespace + "|" + key
	}
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

// redis only takes string, so encoded the generic value.
func encode[T any](value T) ([]byte, error) {
	return json.Marshal(value)
}

func decode[T any](value []byte) (v T, err error) {
	err = json.Unmarshal(value, &v)
	return v, err
}
