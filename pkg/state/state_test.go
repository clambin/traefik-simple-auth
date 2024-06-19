package state

import (
	"context"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/clambin/go-common/cache"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStates(t *testing.T) {
	tests := []struct {
		name      string
		backend   Backend[string]
		wantCount int
	}{
		{
			name:      "localCache",
			backend:   NewLocalCache[string](),
			wantCount: 1,
		},
		{
			name: "memcachedCache",
			backend: MemcachedCache[string]{
				Namespace: "github.com/clambin/traefik-simple-auth",
				Client:    &fakeMemcachedClient{c: LocalCache[string]{values: cache.New[string, string](0, 0)}},
			},
		},
		{
			name: "redisCache",
			backend: RedisCache[string]{
				Namespace: "github.com/clambin/traefik-simple-auth",
				Client:    &fakeRedisClient{c: LocalCache[string]{values: cache.New[string, string](0, 0)}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := States[string]{
				Backend: tt.backend,
				TTL:     500 * time.Millisecond,
			}

			ctx := context.Background()
			state, err := c.Add(ctx, "foo")
			require.NoError(t, err)

			count, err := c.Count(ctx)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCount, count)

			value, err := c.Validate(ctx, state)
			require.NoError(t, err)
			assert.Equal(t, "foo", value)

			count, err = c.Count(ctx)
			require.NoError(t, err)
			assert.Zero(t, count)

			_, err = c.Validate(ctx, state)
			require.ErrorIs(t, err, ErrNotFound)
		})
	}
}

func TestMemcachedCache_int(t *testing.T) {
	s := States[int]{
		Backend: MemcachedCache[int]{
			Client: &fakeMemcachedClient{c: LocalCache[string]{values: cache.New[string, string](0, 0)}},
		},
	}

	ctx := context.Background()
	state, err := s.Add(ctx, 10)
	require.NoError(t, err)
	value, err := s.Validate(ctx, state)
	require.NoError(t, err)
	assert.Equal(t, 10, value)
	_, err = s.Validate(ctx, state)
	assert.ErrorIs(t, err, ErrNotFound)
}

var _ MemcachedClient = &fakeMemcachedClient{}

type fakeMemcachedClient struct {
	c LocalCache[string]
}

func (f *fakeMemcachedClient) Set(item *memcache.Item) error {
	return f.c.add(context.Background(), item.Key, string(item.Value), time.Duration(item.Expiration)*time.Second)
}

func (f *fakeMemcachedClient) Get(key string) (*memcache.Item, error) {
	value, err := f.c.get(context.Background(), key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			err = memcache.ErrCacheMiss
		}
		return nil, err
	}
	return &memcache.Item{Key: key, Value: []byte(value)}, nil
}

func (f *fakeMemcachedClient) Delete(key string) error {
	f.c.values.Remove(key)
	return nil
}

var _ RedisClient = fakeRedisClient{}

type fakeRedisClient struct {
	c LocalCache[string]
}

func (f fakeRedisClient) Set(ctx context.Context, key string, value any, ttl time.Duration) *redis.StatusCmd {
	err := f.c.add(ctx, key, string(value.([]byte)), ttl)
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetErr(err)
	return cmd
}

func (f fakeRedisClient) GetDel(ctx context.Context, key string) *redis.StringCmd {
	val, err := f.c.get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		err = redis.Nil
	}
	cmd := redis.NewStringCmd(ctx)
	cmd.SetErr(err)
	cmd.SetVal(val)
	return cmd
}
