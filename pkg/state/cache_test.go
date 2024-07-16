package state

import (
	"context"
	"errors"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/clambin/go-common/cache"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	tests := []struct {
		name  string
		cache Cache[string]
	}{
		{
			name:  "local cache",
			cache: NewLocalCache[string](),
		},
		{
			name: "memcache",
			cache: MemcachedCache[string]{
				Client: &fakeMemcachedClient{c: LocalCache[string]{values: cache.New[string, string](0, 0)}},
			},
		},
		{
			name: "redis",
			cache: RedisCache[string]{
				Client: &fakeRedisClient{c: LocalCache[string]{values: cache.New[string, string](0, 0)}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			count, err := tt.cache.Len(ctx)
			assert.NoError(t, err)
			assert.Zero(t, count)

			assert.NoError(t, tt.cache.Add(ctx, "key", "value", time.Hour))
			value, err := tt.cache.GetDel(ctx, "key")
			assert.NoError(t, err)
			assert.Equal(t, "value", value)
			_, err = tt.cache.GetDel(ctx, "key")
			assert.ErrorIs(t, err, ErrNotFound)
		})
	}
}

func BenchmarkCache(b *testing.B) {
	ctx := context.Background()
	b.Run("string", func(b *testing.B) {
		c := NewLocalCache[string]()
		for range b.N {
			_ = c.Add(ctx, "key", "value", time.Hour)
			_, _ = c.GetDel(ctx, "key")
		}
	})
	b.Run("int", func(b *testing.B) {
		c := NewLocalCache[int]()
		for range b.N {
			_ = c.Add(ctx, "key", 1, time.Hour)
			_, _ = c.GetDel(ctx, "key")
		}
	})
}

var _ MemcachedClient = &fakeMemcachedClient{}

type fakeMemcachedClient struct {
	c LocalCache[string]
}

func (f *fakeMemcachedClient) Set(item *memcache.Item) error {
	return f.c.Add(context.Background(), item.Key, string(item.Value), time.Duration(item.Expiration)*time.Second)
}

func (f *fakeMemcachedClient) Get(key string) (*memcache.Item, error) {
	value, err := f.c.GetDel(context.Background(), key)
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
	err := f.c.Add(ctx, key, string(value.([]byte)), ttl)
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetErr(err)
	return cmd
}

func (f fakeRedisClient) GetDel(ctx context.Context, key string) *redis.StringCmd {
	val, err := f.c.GetDel(ctx, key)
	if errors.Is(err, ErrNotFound) {
		err = redis.Nil
	}
	cmd := redis.NewStringCmd(ctx)
	cmd.SetErr(err)
	cmd.SetVal(val)
	return cmd
}
