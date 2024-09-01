package state

import (
	"context"
	"errors"
	"github.com/alicebob/miniredis/v2"
	"github.com/bradfitz/gomemcache/memcache"
	gcc "github.com/clambin/go-common/cache"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_cache(t *testing.T) {
	rd := miniredis.RunT(t)
	tests := []struct {
		name   string
		cfg    Configuration
		panics bool
	}{
		{
			name:   "invalid",
			cfg:    Configuration{CacheType: "invalid"},
			panics: true,
		},
		{
			name: "local cache",
			cfg:  Configuration{CacheType: "memory"},
		},
		{
			name: "memcached",
			cfg:  Configuration{CacheType: "memcached"},
		},
		{
			name: "redis",
			cfg:  Configuration{CacheType: "redis", RedisConfiguration: RedisConfiguration{Addr: rd.Addr()}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.panics {
				assert.Panics(t, func() { newCache[string](tt.cfg) })
				return
			}

			c := newCache[string](tt.cfg)
			if tt.cfg.CacheType == "memcached" {
				c = memcachedCache[string]{Client: &fakeMemcachedClient{c: localCache[string]{values: gcc.New[string, string](0, 0)}}}
			}

			ctx := context.Background()
			count, err := c.Len(ctx)
			assert.NoError(t, err)
			assert.Zero(t, count)

			assert.NoError(t, c.Add(ctx, "key", "value", time.Hour))
			value, err := c.GetDel(ctx, "key")
			assert.NoError(t, err)
			assert.Equal(t, "value", value)
			_, err = c.GetDel(ctx, "key")
			assert.ErrorIs(t, err, ErrNotFound)

			assert.NoError(t, c.Ping(ctx))
		})
	}
}

func BenchmarkCache(b *testing.B) {
	ctx := context.Background()
	b.Run("string", func(b *testing.B) {
		c := newCache[string](Configuration{CacheType: "memory"})
		for range b.N {
			_ = c.Add(ctx, "key", "value", time.Hour)
			_, _ = c.GetDel(ctx, "key")
		}
	})
	b.Run("int", func(b *testing.B) {
		c := newCache[int](Configuration{CacheType: "memory"})
		for range b.N {
			_ = c.Add(ctx, "key", 1, time.Hour)
			_, _ = c.GetDel(ctx, "key")
		}
	})
}

var _ memcachedClient = &fakeMemcachedClient{}

type fakeMemcachedClient struct {
	c localCache[string]
}

func (f *fakeMemcachedClient) Ping() error {
	return nil
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
