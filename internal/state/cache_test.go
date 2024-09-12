package state

import (
	"context"
	"github.com/alicebob/miniredis/v2"
	"github.com/daangn/minimemcached"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strconv"
	"testing"
	"time"
)

func Test_cache(t *testing.T) {
	rd := miniredis.RunT(t)
	mc, err := minimemcached.Run(&minimemcached.Config{Port: 0})
	require.NoError(t, err)
	t.Cleanup(mc.Close)

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
			cfg:  Configuration{CacheType: "memcached", MemcachedConfiguration: MemcachedConfiguration{Addr: "localhost:" + strconv.Itoa(int(mc.Port()))}},
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
