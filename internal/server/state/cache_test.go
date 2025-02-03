package state

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"testing"
	"time"
)

func Test_cache(t *testing.T) {
	tests := []struct {
		name      string
		cacheType string
		panics    bool
	}{
		{
			name:      "invalid",
			cacheType: "invalid",
			panics:    true,
		},
		{
			name:      "local cache",
			cacheType: "memory",
		},
		{
			name:      "memcached",
			cacheType: "memcached",
		},
		{
			name:      "redis",
			cacheType: "redis",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Configuration{CacheType: tt.cacheType}
			if tt.panics {
				assert.Panics(t, func() { newCache[string](cfg) })
				return
			}

			ctx := context.Background()
			switch tt.cacheType {
			case "memcached":
				c, ep, err := startContainer(ctx, memcachedReq)
				require.NoError(t, err)
				cfg.MemcachedConfiguration.Addr = ep
				t.Cleanup(func() { _ = c.Terminate(ctx) })
			case "redis":
				c, ep, err := startContainer(ctx, redisReq)
				require.NoError(t, err)
				cfg.RedisConfiguration.Addr = ep
				t.Cleanup(func() { _ = c.Terminate(ctx) })
			}

			c := newCache[string](cfg)

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

var (
	redisReq = testcontainers.ContainerRequest{
		Image:        "redis:latest",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	memcachedReq = testcontainers.ContainerRequest{
		Image:        "memcached:latest",
		ExposedPorts: []string{"11211/tcp"},
		WaitingFor:   wait.ForExposedPort(),
	}
)

func startContainer(ctx context.Context, req testcontainers.ContainerRequest) (testcontainers.Container, string, error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		//Logger:           log.Default(),
	})
	if err != nil {
		return nil, "", err
	}
	endpoint, err := c.Endpoint(ctx, "")
	if err != nil {
		_ = c.Terminate(ctx)
		return nil, "", err
	}
	return c, endpoint, nil
}
