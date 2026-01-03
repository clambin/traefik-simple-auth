package csrf

import (
	"context"
	"encoding/hex"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestStateStore(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := Configuration{
			TTL: 5 * time.Minute,
		}
		c := New(cfg)
		ctx := t.Context()

		// Ping the cache
		assert.NoError(t, c.Ping(ctx))

		// Add a new state
		const value = "foo"
		state, err := c.Add(ctx, value)
		require.NoError(t, err)
		// state is a hex-encoded string
		_, err = hex.DecodeString(state)
		assert.NoError(t, err)

		// Validate the state
		got, err := c.Validate(ctx, state)
		require.NoError(t, err)
		assert.Equal(t, value, got)

		// A state can only be validated once
		_, err = c.Validate(ctx, state)
		require.ErrorIs(t, err, ErrNotFound)

		// A state times out after the TTL duration
		_, err = c.Add(ctx, value)
		require.NoError(t, err)
		time.Sleep(2 * cfg.TTL)
		_, err = c.Validate(ctx, state)
		require.ErrorIs(t, err, ErrNotFound)
	})
}

func Test_cache(t *testing.T) {
	tests := []struct {
		name      string
		cacheType string
		panics    bool
	}{
		{
			name:      "memory",
			cacheType: "memory",
		},
		{
			name:      "redis",
			cacheType: "redis",
		},
	}

	for _, tt := range tests {
		cfg := Configuration{TTL: time.Minute, Redis: RedisConfiguration{Namespace: "foo"}}
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			switch tt.cacheType {
			case "redis":
				c, ep, err := startContainer(ctx, redisReq)
				require.NoError(t, err)
				cfg.Redis.Addr = ep
				t.Cleanup(func() { _ = c.Terminate(context.Background()) })
			}

			c := New(cfg).cache
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

var redisReq = testcontainers.ContainerRequest{
	Image:        "redis:latest",
	ExposedPorts: []string{"6379/tcp"},
	WaitingFor:   wait.ForLog("Ready to accept connections"),
}

func startContainer(ctx context.Context, req testcontainers.ContainerRequest) (testcontainers.Container, string, error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
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
