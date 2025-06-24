package csrf

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestStateStore(t *testing.T) {
	c := New(Configuration{
		TTL: 500 * time.Millisecond,
	})

	ctx := context.Background()
	state, err := c.Add(ctx, "foo")
	require.NoError(t, err)
	_, err = hex.DecodeString(state)
	assert.NoError(t, err)

	value, err := c.Validate(ctx, state)
	require.NoError(t, err)
	assert.Equal(t, "foo", value)

	_, err = c.Validate(ctx, state)
	require.ErrorIs(t, err, ErrNotFound)

	assert.NoError(t, c.Ping(ctx))
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
