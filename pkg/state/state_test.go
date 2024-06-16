package state

import (
	"context"
	"github.com/clambin/go-common/cache"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStates(t *testing.T) {
	tests := []struct {
		name    string
		backend Backend[string]
	}{
		{
			name: "localCache",
			backend: LocalCache[string]{
				values: cache.New[string, string](0, 0),
			},
		},
		{
			name: "redisCache",
			backend: RedisCache{
				Client: &fakeRedisClient{c: LocalCache[string]{values: cache.New[string, string](0, 0)}},
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
			assert.Equal(t, 1, count)

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

var _ RedisClient = &fakeRedisClient{}

type fakeRedisClient struct {
	c LocalCache[string]
}

func (f *fakeRedisClient) Set(ctx context.Context, key string, value any, expiration time.Duration) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(ctx)
	cmd.SetErr(f.c.Add(ctx, key, value.(string), expiration))
	return cmd
}

func (f *fakeRedisClient) GetDel(ctx context.Context, key string) *redis.StringCmd {
	cmd := redis.NewStringCmd(ctx)
	value, err := f.c.Get(ctx, key)
	cmd.SetVal(value)
	cmd.SetErr(err)
	return cmd
}

func (f *fakeRedisClient) Keys(ctx context.Context, _ string) *redis.StringSliceCmd {
	cmd := redis.NewStringSliceCmd(ctx)
	cmd.SetVal(f.c.values.GetKeys())
	return cmd
}
