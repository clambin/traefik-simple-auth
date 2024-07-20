package state

import (
	"context"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStates(t *testing.T) {
	c := States{
		Cache:     NewLocalCache[string](),
		Namespace: "github.com/clambin/traefik-simple-auth",
		TTL:       500 * time.Millisecond,
	}

	ctx := context.Background()
	state, err := c.Add(ctx, "foo")
	require.NoError(t, err)
	_, err = hex.DecodeString(state)
	assert.NoError(t, err)

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
}
