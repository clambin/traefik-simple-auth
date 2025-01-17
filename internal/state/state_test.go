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
	c := New(Configuration{
		CacheType: "memory",
		Namespace: "github.com/clambin/traefik-simple-auth/states",
		TTL:       500 * time.Millisecond,
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
