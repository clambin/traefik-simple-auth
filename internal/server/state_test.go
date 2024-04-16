package server

import (
	"github.com/clambin/go-common/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStateHandler(t *testing.T) {
	h := stateHandler{
		cache: cache.New[string, string](100*time.Millisecond, time.Hour),
	}

	url := "https://example.com"
	key, err := h.add(url)
	require.NoErrorf(t, err, "failed to add to cache")

	url2, ok := h.get(key)
	require.Truef(t, ok && url == url2, "failed to retrieve url from cache")

	assert.Eventuallyf(t, func() bool {
		_, ok = h.get(key)
		return !ok
	}, time.Second, 50*time.Millisecond, "state didn't expire")
}
