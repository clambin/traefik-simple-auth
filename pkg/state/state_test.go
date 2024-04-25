package state

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_stateHandler(t *testing.T) {
	h := New[string](100 * time.Millisecond)

	url := "https://example.com"
	key := h.Add(url)

	url2, ok := h.Get(key)
	require.Truef(t, ok && url == url2, "failed to retrieve url from cache")

	assert.Eventuallyf(t, func() bool {
		_, ok = h.Get(key)
		return !ok
	}, time.Second, 50*time.Millisecond, "state didn't expire")
}
