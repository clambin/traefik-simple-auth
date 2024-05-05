package state

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStates(t *testing.T) {
	s := New[string](100 * time.Millisecond)

	url := "https://example.com"
	key := s.Add(url)
	assert.Equal(t, 1, s.Count())

	url2, ok := s.Validate(key)
	require.Truef(t, ok && url == url2, "failed to retrieve url from cache")

	_, ok = s.Validate(key)
	assert.Falsef(t, ok, "key should be removed after validation")

	assert.Eventuallyf(t, func() bool {
		_, ok = s.Validate(key)
		return !ok
	}, time.Second, 50*time.Millisecond, "state didn't expire")
	assert.Zero(t, s.Count())
}
