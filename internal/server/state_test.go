package server

import (
	"github.com/clambin/go-common/cache"
	"testing"
	"time"
)

func TestStateHandler(t *testing.T) {
	h := stateHandler{
		cache: cache.New[string, string](100*time.Millisecond, time.Hour),
	}

	url := "https://example.com"
	key, err := h.Add(url)
	if err != nil {
		t.Fatalf("Error adding to cache: %v", err)
	}

	url2, ok := h.Get(key)
	if !ok || url != url2 {
		t.Errorf("Getting from cache failed: expected %v, got %v", url2, url)
	}

	time.Sleep(300 * time.Millisecond)
	if _, ok = h.Get(key); ok {
		t.Errorf("Getting from cache failed: cache still exists")
	}
}
