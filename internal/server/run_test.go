package server

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		*addr = "localhost:8081"
		*promAddr = "localhost:9091"
		*users = "foo@example.com"
		*domainsString = "example.com"
		*clientId = "1234"
		*clientSecret = "567890"
		go func() {
			err := Run(ctx, os.Stderr, "dev")
			require.NoError(t, err)
		}()

		assert.Eventually(t, func() bool {
			resp, err := http.Get("http://localhost:8081/health")
			return err == nil && resp.StatusCode == http.StatusOK
		}, time.Second, 10*time.Millisecond)

		cancel()

		assert.Eventually(t, func() bool {
			_, err := http.Get("http://localhost:8081/health")
			return err != nil
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("config failure", func(t *testing.T) {
		*domainsString = ""
		err := Run(context.Background(), os.Stderr, "failing")
		assert.Error(t, err)
	})
}
