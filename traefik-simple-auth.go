package main

import (
	"context"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/cmd"
	"github.com/prometheus/client_golang/prometheus"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
)

var version = "change-me"

func main() {
	go func() { _ = http.ListenAndServe(":6000", nil) }()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cmd.Main(ctx, prometheus.DefaultRegisterer, version); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to start traefik-simple-auth: %s", err.Error())
		os.Exit(1)
	}
}
