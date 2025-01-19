package main

import (
	"context"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/cmd"
	"github.com/prometheus/client_golang/prometheus"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
)

var version = "change-me"

func main() {
	if info, ok := debug.ReadBuildInfo(); ok {
		slog.Info("successfully read build info", "version", info.GoVersion, "main", info.Main)
	}
	go func() { _ = http.ListenAndServe(":6000", nil) }()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := cmd.Main(ctx, prometheus.DefaultRegisterer, version); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to start traefik-simple-auth: %s", err.Error())
		os.Exit(1)
	}
}
