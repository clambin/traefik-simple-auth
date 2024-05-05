package main

import (
	"context"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/cmd"
	"github.com/clambin/traefik-simple-auth/internal/server"
	"github.com/prometheus/client_golang/prometheus"
	"os"
	"os/signal"
	"syscall"
)

var version string = "change-me"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := server.GetConfiguration()
	if err == nil {
		err = cmd.Run(ctx, cfg, prometheus.DefaultRegisterer, os.Stderr, version)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to start traefik-simple-auth: %s", err.Error())
		os.Exit(1)
	}
}
