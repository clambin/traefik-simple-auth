package main

import (
	"context"
	"fmt"
	"github.com/clambin/traefik-simple-auth/internal/server"
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
		err = server.Run(ctx, cfg, os.Stderr, version)
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to start traefik-simple-auth: %s", err.Error())
		os.Exit(1)
	}
}
