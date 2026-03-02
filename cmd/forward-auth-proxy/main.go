package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

// A simple development tool that emulates a forward-auth between a client and a server.

var (
	user = flag.String("user", "user@example.com", "User to forward")
	addr = flag.String("addr", ":8080", "Address to listen on")
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		_, _ = fmt.Fprintf(os.Stderr, "usage: %s [ -user <username> ] [ -addr <listener-address> ] <backend-url>\n", os.Args[0])
		os.Exit(1)
	}
	backendURL, err := url.Parse(flag.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid backend URL: %v", err)
		os.Exit(2)
	}

	log.Printf("Proxy on %s\n", *addr)
	http.Handle("/", forwardAuthHandler(backendURL, *user))
	if err := http.ListenAndServe(*addr, nil); !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func forwardAuthHandler(backendURL *url.URL, user string) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.Clone(r.Context())
		r.Header.Set("X-Forwarded-User", user)
		log.Printf("Forwarding request for %s to %s", r.URL.String(), backendURL.String())
		proxy.ServeHTTP(w, r)
	})
}
