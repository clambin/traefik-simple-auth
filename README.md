# traefik-simple-auth
[![release](https://img.shields.io/github/v/tag/clambin/traefik-simple-auth?color=green&label=release&style=plastic)](https://github.com/clambin/traefik-simple-auth/releases)
[![codecov](https://img.shields.io/codecov/c/gh/clambin/traefik-simple-auth?style=plastic)](https://app.codecov.io/gh/clambin/traefik-simple-auth)
[![test](https://github.com/clambin/traefik-simple-auth/workflows/ci.yaml/badge.svg)](https://github.com/clambin/traefik-simple-auth/actions)
[![build](https://github.com/clambin/traefik-simple-auth/workflows/build.yaml/badge.svg)](https://github.com/clambin/traefik-simple-auth/actions)
[![go report card](https://goreportcard.com/badge/github.com/clambin/traefik-simple-auth)](https://goreportcard.com/report/github.com/clambin/traefik-simple-auth)
[![license](https://img.shields.io/github/license/clambin/traefik-simple-auth?style=plastic)](LICENSE.md)

A simpler, up-to-date implementation of traefik-forward-auth

## Installation

## Running

```
Usage:
  -addr string
        The address to listen on for HTTP requests (default ":8080")
  -auth-host string
        Hostname that handles authentication requests from Google (default: auth.<domain>)
  -client-id string
        Google OAuth Client ID
  -client-secret string
        Google OAuth Client Secret
  -debug
        Enable debug mode
  -domain string
        Domain managed by traefik-simple-auth
  -expiry duration
        How long a session remains valid (default 720h0m0s)
  -insecure
        Use insecure cookies
  -prom string
        The address to listen on for Prometheus scrape requests (default ":9090")
  -secret string
        Secret to use for authentication
  -users string
        Comma-separated list of usernames to login
```

## Configuration

### Google

### Traefik

#### Middleware

#### Inggress

## Metrics

traefik-simple-auth exports the following metrics:

| metric | type |  labels | help |
| --- | --- |  --- | --- |
| traefik_simple_auth_http_request_duration_seconds | HISTOGRAM | code, method, path|duration of http requests |
| traefik_simple_auth_http_requests_total | COUNTER | code, method, path|total number of http requests |

## Authors

* **Christophe Lambin**

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

