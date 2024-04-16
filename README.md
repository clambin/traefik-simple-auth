# traefik-simple-auth
[![release](https://img.shields.io/github/v/tag/clambin/traefik-simple-auth?color=green&label=release&style=plastic)](https://github.com/clambin/traefik-simple-auth/releases)
[![codecov](https://img.shields.io/codecov/c/gh/clambin/traefik-simple-auth?style=plastic)](https://app.codecov.io/gh/clambin/traefik-simple-auth)
[![Test](https://github.com/clambin/traefik-simple-auth/actions/workflows/ci.yaml/badge.svg)](https://github.com/clambin/traefik-simple-auth/actions)
[![Build](https://github.com/clambin/traefik-simple-auth/actions/workflows/build.yaml/badge.svg)](https://github.com/clambin/traefik-simple-auth/actions)
[![go report card](https://goreportcard.com/badge/github.com/clambin/traefik-simple-auth)](https://goreportcard.com/report/github.com/clambin/traefik-simple-auth)
[![license](https://img.shields.io/github/license/clambin/traefik-simple-auth?style=plastic)](LICENSE.md)

A simple, up-to-date, re-implementation of traefik-forward-auth.

## Design

TODO

## Installation

Container images are available on [ghcr.io](https://ghcr.io/clambin/traefik-simple-auth).

## Configuration
### Google

Head to https://console.developers.google.com and create a new project. Create new Credentials and select OAuth Client ID 
with "web application" as its application type.

Give the credentials a name and define the authorized redirect URIs. We currently supports one redirect URI, so all applications
will need to be grouped under the same domain. E.g. if you need to support the following application URLs:

    * app1.example.com
    * app2.example.com
    * app3.example.com

then the redirectURL should use the domain `example.com` and the redirect URL should be `auth.example.com/_oauth`.

Note the Client ID and Client Secret as you will need to configure these for traefik-auth-simple.

### Traefik
#### Middleware

With your Google credentials defined, set up a `forward-auth` middleware. This will cause Traefik to forward each incoming 
request for an router configured with this middleware for authentication.

In Kubernetes, this can be done with the following manifest:

```
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: traefik-simple-auth
spec:
  forwardAuth:
    address: http://traefik-simple-auth:8080
    trustForwardHeader: true
    authResponseHeaders:
      - "X-Forwarded-User"
```

This created a new middleware `traefik-simple-auth` that forwards incoming requests to `http://traefik-simple-auth:8080`
(the service pointing to traefik-simple-auth) for authentication. 

#### Ingress

To authenticate a user, traefik-simple-auth redirects the user to its Google login page. Upon successful login, Google 
forwards the request to the redirectURL (as configured in section Google). You will therefore need an ingress to route 
the request to traefik-simple-auth:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: traefik-simple-auth
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.middlewares: traefik-traefik-simple-auth@kubernetescrd
spec:
  rules:
    - host: auth.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: traefik-simple-auth
                port:
                  number: 8080
```

This forwards the Google request back to traefik-simple-auth. 

### Running traefik-simple-auth

traefik-simple-auth supports the following command-line arguments:

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

#### Option details

- `auth-host`

   Google authentication requests are routed back to this host. If not set, it defaults to auth.`domain`

- `domain`

   The domain to construct `auth-host`. All targets supported by an installation of traefik-simple-auth must be part of the same domain.

- `client-id`

   The (hex-encoded) Google Client ID, found in the Google Credentials configuration.

- `client-secret`

  The (hex-encoded) Google Client Secret, found in the Google Credentials configuration

- `secret`

  A (hex-encoded) 256-bit secret used to protect the session cookie.

- `expiry`

  Lifetime of the session cookie, i.e. how long before a user must log back into Google.

- `insecure`

  Marks the session cookie as insecure so it can be used over HTTP sessions.

- `users`

  A comma-separated list of email addresses that should be allowed to use traefik-simple-auth.

- `addr`

   Listener address for traefik-simple-auth

- `prom`

  Listener address for Prometheus metrics

- `debug` 

  Enable debug mode

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

