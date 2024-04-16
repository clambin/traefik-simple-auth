# traefik-simple-auth
[![release](https://img.shields.io/github/v/tag/clambin/traefik-simple-auth?color=green&label=release&style=plastic)](https://github.com/clambin/traefik-simple-auth/releases)
[![codecov](https://img.shields.io/codecov/c/gh/clambin/traefik-simple-auth?style=plastic)](https://app.codecov.io/gh/clambin/traefik-simple-auth)
[![Test](https://github.com/clambin/traefik-simple-auth/actions/workflows/ci.yaml/badge.svg)](https://github.com/clambin/traefik-simple-auth/actions)
[![Build](https://github.com/clambin/traefik-simple-auth/actions/workflows/build.yaml/badge.svg)](https://github.com/clambin/traefik-simple-auth/actions)
[![go report card](https://goreportcard.com/badge/github.com/clambin/traefik-simple-auth)](https://goreportcard.com/report/github.com/clambin/traefik-simple-auth)
[![license](https://img.shields.io/github/license/clambin/traefik-simple-auth?style=plastic)](LICENSE.md)

A simple, up-to-date, re-implementation of traefik-forward-auth.

## Goals

traefik-simple-auth provides an implementation of Traefik's forwardAuth middleware. Most people typically use Thom Seddon's 
[!traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth?tab=readme-ov-file#configuration), or one of its
many forks. However, that implementation hasn't been updated in over 3 years. I wrote traefik-simple-auth with the following goals:

* to learn about Traefik's forwardAuth middleware and the oauth approach that traefik-forward-auth uses;
* have an implementation that uses recent versions of Go and underlying modules (incorporating any security fixes since the last version of traefik-forward-auth was released);
* provide more operational observability into how forwardAuth is used;
* fun!

traefik-forward-auth offers many features that I wasn't necessarily interested in: support for openID, multiple domains, rules, etc. 
Those are not implemented in the current version of traefik-simple-auth. That may change in the future. 

## Design

The forwardAuth middleware delegates authentication to an external service. If the service answers with a 2XX code, access is granted, 
and the original request is performed. Otherwise, the response from the authentication server is returned.

traefik-simple-auth (like traefik-forward-auth) implements this authentication as a session Cookie: if the browser passes a valid cookie,
we consider the user as a valid user and can tell Traefik to perform the original request. 

For traefik-simple-auth, a valid cookie:

* has the name `_simple_auth`;
* comes from an authenticated user (more below);
* hasn't expired (as determined by the `expiry` parameter documented below);
* is secure (by creating a SHA256 HMAC of the above two values, using the `secret` parameter to generate the HMAC, to ensure it was issued by us);
* is sent to us by the browser, i.e. the final destination needs to be part of the `domain` configured for traefik-simple-auth).

If an incoming request does not contain a valid session cookie, the user needs to be authenticated:

* We forward the user to Google's login page, so the user can be authenticated;
* When the user has logged in, Google sends the request back to traefik-simple-auth, specifically to the address `<auth-host>/_oauth`;
* This routes the request to traefik-simple-auth's authCallback handler;
* The handler uses the request to retrieve the authenticated user's email address and see if it is part of the `users` whitelist; 
* If so, it creates a new session cookie, and redirects the user to the original destination, with the session cookie;
* This results in the request being sent back to traefik-simple-auth, with the session cookie, so it passes and the request is sent to the final destination.

Given the asynchronous nature of the handshake during the authentication, traefik-simple-auth needs to validate the request 
received from Google, to protect against cross-site request forgery (CSFR). The approach is as follows:

* When the authCallback handler forwards the user to Google, it passes a random 'state', that it associates with the original request (i.e. the final destination)
* When Google sends the request back to traefik-simple-auth, it passes the same 'state' with the request.
* traefik-simple-auth only keeps the state (with the final destination) for 5 minutes, which should be ample time for the user to log in.

## Installation

Container images are available on [ghcr.io](https://ghcr.io/clambin/traefik-simple-auth).

## Configuration
### Google

Head to https://console.developers.google.com and create a new project. Create new Credentials and select OAuth Client ID 
with "web application" as its application type.

Give the credentials a name and define the authorized redirect URIs. We currently supports one redirect URI, so all applications
need to be grouped under the same domain. E.g. if you need to support the following application URLs:

    * app1.example.com
    * app2.example.com
    * app3.example.com

then the redirectURL should use the domain `example.com` and the redirect URL should be `auth.example.com/_oauth`.

Note the Client ID and Client Secret as you will need to configure these for traefik-simple-auth.

### Traefik
#### Middleware

With your Google credentials defined, set up a `forward-auth` middleware. This causes Traefik to forward each incoming 
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

To authenticate a user, traefik-simple-auth redirects the user to their Google login page. Upon successful login, Google 
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

