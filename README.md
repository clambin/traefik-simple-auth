![logo.png](assets/images/logo.png)

# traefik-simple-auth
[![release](https://img.shields.io/github/v/tag/clambin/traefik-simple-auth?color=green&label=release&style=plastic)](https://github.com/clambin/traefik-simple-auth/releases)
[![codecov](https://img.shields.io/codecov/c/gh/clambin/traefik-simple-auth?style=plastic)](https://app.codecov.io/gh/clambin/traefik-simple-auth)
[![Test](https://github.com/clambin/traefik-simple-auth/actions/workflows/ci.yaml/badge.svg)](https://github.com/clambin/traefik-simple-auth/actions)
[![Build](https://github.com/clambin/traefik-simple-auth/actions/workflows/build.yaml/badge.svg)](https://github.com/clambin/traefik-simple-auth/actions)
[![go report card](https://goreportcard.com/badge/github.com/clambin/traefik-simple-auth)](https://goreportcard.com/report/github.com/clambin/traefik-simple-auth)
[![license](https://img.shields.io/github/license/clambin/traefik-simple-auth?style=plastic)](LICENSE.md)

A simple, up-to-date, re-implementation of traefik-forward-auth.

## ⚠️ Breaking change in v0.11.0
V0.11.0 only supports one domain. The command line argument `-domains` is replaced by `-domain`. 
To support multiple domains, run one instance of traefik-simple-auth per domain.

## Contents

- [Goals](#goals)
- [Design](#design)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Using Google as auth provider](#using-google-as-auth-provider)
  - [traefik](#traefik)
  - [traefik-simple-auth](#traefik-simple-auth)
- [Command line arguments](#command-line-arguments)
- [Metrics](#metrics)
- [Limitations](#limitations)
- [Authors](#authors)
- [License](#license)

## Goals

traefik-simple-auth provides an implementation of Traefik's forwardAuth middleware. 
The most well-known implementation of that middleware is Thom Seddon's[traefik-forward-auth](https://github.com/thomseddon/traefik-forward-auth), or one of its many forks. 
However, that implementation hasn't been updated in over 3 years. 

I wrote traefik-simple-auth with the following goals:

* to learn about Traefik's forwardAuth middleware and the oauth approach that traefik-forward-auth uses;
* have an implementation that uses recent versions of Go and underlying modules (incorporating any security fixes since the last version of traefik-forward-auth was released);
* provide more operational observability into how forwardAuth is used;
* fun! :)

traefik-forward-auth offers many features that I wasn't necessarily interested in: overlay mode, rules, etc. 
Those are not implemented in the current version of traefik-simple-auth. That may change in the future. 

## Design

The forwardAuth middleware delegates authentication to an external service. If the service answers with a 2XX code, access is granted, 
and the original request is performed. Otherwise, the response from the authentication server is returned.

traefik-simple-auth (like traefik-forward-auth) implements this authentication as a session Cookie: if the browser passes a valid cookie,
we consider the user as a valid user and can tell Traefik to perform the original request. 

For traefik-simple-auth, a valid cookie:

* has the name `_traefik_simple_auth`;
* comes from an authenticated user (more below);
* hasn't expired (as determined by the `expiry` parameter documented below);
* is secure (by creating a SHA256 HMAC of the above two values, using the `secret` parameter to generate the HMAC, to ensure it was issued by us);
* is sent to us by the browser, i.e. the final destination needs to be part of the `domain` configured for traefik-simple-auth.

If an incoming request does not contain a valid session cookie, the user needs to be authenticated:

* We forward the user to the auth provider's login page, so the user can be authenticated;
* When the user has logged in, the provider sends the request back to traefik-simple-auth, specifically to the address `<auth-prefix>.<domain>/_oauth`, 
which routes the request to traefik-simple-auth's authCallback handler;
* The handler uses the request to retrieve the authenticated user's email address and see if it is part of the `users` whitelist; 
* If so, it creates a new session cookie, and redirects the user to the original destination, with the session cookie;
* This results in the request being sent back to traefik-simple-auth, with the session cookie, so it passes and the request is sent to the final destination.

Given the asynchronous nature of the handshake during the authentication, traefik-simple-auth needs to validate the request 
received from the auth provider, to protect against cross-site request forgery (CSRF). The approach is as follows:

* When the authCallback handler forwards the user to the auth provider, it passes a random 'state', that it associates with the original request (i.e. the final destination)
* When the auth provider sends the request back to traefik-simple-auth, it passes the same 'state' with the request.
* traefik-simple-auth only keeps the state (with the final destination) for 10 minutes, which should be ample time for the user to log in.

## Installation

Container images are available on [ghcr.io](https://ghcr.io/clambin/traefik-simple-auth). Images are available for linux/amd64, linux/arm and linux/arm64.

## Configuration
### Using Google as auth provider

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

With your auth credentials defined, set up a `forward-auth` middleware. This causes Traefik to forward each incoming 
request for a router configured with this middleware for authentication.

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

traefik-simple-auth will add the email address of the authenticated used in the X-Forwarded-User header.

#### Ingress for Authentication

To authenticate a user, traefik-simple-auth redirects the user to the auth provider's login page. Upon successful login,
the provider forwards the request to the redirectURL (as configured in section `Using Google as auth provider`). 
You therefore need an ingress to route the request to traefik-simple-auth:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: traefik-simple-auth
  namespace: traefik
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
spec:
  rules:
    - host: auth.example.com
      http:
        paths:
          - path: /_oauth
            pathType: Prefix
            backend:
              service:
                name: traefik-simple-auth
                port:
                  number: 8080
```

This forwards the request to traefik-simple-auth. 

Note: unlike with github/thomseddon/traefik-forward-auth, the ingress for the authentication callback flow does not need the forwardAuth middleware
(i.e. it does not include a `traefik.ingress.kubernetes.io/router.middlewares: <traefik-simple-auth>` annotation).

#### Authenticating access to an ingress

To enable traefik-simple-auth to authenticate access to an ingress, add the middleware as an annotation:

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grafana-external
  namespace: monitoring
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: websecure
    traefik.ingress.kubernetes.io/router.middlewares: traefik-traefik-simple-auth@kubernetescrd
spec:
  rules:
    [...]
```

Each access to the ingress causes traefik to first forward the request to the middleware.  If the middleware responds
with an HTTP 2xx code (meaning the request has a valid session cookie), traefik honours the request.

Note: traefik prepends the namespace to the name of the middleware defined via a kubernetes resource. So, the middleware
`traefik-simple-auth` in the `traefik` namespace becomes `traefik-traefik-simple-auth`.

### traefik-simple-auth

With the configuration above, run traefik-forward-auth:

```
traefik-simple-auth \
  -addr :8080 \                     # service directs to port 8080
  -provider google \                # google is the auth provider
  -auth-prefix auth \               # prefix of the redirect URL configured in the auth provider
  -domain .example.com \            # only access requests for this domain 
  -client-id <client-id> \          # auth provider Client ID
  -client-secret <client-secret> \  # auth provider Client Secret
  -secret c2VjcmV0Cg==              # secret used to protect the session cookie
```

With this configuration, traefik-simple-auth authenticates any request for example.com, or any subdomain. Since no 
whitelist is provided, any authenticated user is allowed. The application handling the authenticated traffic can find 
the user in the `X-Forwarded-User` header of the request.

## Command line arguments

traefik-simple-auth supports the following command-line arguments:

```
Usage:
   -addr string
        The address to listen on for HTTP requests (default ":8080")
  -auth-prefix string
        prefix to construct the authRedirect URL from the domain (default "auth")
  -cache string
        The backend to use for caching CSFR states. memory, memcached and redis are supported (default "memory")
  -cache-memcached-addr string
        memcached address to use (only used when cache backend is memcached)
  -cache-redis-addr string
        redis address to use (only used when cache backend is redis)
  -cache-redis-database int
        redis database to use (only used when cache backend is redis)
  -cache-redis-password string
        Redis password (only used when cache backend is redis)
  -cache-redis-username string
        Redis username (only used when cache backend is redis)
  -client-id string
        OAuth2 Client ID
  -client-secret string
        OAuth2 Client Secret
  -debug
        Log debug messages
  -domain string
        Domain to allow access
  -expiry duration
        How long a session remains valid (default 720h0m0s)
  -prom string
        The address to listen on for Prometheus scrape requests (default ":9090")
  -provider string
        The OAuth2 provider (default "google")
  -provider-oidc-issuer string
        The OIDC Issuer URL to use (only used when provider is oidc (default "https://accounts.google.com")
  -secret string
        Secret to use for authentication (base64 encoded)
  -session-cookie-name string
        The cookie name to use for authentication (default "_traefik_simple_auth")
  -users string
        Comma-separated list of usernames to allow access
```

#### Option details

- `addr`

  Listener address for traefik-simple-auth

- `auth-prefix`

  The prefix used to construct the auth provider's redirect URL.

  Example: if the auth-prefix is `auth` and the domain is `example.com`, the Auth Redirect URL will be `https://auth.example.com/_oauth'.

- `cache`

  Defines how the State is shared between the forwardAuth and authCallback handlers. Default is `memory`, meaning the state is cached locally in memory.
  To support running multiple instances of traefik-simple-auth, this can be switched to `memcached` or `redis`, which uses an (external) server instead.

- `-cache-memcached-addr`

  Address of the memcached instance to use. Only used when `cache` is `memcached`.

- `cache-redis-addr`, `cache-redis-username`, `cache-redis-password`, `cache-redis-database`

  Address, username, password and database number to use. Only used when `cache` is `redis`. 

- `client-id`

  The Client ID, found in the OAuth provider's credentials configuration.

- `client-secret`

  The Client Secret, found in the OAuth provider's Credentials configuration.

- `debug`

  Log debug messages

- `domain`

  The domain to allow requests for: if "example.com" is an allowed domain, then all subdomains (e.g. www.example.com) are allowed.

  Note: the domain needs a redirect URL configured in the Oauth2 provider, matching the domain, e.g. when using example.com,
  https://auth.example.com/_oauth needs to be set up as redirect URLs and an ingress is needed to route back to traefik-simple-auth.

- `expiry`

  Lifetime of the session cookie, i.e. how long before a user must log back into Google.

- `prom`

  Listener address for Prometheus metrics

- `provider`

  The auth provider to use. Supported values are `github`, `google` and `oidc`. When using `oidc` (i.e. OpenID Connect), 
  the user should also provide the OIDC Issuer URL for the OIDC service (`-provider-oidc-issuer-url`).

  Note: in theory any OpenID Connect-compliant service should work, but only Google has been tested.

- `provider-oidc-issuer-url`

  The OpenID Connect Issuer URL to use for the oidc provider. Default is "https://accounts.google.com" (i.e. Google)

- `secret`

  A (base64-encoded) secret used to protect the session cookie.

- `session-cookie-name`

  The name of the browser cookie holding the session. Overriding this may be useful when you to segregate a user signing in to one instance of traefik-simple-auth vs. any other instances.
  
  By default, traefik-simple-auth uses Google as oauth provider and a session cooke called `traefik-simple-auth`.
  If a second instance, using GitHub oauth, used the same cookie name, then signing in to Google would also allow any flows
  authenticated by GitHub. If you want to segregate this, use a different `session-cookie-name` for the GitHub instance.  

- `users`

  A comma-separated list of email addresses that should be allowed to use traefik-simple-auth. If the list is blank, then any email address will be allowed.

## Metrics

traefik-simple-auth exports the following metrics:

| metric                                            | type      | labels                           | help                          |
|---------------------------------------------------|-----------|----------------------------------|-------------------------------|
| traefik_simple_auth_active_users                  | GAUGE     | provider, user                   | number of active users        |
| traefik_simple_auth_http_request_duration_seconds | HISTOGRAM | code, host, path, provider, user | duration of http requests     |
| traefik_simple_auth_http_requests_total           | COUNTER   | code, host, path, provider, user | total number of http requests |

## Limitations

- The oauth callback (`https://<auth-prefix>.<domain>/_oauth`) is restricted to the standard https port (i.e. 443).

## Authors

* **Christophe Lambin**

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

