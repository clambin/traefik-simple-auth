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
need to be grouped under the same domain. E.g., if you need to support the following application URLs:

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
(i.e., it does not include a `traefik.ingress.kubernetes.io/router.middlewares: <traefik-simple-auth>` annotation).

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
with an HTTP 2xx code (meaning the request has a valid session cookie), traefik honors the request.

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
  -auth.auth-prefix string
        Prefix to construct the authRedirect URL from the domain (default "auth")
  -auth.client-id string
        OAuth2 Client ID
  -auth.client-secret string
        OAuth2 Client Secret
  -auth.issuer-url string
        The Auth Issuer URL to use (only used when provider is oidc) (default "https://accounts.google.com")
  -auth.provider string
        OAuth2 provider (default "google")
  -csrf.redis.addr string
        Redis server address
  -csrf.redis.database int
        Redis database number
  -csrf.redis.namespace string
        When sharing a redis db, namespace can be prepended to the key to avoid collision with other applications  (default "github.com/clambin/traefik-simple-auth/state")
  -csrf.redis.password string
        Redis password
  -csrf.redis.username string
        Redis username
  -csrf.ttl duration
        Lifetime of a CSRF token (default 10m0s)
  -domain value
        Domain to allow access
  -log.format string
        log format (default "text")
  -log.level string
        log level (default "info")
  -prom.addr string
        prometheus listen address (default ":9100")
  -prom.path string
        prometheus path (default "/metrics")
  -session.cookie-name string
        The cookie name to use for authentication (default "_traefik_simple_auth")
  -session.expiration duration
        How long the session should remain valid (default 720h0m0s)
  -session.secret value
        Secret to use for authentication (base64 encoded)
  -users value
        Comma-separated list of usernames to allow access
```

##### Maim parameters

- `domain`

  The domain to allow requests for: if "example.com" is an allowed domain, then all subdomains (e.g., www.example.com) are allowed.

  Note: the domain needs a redirect URL configured in the Oauth2 provider, matching the domain, e.g., when using example.com,
  https://auth.example.com/_oauth needs to be set up as redirect URLs and an ingress is needed to route requests back to traefik-simple-auth.

- `session.expiration`

  Lifetime of the session cookie, i.e., how long before a user must log back into Google.

- `session.secret`

  A (base64-encoded) secret used to protect the session cookie.

- `session.cookie-name`

  The name of the browser cookie holding the session. Overriding this may be useful when you to segregate multiple instances of traefik-simple-auth, running for different domains / providers.

##### auth

- `auth.provider`

  This specifies the type of oauth2 provider. Currently supports `google`, `github` and `oidc`.

- `auth.client-id` and `auth.client-secret`

  These are the Client ID and Client Secret obtained from your auth provider. 

- `auth.issuer-url string`

  The OpenID Connect Issuer URL to use for the oidc provider. Only needed when using `oidc`.

- `auth.auth-prefix`

  The prefix used to construct the auth provider's redirect URL.

 Example: if the auth-prefix is `auth` and the domain is `example.com`, the Auth Redirect URL will be `https://auth.example.com/_oauth'.


##### csrf 

- `-csrf.ttl`

  Specifies how long a CSRF token remains valid, i.e., how long we wait for the user to log into his auth provider.

- `csrf.redis.addr`, `csrf.redis.database`, `csrf.redis.username`, `csrf.redis.password`

  traefik-simple-auth can store the CSRF tokens in a redis database. This is only relevant when running multiple instances.
  
  If `csrf.redis.addr` is empty, traefik-simple-auth stores the CSRF tokens in a memory cache.

- `csrf.redis.namespace`

  Namespace for redis keys. Only relevant when using redis as a CSRF cache, sharing the database with other applications.
 
## Metrics

traefik-simple-auth exports the following metrics:

| metric                                            | type      | labels                           | help                          |
|---------------------------------------------------|-----------|----------------------------------|-------------------------------|
| traefik_simple_auth_active_users                  | GAUGE     | provider, user                   | number of active users        |
| traefik_simple_auth_http_request_duration_seconds | HISTOGRAM | code, host, path, provider, user | duration of http requests     |
| traefik_simple_auth_http_requests_total           | COUNTER   | code, host, path, provider, user | total number of http requests |

## Limitations

- The oauth callback (`https://<auth-prefix>.<domain>/_oauth`) is restricted to the standard https port (i.e., 443).

## Authors

* **Christophe Lambin**

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
