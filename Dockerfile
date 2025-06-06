FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.24 AS builder

ARG BUILDPLATFORM
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ENV VERSION=$VERSION

WORKDIR /app/
ADD . .
RUN GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -ldflags="-X main.version=$VERSION" \
    -o traefik-simple-auth \
    .

FROM alpine

WORKDIR /app
COPY --from=builder /app/traefik-simple-auth /app/traefik-simple-auth

RUN /usr/sbin/addgroup app
RUN /usr/sbin/adduser app -G app -D
USER app

ENTRYPOINT ["/app/traefik-simple-auth"]
CMD []
