# hop-server, the HopKey sync server.
#
#   docker build -t hop-server .
#   docker run -v hop-data:/data -p 8080:8080 hop-server \
#       --origin https://hop.example.com --insecure-http --trusted-proxy 172.16.0.0/12
#
# TLS: the image serves plain HTTP on :8080 and refuses to start that way
# unless the operator says how TLS is handled. Run it behind a reverse proxy
# that terminates TLS (Caddy, nginx, a cloud load balancer) and pass
# --insecure-http, together with --trusted-proxy for the proxy's address so
# rate limits see real client IPs. Use --insecure-http only when the
# container's port is reachable from that proxy alone, on an isolated
# network; never publish it to the internet. Alternatively mount a
# certificate and pass --tls-cert and --tls-key. Clients always require
# HTTPS, whatever the server does (R10).
#
# --origin is required: the external https:// origin clients use. The
# server binds signatures to it and never takes it from request headers.
#
# The database lives in the /data volume. Back it up with
#   docker exec <container> hop-server backup /data/backup.db --data /data
# Health: GET /v1/healthz.

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
# modernc.org/sqlite is pure Go, so the binary is static with cgo off.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
        -ldflags "-s -w -X github.com/dalyem/hopkey/internal/version.Version=${VERSION}" \
        -o /out/hop-server ./cmd/hop-server \
    && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hop-server /usr/local/bin/hop-server
# The volume starts owned by the nonroot user (65532), which the server
# runs as.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hop-server", "serve", "--listen", ":8080", "--data", "/data"]
