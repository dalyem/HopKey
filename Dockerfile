# hop-server, the HopKey sync server.
#
#   docker build -t hop-server .
#   docker network create --internal --subnet 172.30.0.0/24 \
#       -o com.docker.network.bridge.inhibit_ipv4=true hop-net
#   docker run -d --name hop --network hop-net --ip 172.30.0.3 -v hop-data:/data \
#       hop-server --origin https://hop.example.com --insecure-http \
#       --trusted-proxy 172.30.0.2/32
#
# and the TLS proxy (here Caddy, but any will do), which publishes only
# HTTPS and joins hop-net at the one address the server trusts. The server
# takes an explicit address too, so that Docker never hands it the proxy's:
#
#   docker create --name proxy -p 443:443 \
#       caddy caddy reverse-proxy --from hop.example.com --to hop:8080
#   docker network connect --ip 172.30.0.2 hop-net proxy
#   docker start proxy
#
# The server's own port is never published, and only containers on hop-net
# reach :8080: the network is internal, so nothing routes to it from
# outside, and inhibit_ipv4 leaves the host without an address on its
# bridge (Docker otherwise gives the host 172.30.0.1 there, and any process
# on the host could reach the server directly). --trusted-proxy names the
# proxy alone.
# (For a proxy on the host instead, publish to loopback only, -p
# 127.0.0.1:8080:8080, and trust the address the container sees for it:
# the gateway of the network the container runs on, which docker network
# inspect shows, as a /32.)
#
# TLS: the image serves plain HTTP on :8080 and refuses to start that way
# unless the operator says how TLS is handled. Run it behind a reverse proxy
# that terminates TLS, as above, and pass --insecure-http together with
# --trusted-proxy for that proxy's address, so rate limits see real client
# IPs. Never publish the plain-HTTP port beyond the proxy: anyone who can
# reach it bypasses TLS and can forge X-Forwarded-For if it falls inside a
# trusted range. Alternatively mount a certificate and pass --tls-cert and
# --tls-key. Clients always require HTTPS, whatever the server does (R10).
#
# Both base images are pinned by digest. To update one, resolve the tag's
# current digest (docker buildx imagetools inspect <tag>) and replace it.
#
# --origin is required: the external https:// origin clients use. The
# server binds signatures to it and never takes it from request headers.
#
# The database lives in the /data volume. Back it up with
#   docker exec <container> hop-server backup /data/backup.db --data /data
# Health: GET /v1/healthz.

FROM golang:1.27-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/hop-server /usr/local/bin/hop-server
# The volume starts owned by the nonroot user (65532), which the server
# runs as.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/hop-server", "serve", "--listen", ":8080", "--data", "/data"]
