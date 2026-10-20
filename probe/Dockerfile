# Build context is the repo ROOT so the shared pkg/ module is available.
# The build stage runs natively and cross-compiles, so multi-arch images don't
# compile Go under emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0
COPY pkg/ ./pkg/
COPY probe/go.mod probe/go.sum ./probe/
WORKDIR /src/probe
RUN go mod download
COPY probe/ ./
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /out/probe .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/probe /probe
# The default ./data/probe.key resolves to /data/probe.key. With no HUB_URL the
# image contributes to the public network, so `docker run` needs no config.
WORKDIR /
ENV HUB_URL=https://nl.lp.mw.gg
# NOTE: the ICMP and traceroute checks need raw sockets. To enable them, run the
# probe container with cap_add: [NET_RAW] (and/or set net.ipv4.ping_group_range).
# The HTTP/TCP/DNS/TLS checks need no extra privileges.
ENTRYPOINT ["/probe"]
