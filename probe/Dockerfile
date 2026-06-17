# Build context is the repo ROOT so the shared pkg/ module is available.
FROM golang:1.26 AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0
COPY pkg/ ./pkg/
COPY probe/go.mod probe/go.sum ./probe/
WORKDIR /src/probe
RUN go mod download
COPY probe/ ./
RUN go build -trimpath -ldflags="-s -w" -o /out/probe .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/probe /probe
# NOTE: the ICMP and traceroute checks need raw sockets. To enable them, run the
# probe container with cap_add: [NET_RAW] (and/or set net.ipv4.ping_group_range).
# The HTTP/TCP/DNS/TLS checks need no extra privileges.
ENTRYPOINT ["/probe"]
