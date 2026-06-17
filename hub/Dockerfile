# Build context is the repo ROOT (see docker-compose.yml) so the shared pkg/
# module is available to the hub's `replace` directive.
FROM golang:1.26 AS build
WORKDIR /src
ENV GOWORK=off CGO_ENABLED=0
COPY pkg/ ./pkg/
COPY hub/go.mod hub/go.sum ./hub/
WORKDIR /src/hub
RUN go mod download
COPY hub/ ./
RUN go build -trimpath -ldflags="-s -w" -o /out/hub .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/hub /hub
COPY migrations/ /migrations/
# 8080 = HTTP API/dashboard, 4001 = libp2p mesh
EXPOSE 8080 4001
ENTRYPOINT ["/hub"]
