# LibrePing developer shortcuts. The Go code is a workspace of three modules
# (pkg, probe, hub) tied together by go.work.

GO_MODULES := pkg probe hub

.PHONY: build test vet lint web up probe-up down tidy fmt

## build: compile every Go module
build:
	@for m in $(GO_MODULES); do echo ">> build $$m"; (cd $$m && go build ./...) || exit 1; done

## test: run every Go module's tests (includes the P2P gossip integration test)
test:
	@for m in $(GO_MODULES); do echo ">> test $$m"; (cd $$m && go test ./...) || exit 1; done

## vet: go vet across modules
vet:
	@for m in $(GO_MODULES); do echo ">> vet $$m"; (cd $$m && go vet ./...) || exit 1; done

## lint: run golangci-lint if installed, otherwise fall back to vet
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		for m in $(GO_MODULES); do echo ">> lint $$m"; (cd $$m && golangci-lint run) || exit 1; done; \
	else \
		echo "golangci-lint not installed; running go vet instead"; \
		$(MAKE) vet; \
	fi

## fmt: format all Go code
fmt:
	gofmt -w $(GO_MODULES)

## tidy: tidy module dependencies
tidy:
	@for m in $(GO_MODULES); do echo ">> tidy $$m"; (cd $$m && GOWORK=off go mod tidy) || exit 1; done

## web: build the dashboard
web:
	cd web && npm install && npm run build

## up: run a full hub node (hub + db + dashboard + local probe)
up:
	docker compose up --build

## probe-up: run a probe-only node (set HUB_URL)
probe-up:
	docker compose -f docker-compose.probe.yml up --build

## down: stop and remove the local stack
down:
	docker compose down
