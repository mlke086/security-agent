# Go Agent build -- produces platform binaries for download via the console.
#
# Usage:
#   make build           # build for current platform
#   make build-linux-amd64
#   make build-linux-arm64
#   make build-windows-amd64
#   make build-all       # build for linux/amd64 + linux/arm64 + windows/amd64
#
# Output goes to ../deployments/agent/dist/<os>/<arch>/agent[.exe]
# (the same path the FastAPI ``/api/v1/agents/binary/<os>/<arch>`` endpoint reads).

BINARY_NAME := agent
DIST := ../deployments/agent/dist

LDFLAGS := -s -w
GO ?= go

.PHONY: all build build-linux-amd64 build-linux-arm64 build-windows-amd64 build-all clean help

all: build

help:
	@echo "Targets:"
	@echo "  build               - build for the current platform"
	@echo "  build-linux-amd64   - linux/amd64"
	@echo "  build-linux-arm64   - linux/arm64"
	@echo "  build-windows-amd64 - windows/amd64 (.exe)"
	@echo "  build-all           - all of the above"
	@echo "  clean               - remove build artifacts"

build:
	@mkdir -p $(DIST)/$$(go env GOOS)/$$(go env GOARCH)
	$(GO) build -ldflags '$(LDFLAGS)' -o $(DIST)/$$(go env GOOS)/$$(go env GOARCH)/$(BINARY_NAME)$$( [ "$$(go env GOOS)" = "windows" ] && echo .exe ) ./cmd/agent

build-linux-amd64:
	@mkdir -p $(DIST)/linux/amd64
	GOOS=linux GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(DIST)/linux/amd64/$(BINARY_NAME) ./cmd/agent
	@echo "Built: $(DIST)/linux/amd64/$(BINARY_NAME)"

build-linux-arm64:
	@mkdir -p $(DIST)/linux/arm64
	GOOS=linux GOARCH=arm64 $(GO) build -ldflags '$(LDFLAGS)' -o $(DIST)/linux/arm64/$(BINARY_NAME) ./cmd/agent
	@echo "Built: $(DIST)/linux/arm64/$(BINARY_NAME)"

build-windows-amd64:
	@mkdir -p $(DIST)/windows/amd64
	GOOS=windows GOARCH=amd64 $(GO) build -ldflags '$(LDFLAGS)' -o $(DIST)/windows/amd64/$(BINARY_NAME).exe ./cmd/agent
	@echo "Built: $(DIST)/windows/amd64/$(BINARY_NAME).exe"

build-all: build-linux-amd64 build-linux-arm64 build-windows-amd64

clean:
	rm -rf $(DIST)
