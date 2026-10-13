# agentaudit Makefile
# Build automation for the AI-assistant config scanner

.PHONY: all help build install test test-race vet fmt fmt-check lint wasm \
	wasm-compile wasm-test check clean

VERSION ?= dev
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

# The scanner is pure Go, so CGO buys nothing and
# disabling it keeps the binary portable.
export CGO_ENABLED := 0

all: check build

help:                       ## List the available targets
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | expand -t24

build:                      ## Build the CLI into dist/agentaudit
	@mkdir -p dist
	go build $(LDFLAGS) -o dist/agentaudit ./cmd/agentaudit

install:                    ## Install the CLI into GOBIN (or GOPATH/bin)
	go install $(LDFLAGS) ./cmd/agentaudit

test:                       ## Run the test suite
	go test ./... -count=1

# The race detector is a cgo-backed runtime on most toolchains, so this gate
# asks for cgo rather than depending on one that happens to permit it without.
test-race: CGO_ENABLED := 1
test-race:                  ## Run the test suite under the race detector
	go test ./... -count=1 -race

vet:                        ## Run go vet
	go vet ./...

fmt:                        ## Format every Go file in place
	gofmt -w .

fmt-check:                  ## Fail if any Go file is not gofmt-clean
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

lint:                       ## Run staticcheck when it is installed
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed, skipping"; \
	fi

# The browser artifact: the JS boundary plus everything it links.
wasm:                       ## Build the js/wasm target into dist/agentaudit.wasm
	@mkdir -p dist
	GOOS=js GOARCH=wasm go build -o dist/agentaudit.wasm ./wasm

# Go neither puts its js/wasm exec wrapper on PATH nor finds it from the test
# binary, and a run without -exec dies with "exec format error", which reads as
# a crash rather than as a missing wrapper.
WASM_EXEC = $(shell go env GOROOT)/lib/wasm/go_js_wasm_exec

# The artifact target above links only what the JS boundary reaches, so it says
# nothing about the rest of the module. This compiles every package.
wasm-compile:               ## Compile the whole module for js/wasm
	GOOS=js GOARCH=wasm go build ./...

# cmd/agentaudit is out of this sweep by nature rather than as a workaround.
# Its e2e tests and isolation guards shell out to the go tool, which a js/wasm
# host does not offer, and its linkFS fixture pins os.Root's hop-budget refusal
# of a symlink loop, which the shim answers with a different error. Those are
# host properties. perf_test.go opts out through its own build constraint for
# the same reason, so the sweep asserts behaviour and not wall-clock.
wasm-test:                  ## Run the suite under js/wasm, minus the CLI
	@wrapper='$(WASM_EXEC)'; \
	if [ ! -x "$$wrapper" ]; then \
		echo "no js/wasm exec wrapper at $$wrapper"; \
		exit 1; \
	fi; \
	packages=$$(GOOS=js GOARCH=wasm go list ./... | grep -v '/cmd/agentaudit$$'); \
	GOOS=js GOARCH=wasm go test $$packages -count=1 -exec="$$wrapper"

# The gates this project treats as non-negotiable.
check: fmt-check vet test test-race wasm-compile wasm-test  ## Run every gate

clean:                      ## Remove build artifacts
	rm -rf dist/
