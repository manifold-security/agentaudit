# agentaudit Makefile
# Build automation for the AI-assistant config scanner

.PHONY: all help build install test test-race vet fmt fmt-check lint \
	check clean

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

# The gates this project treats as non-negotiable.
check: fmt-check vet test test-race  ## Run every gate

clean:                      ## Remove build artifacts
	rm -rf dist/
