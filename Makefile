GO ?= go
GOFMT ?= gofmt
NODE ?= node
TARGET_OS := $(shell $(GO) env GOOS)
EXT := so
ifeq ($(TARGET_OS),darwin)
EXT := dylib
endif
ifeq ($(TARGET_OS),windows)
EXT := dll
endif
LIB := build/cpa-plugin-set-proxies.$(EXT)

.DEFAULT_GOAL := build
.PHONY: build fmt fmt-check vet test check clean

build:
	mkdir -p build
	CGO_ENABLED=1 $(GO) build -trimpath -buildmode=c-shared -o $(LIB) ./cmd/cpa-plugin-set-proxies

fmt:
	$(GOFMT) -w cmd internal

fmt-check:
	@files="$$($(GOFMT) -l cmd internal)" || exit 1; \
	if [ -n "$$files" ]; then printf 'Run make fmt to format:\n%s\n' "$$files"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	CGO_ENABLED=1 $(GO) test -race ./...
	$(NODE) --test test_ui.mjs

check: fmt-check vet test

clean:
	rm -rf build dist
