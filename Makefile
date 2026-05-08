.PHONY: build test clean deploy rollout-bastille replica diagnose-replica promote-replica help

DATA_DIR  ?= /data/samples
DB        ?= postgres://hopper@hopper-db/hopper?sslmode=disable
SOURCE    ?= harvest
DASH_ADDR ?= 0.0.0.0:8081
WORKERS   ?= 0

help:
	@echo "Available targets:"
	@echo "  make build                  Build the hopper binary"
	@echo "  make test                   Run tests"
	@echo "  make lint                   Run linters"
	@echo "  make clean                  Clean build artifacts"
	@echo "  make deploy                 Install as a hardened systemd service on this Linux host"
	@echo "                              (DATA_DIR=$(DATA_DIR) DB=... SOURCE=$(SOURCE) DASH_ADDR=$(DASH_ADDR) WORKERS=$(WORKERS))"
	@echo "  make rollout-bastille       Deploy to Bastille jails (BUILD=build RUN=hopper [DB_ONLY=1])"
	@echo "  make replica                Configure local postgres as a logical replica of the"
	@echo "                              upstream hopper DB (idempotent; reads ~/.pgpass)"
	@echo "  make diagnose-replica       Dump replication status from both sides (read-only)"
	@echo "  make promote-replica        Turn the local replica into a standalone primary"
	@echo "                              (writes must already be stopped; idempotent)"

build:
	CGO_ENABLED=1 go build -o hopper -ldflags="-s -w" ./cmd/hopper

test:
	go test ./...

BUILD ?= build
RUN ?= hopper

deploy:
	DATA_DIR='$(DATA_DIR)' DB='$(DB)' SOURCE='$(SOURCE)' \
	DASH_ADDR='$(DASH_ADDR)' WORKERS='$(WORKERS)' \
	./scripts/master/linux-systemd.sh

rollout-bastille:
	@if [ -n "$(DB_ONLY)" ]; then \
		DB_ONLY=1 ./scripts/master/freebsd-bastille.sh "" "$(RUN)"; \
	else \
		./scripts/master/freebsd-bastille.sh "$(BUILD)" "$(RUN)"; \
	fi

replica: build
	@./scripts/replica/setup.sh

diagnose-replica:
	@./scripts/replica/diagnose.sh

promote-replica:
	@./scripts/replica/promote.sh

clean:
	rm -f hopper

# BEGIN: lint-install .
# http://github.com/codeGROOVE-dev/lint-install

.PHONY: lint
lint: _lint

LINT_ARCH := $(shell uname -m)
LINT_OS := $(shell uname)
LINT_OS_LOWER := $(shell echo $(LINT_OS) | tr '[:upper:]' '[:lower:]')
LINT_ROOT := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# shellcheck and hadolint lack arm64 native binaries: rely on x86-64 emulation
ifeq ($(LINT_OS),Darwin)
	ifeq ($(LINT_ARCH),arm64)
		LINT_ARCH=x86_64
	endif
endif

LINTERS :=
FIXERS :=

GOLANGCI_LINT_CONFIG := $(LINT_ROOT)/.golangci.yml
GOLANGCI_LINT_VERSION ?= v2.10.1
GOLANGCI_LINT_BIN := $(LINT_ROOT)/out/linters/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(LINT_ARCH)
$(GOLANGCI_LINT_BIN):
	mkdir -p $(LINT_ROOT)/out/linters
	rm -rf $(LINT_ROOT)/out/linters/golangci-lint-*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LINT_ROOT)/out/linters $(GOLANGCI_LINT_VERSION)
	mv $(LINT_ROOT)/out/linters/golangci-lint $@

LINTERS += golangci-lint-lint
golangci-lint-lint: $(GOLANGCI_LINT_BIN)
	"$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" ./...

FIXERS += golangci-lint-fix
golangci-lint-fix: $(GOLANGCI_LINT_BIN)
	"$(GOLANGCI_LINT_BIN)" run -c "$(GOLANGCI_LINT_CONFIG)" --fix ./...

.PHONY: _lint $(LINTERS)
_lint:
	@exit_code=0; \
	for target in $(LINTERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

.PHONY: fix $(FIXERS)
fix:
	@exit_code=0; \
	for target in $(FIXERS); do \
		$(MAKE) $$target || exit_code=1; \
	done; \
	exit $$exit_code

# END: lint-install .
